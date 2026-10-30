"""认证、会话与当前用户依赖。

两条安全不变量（改动前都缺）：

1. **OIDC state 由服务端校验且一次性消费**。state 落库（只存 sha256），
   回调时先校验再消费，不匹配 / 已消费 / 超期一律拒绝；PKCE verifier 与
   nonce 只留在服务端，不再下发浏览器——否则 state 校验形同自证。
2. **刷新令牌只走 HttpOnly Cookie**，不进响应体、不进任何 JS 可读的存储。
   访问令牌由前端仅存内存。
3. **登录失败锁定跨副本一致**：计数落 ``runtime_counter`` 表，而不是进程内
   dict——否则两个副本各锁各的，阈值被放大一倍。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from rg_contracts.auth.oidc import DirectoryProvider, OidcClient
from rg_contracts.auth.sessions import (
    burn_password_comparison,
    decode_session_token,
    issue_refresh_token,
    issue_session_token,
    token_ttl_seconds,
    verify_password,
)
from rg_contracts.config import AuthMode, Settings, get_settings
from rg_contracts.db.models import (
    OidcLoginState,
    ProjectMember,
    TimestampCodec,
    User,
    new_id,
    ts,
)
from rg_contracts.db.rls import scope_session_for_subject
from rg_contracts.db.session import db_session
from rg_contracts.errors import AuthenticationError, PermissionDeniedError, RateLimitedError
from rg_contracts.security.policy import Subject
from rg_contracts.security.state_store import SCOPE_LOGIN_FAILURE, RuntimeStateStore
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)

# 登录 state 的存活窗口：一次浏览器跳转往返，超期即作废
OIDC_STATE_TTL_SECONDS = 300
# 刷新令牌 Cookie：限定到认证路径，JS 读不到（HttpOnly），仅同站可带（SameSite）
REFRESH_COOKIE_NAME = "crg_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"

# 登录失败锁定：同一用户名 5 次失败锁 5 分钟。
# 计数落库（runtime_counter）而不是进程内 dict：replicas=2 + HPA 下进程内
# 计数按副本数放大，锁定阈值会从「第 6 次」退化成「第 11 次」。写入走独立
# 事务并立即提交——失败路径随后会抛异常回滚业务会话，复用业务会话会把
# 计数一起清掉。
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 300
_login_store = RuntimeStateStore()


def _failure_count(username: str) -> int:
    return _login_store.count(SCOPE_LOGIN_FAILURE, username, LOGIN_LOCKOUT_SECONDS)


def _register_login_failure(username: str) -> int:
    _login_store.record(SCOPE_LOGIN_FAILURE, username)
    return _failure_count(username)


def _clear_login_failures(username: str) -> None:
    _login_store.purge_subject(SCOPE_LOGIN_FAILURE, username)


def _locked_out(username: str) -> bool:
    return _failure_count(username) >= LOGIN_MAX_FAILURES


def reset_login_state() -> None:
    """测试/运维用：清空登录失败计数（与 startup.reset_runtime 同风格）。"""
    _login_store.purge(scopes=(SCOPE_LOGIN_FAILURE,))


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=190)
    password: str = Field(min_length=6, max_length=128)


class TokenResponse(BaseModel):
    """登录/刷新响应。

    刻意**不含** refresh_token：刷新令牌只在 Set-Cookie 里下发。
    响应体一旦带上它，前端就一定会把它落到 localStorage 之类的可读位置。
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


def _set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    """把刷新令牌写进 HttpOnly Cookie。

    ``SameSite=Strict`` 已经覆盖 refresh / logout 端点的 CSRF 风险（跨站请求
    不会带上 Cookie），因此不需要额外的双提交 token。``Secure`` 由
    ``AUTH_COOKIE_SECURE`` 控制（默认 True；prod 强制 True）：纯 HTTP 部署下
    浏览器会静默丢弃 Secure Cookie，只能由运维显式关闭并留下配置记录。
    """
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        max_age=settings.JWT_REFRESH_TTL_MINUTES * 60,
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite="strict",
    )


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def _prune_expired_states(session: Session, scan: int = 200) -> None:
    """清掉已过期的 state 行，避免表只增不减。

    刻意在 Python 侧判断过期：``TS()`` 在两个方言下分别是 ISO 文本与
    timestamptz，用 SQL 直接比较字符串会有方言差异。
    """
    rows = session.execute(
        select(OidcLoginState).order_by(OidcLoginState.created_at).limit(scan)
    ).scalars().all()
    now = datetime.now(timezone.utc)
    expired = [
        row.id
        for row in rows
        if (expires := TimestampCodec.decode(row.expires_at)) is not None and expires < now
    ]
    if expired:
        session.execute(delete(OidcLoginState).where(OidcLoginState.id.in_(expired)))
        session.commit()


def _consume_login_state(session: Session, state: str) -> OidcLoginState:
    """校验并**一次性**消费登录 state，不通过直接拒绝。

    三条拒绝路径：查无此 state（含伪造/不属于本服务）、已被消费过、已超期。
    消费用条件 UPDATE（``consumed_at IS NULL``）抢占而不是「查完再置位」：
    两个并发回调只有一个能抢到，另一个 rowcount=0 被拒，重放窗口被消除。
    """
    digest = _state_hash(state)
    record = session.execute(
        select(OidcLoginState).where(OidcLoginState.state_hash == digest)
    ).scalar_one_or_none()
    if record is None:
        raise AuthenticationError("state 无效，请重新登录")
    if record.consumed_at:
        raise AuthenticationError("state 已被使用，请重新登录")
    expires_at = TimestampCodec.decode(record.expires_at)
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        raise AuthenticationError("state 已过期，请重新登录")

    consumed_at = ts()
    claimed = session.execute(
        update(OidcLoginState)
        .where(OidcLoginState.id == record.id, OidcLoginState.consumed_at.is_(None))
        .values(consumed_at=consumed_at)
    )
    if claimed.rowcount != 1:
        session.rollback()
        raise AuthenticationError("state 已被使用，请重新登录")
    session.commit()
    record.consumed_at = consumed_at
    return record


def _load_subject(session: Session, user: User) -> Subject:
    members = session.execute(
        select(ProjectMember).where(ProjectMember.user_id == user.id)
    ).scalars().all()
    return Subject(
        user_id=user.id,
        subject=user.subject,
        display_name=user.display_name,
        role=user.role,
        org_id=user.org_id,
        classification_ceiling=user.classification_ceiling,
        project_ids=frozenset(m.project_id for m in members),
        visible_ceilings={m.project_id: m.visible_ceiling for m in members},
        auth_mode="dev",
        attributes=user.attributes,
    )


def resolve_subject(token: str, session: Session, settings: Settings) -> Subject:
    """解析会话令牌 → Subject。OIDC 模式下可替换为 ID Token 校验。"""
    payload = decode_session_token(token, settings)
    user = session.execute(
        select(User).where(User.id == payload.get("uid"))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthenticationError("用户不存在或已停用")
    return _load_subject(session, user)


def current_subject(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(db_session),
) -> Subject:
    settings = get_settings()
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("缺少认证凭证")
    subject = resolve_subject(credentials.credentials, session, settings)
    request.state.subject = subject
    # 第二道防线：把授权边界写进数据库会话变量。应用层照旧按项目/密级拼 WHERE，
    # 但即使某条查询漏了条件，PostgreSQL 策略也只返回这个作用域内的行。
    # 这里只依赖服务端解析出的 Subject，不接受任何客户端传入的范围。
    if settings.DB_RLS_ENABLED:
        scope_session_for_subject(session, subject)
    return subject


def current_user_id(subject: Subject = Depends(current_subject)) -> str:
    return subject.user_id


@router.get("/config")
def auth_config() -> dict:
    """前端据此决定展示 OIDC 登录还是本地登录。"""
    settings = get_settings()
    oidc_ready = bool(settings.OIDC_ISSUER or settings.OIDC_AUTHORIZE_URL)
    return {
        "mode": settings.AUTH_MODE.value,
        "oidc_enabled": settings.AUTH_MODE is AuthMode.OIDC and oidc_ready,
        "dev_login_enabled": settings.DEV_LOGIN_ENABLED,
        "directory_mode": settings.DIRECTORY_MODE.value,
    }


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: Session = Depends(db_session),
) -> dict:
    settings = get_settings()
    if not settings.DEV_LOGIN_ENABLED:
        raise PermissionDeniedError("当前环境未启用本地登录，请使用 OIDC")
    if _locked_out(payload.username):
        from rg_api.services.audit import audit_security

        audit_security(
            session,
            None,
            "login_locked_out",
            f"账号连续登录失败被临时锁定：{payload.username}",
            severity="high",
            metadata={"username": payload.username, "window_seconds": LOGIN_LOCKOUT_SECONDS},
            independent=True,
        )
        raise RateLimitedError("登录失败次数过多，请稍后再试", retry_after=LOGIN_LOCKOUT_SECONDS)
    user = session.execute(
        select(User).where(User.subject == payload.username)
    ).scalar_one_or_none()
    if user is None:
        # 陪跑一次同等耗时的哈希：否则「用户不存在」会明显快于「密码错」，
        # 攻击者可据此枚举有效账号（时序侧信道）
        burn_password_comparison(payload.password)
        authenticated = False
    else:
        authenticated = verify_password(payload.password, user.password_hash)
    if not authenticated:
        from rg_api.services.audit import audit_security

        attempts = _register_login_failure(payload.username)
        audit_security(
            session,
            None,
            "login_failed",
            f"登录失败：{payload.username}（{attempts} 次）",
            severity="medium" if attempts < LOGIN_MAX_FAILURES else "high",
            metadata={"username": payload.username, "attempts": attempts},
            # 下面会抛异常 → 业务会话回滚，必须独立事务留痕
            independent=True,
        )
        raise AuthenticationError("用户名或密码错误")
    if not user.is_active:
        raise AuthenticationError("用户已停用")
    _clear_login_failures(payload.username)

    subject = _load_subject(session, user)
    access = issue_session_token(
        subject=user.subject,
        user_id=user.id,
        role=user.role,
        org_id=user.org_id,
        classification_ceiling=user.classification_ceiling,
        project_ids=sorted(subject.project_ids),
        settings=settings,
    )
    refresh = issue_refresh_token(user.subject, user.id, settings)
    user.last_login_at = ts()
    session.commit()
    _set_refresh_cookie(response, refresh, settings)
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": token_ttl_seconds(settings),
        "user": {
            "id": user.id,
            "subject": user.subject,
            "display_name": user.display_name,
            "role": user.role,
            "classification_ceiling": user.classification_ceiling,
            "project_ids": sorted(subject.project_ids),
        },
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, session: Session = Depends(db_session)) -> dict:
    """用 Cookie 里的刷新令牌换新的访问令牌。

    只认 Cookie、不接受请求体：一旦允许请求体传令牌，前端就会为了兼容而
    把它放回可读存储，等于把这道加固作废。
    """
    settings = get_settings()
    token = request.cookies.get(REFRESH_COOKIE_NAME, "")
    if not token:
        raise AuthenticationError("缺少刷新令牌")
    # 只接受 refresh 类型：访问令牌放到 Cookie 里换新令牌会让会话无限续期
    token_data = decode_session_token(token, settings, expected_type="refresh")
    user = session.execute(
        select(User).where(User.id == token_data.get("uid"))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthenticationError("用户不存在或已停用")
    subject = _load_subject(session, user)
    access = issue_session_token(
        subject=user.subject,
        user_id=user.id,
        role=user.role,
        org_id=user.org_id,
        classification_ceiling=user.classification_ceiling,
        project_ids=sorted(subject.project_ids),
        settings=settings,
    )
    # 滑动续期：Cookie 续期，JWT 本身的 exp 不变（不引入无限会话）
    _set_refresh_cookie(response, token, settings)
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": token_ttl_seconds(settings),
        "user": {
            "id": user.id,
            "subject": user.subject,
            "display_name": user.display_name,
            "role": user.role,
            "classification_ceiling": user.classification_ceiling,
            "project_ids": sorted(subject.project_ids),
        },
    }


@router.get("/oidc/authorize")
def oidc_authorize(session: Session = Depends(db_session)) -> dict:
    """签发授权 URL，并把 state / PKCE verifier / nonce **落库**。

    响应只回 state 与授权 URL：verifier 与 nonce 留在服务端，回调时按 state
    取回，避免它们经由浏览器往返（浏览器是本次加固要信任最小的组件）。
    """
    settings = get_settings()
    if settings.AUTH_MODE is not AuthMode.OIDC:
        raise PermissionDeniedError("当前未启用 OIDC 模式")
    client = OidcClient(settings)
    url = client.build_authorize_url()
    now = datetime.now(timezone.utc)
    session.add(
        OidcLoginState(
            id=new_id("ols"),
            state_hash=_state_hash(url.state),
            code_verifier=url.code_verifier,
            nonce=url.nonce,
            redirect_uri=settings.OIDC_REDIRECT_URI,
            created_at=ts(now),
            expires_at=ts(now + timedelta(seconds=OIDC_STATE_TTL_SECONDS)),
        )
    )
    session.commit()
    _prune_expired_states(session)
    return {"authorize_url": url.url, "state": url.state}


class OidcCallbackRequest(BaseModel):
    code: str
    # state 必填且必须与服务端落库记录匹配：登录 CSRF 防护的服务端权威点
    state: str = Field(min_length=1, max_length=190)
    # 以下两项仅作向后兼容，服务端一律以落库值为准，不接受客户端传值
    code_verifier: str | None = None
    nonce: str | None = None


@router.post("/oidc/callback", response_model=TokenResponse)
def oidc_callback(
    payload: OidcCallbackRequest,
    response: Response,
    session: Session = Depends(db_session),
) -> dict:
    """OIDC 回调：校验并消费 state → 换 token → 校验 ID Token → 补全组织信息 → 落本地账号。

    顺序铁律：state 必须**先**校验并消费，再去和 IdP 换 token。否则攻击者可以
    用伪造/重放的 state 消耗掉我们与 IdP 的会话。
    """
    settings = get_settings()
    if settings.AUTH_MODE is not AuthMode.OIDC:
        raise PermissionDeniedError("当前未启用 OIDC 模式")

    record = _consume_login_state(session, payload.state)

    client = OidcClient(settings)
    token_data = client.exchange_code(payload.code, record.code_verifier)
    id_token = token_data.get("id_token") or ""
    claims = client.verify_id_token(id_token, record.nonce) if id_token else {}
    if not claims:
        claims = client.userinfo(token_data.get("access_token", ""))
    if not claims:
        raise AuthenticationError("OIDC 未返回用户信息")

    subject_value = str(claims.get("sub") or claims.get("email") or "")
    if not subject_value:
        raise AuthenticationError("OIDC 用户标识缺失")

    directory = DirectoryProvider(settings)
    profile = directory.fetch(subject_value, claims)

    user = session.execute(
        select(User).where(User.subject == subject_value)
    ).scalar_one_or_none()
    if user is None:
        user = User(
            id=f"usr_{subject_value.split('@')[0]}"[:64],
            subject=subject_value,
            display_name=profile.display_name,
            email=profile.email,
            role=profile.role,
            org_id=profile.org_id,
            classification_ceiling=profile.classification_ceiling,
            is_active=True,
            password_hash=None,
            attributes={**profile.attributes, "directory_source": settings.DIRECTORY_MODE.value},
        )
        session.add(user)
        session.flush()
        for pid in profile.project_ids:
            exists = session.execute(
                select(ProjectMember).where(
                    ProjectMember.user_id == user.id, ProjectMember.project_id == pid
                )
            ).scalar_one_or_none()
            if exists is None:
                session.add(
                    ProjectMember(
                        id=f"pm_{user.id}_{pid}"[:64],
                        user_id=user.id,
                        project_id=pid,
                        visible_ceiling=profile.visible_ceilings.get(
                            pid, profile.classification_ceiling
                        ),
                        created_at=ts(),
                    )
                )
        session.commit()
    else:
        # 每次登录同步目录信息，保证组织变更及时生效
        user.display_name = profile.display_name
        user.role = profile.role
        user.org_id = profile.org_id or user.org_id
        user.classification_ceiling = profile.classification_ceiling
        user.last_login_at = ts()
        session.commit()

    # 回填消费主体，便于事后审计「这条 state 是谁消费的」
    session.execute(
        update(OidcLoginState)
        .where(OidcLoginState.id == record.id)
        .values(subject=user.subject)
    )
    session.commit()

    subject = _load_subject(session, user)
    access = issue_session_token(
        subject=user.subject,
        user_id=user.id,
        role=user.role,
        org_id=user.org_id,
        classification_ceiling=user.classification_ceiling,
        project_ids=sorted(subject.project_ids),
        settings=settings,
    )
    refresh_token_value = issue_refresh_token(user.subject, user.id, settings)
    _set_refresh_cookie(response, refresh_token_value, settings)
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": token_ttl_seconds(settings),
        "user": {
            "id": user.id,
            "subject": user.subject,
            "display_name": user.display_name,
            "role": user.role,
            "classification_ceiling": user.classification_ceiling,
            "project_ids": sorted(subject.project_ids),
            "directory_mode": settings.DIRECTORY_MODE.value,
        },
    }


@router.get("/me")
def me(subject: Subject = Depends(current_subject)) -> dict:
    return {
        "id": subject.user_id,
        "subject": subject.subject,
        "display_name": subject.display_name,
        "role": subject.role,
        "org_id": subject.org_id,
        "classification_ceiling": subject.classification_ceiling,
        "project_ids": sorted(subject.project_ids),
        "auth_mode": subject.auth_mode,
    }


@router.post("/logout")
def logout(
    response: Response,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(db_session),
) -> dict:
    """登出：清掉刷新令牌 Cookie。

    刻意**不强制**要求有效访问令牌：令牌过期恰恰是最需要登出的时刻，
    若此时 401，Cookie 清不掉，用户会被困在一个刷新也失败的死状态里。
    解析出的 user_id 仅用于回显，解析失败不影响登出。
    """
    user_id = ""
    if credentials and credentials.credentials:
        try:
            user_id = resolve_subject(credentials.credentials, session, get_settings()).user_id
        except AuthenticationError:
            user_id = ""
    _clear_refresh_cookie(response)
    return {"ok": True, "user_id": user_id}


__all__ = ["current_subject", "router"]
