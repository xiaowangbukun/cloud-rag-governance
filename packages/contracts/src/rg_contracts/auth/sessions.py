"""平台会话令牌与口令哈希。

- 会话令牌为 HS256 JWT，仅用于平台内部，密钥来自环境变量
- 口令使用 PBKDF2-SHA256，不引入额外算法依赖
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from passlib.context import CryptContext

from rg_contracts.config import Settings, get_settings
from rg_contracts.errors import AuthenticationError

_pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

#: 用户名不存在时用来「陪跑」一次 PBKDF2 的哈希。
#: 直接 return False 会让「用户不存在」比「密码错」快一个数量级，
#: 攻击者可据此枚举有效账号。校验成本必须对齐。
_DUMMY_PASSWORD_HASH = _pwd_context.hash("dummy-password-for-timing-equalisation")


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    try:
        return _pwd_context.verify(password, hashed)
    except ValueError:
        return False


def burn_password_comparison(password: str) -> None:
    """对不存在的账号做一次等价耗时的校验（不泄露用户是否存在）。"""
    verify_password(password, _DUMMY_PASSWORD_HASH)


def issue_session_token(
    subject: str,
    user_id: str,
    role: str,
    org_id: str | None,
    classification_ceiling: str,
    project_ids: list[str],
    ttl_minutes: int | None = None,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    now = int(time.time())
    ttl = ttl_minutes or settings.JWT_ACCESS_TTL_MINUTES
    payload: dict[str, Any] = {
        "sub": subject,
        "uid": user_id,
        "role": role,
        "org": org_id,
        "lvl": classification_ceiling,
        "prj": project_ids,
        "typ": "access",
        "iat": now,
        "exp": now + ttl * 60,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def issue_refresh_token(subject: str, user_id: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    now = int(time.time())
    payload = {
        "sub": subject,
        "uid": user_id,
        "typ": "refresh",
        "iat": now,
        "exp": now + settings.JWT_REFRESH_TTL_MINUTES * 60,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_session_token(
    token: str,
    settings: Settings | None = None,
    expected_type: str = "access",
) -> dict:
    """解析并**校验令牌类型**。

    访问令牌与刷新令牌共用同一签名密钥，若只验签名不验 ``typ``，刷新令牌
    就能当访问令牌用（有效期 7 天的凭证被降级成万能 Bearer），访问令牌也能
    拿去换新令牌（会话可无限续期）。因此 ``typ`` 必须与调用方预期严格相等，
    默认只接受 ``access``；刷新端点显式传 ``expected_type="refresh"``。
    """
    settings = settings or get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("会话已过期") from exc
    except jwt.PyJWTError as exc:
        raise AuthenticationError("无效会话令牌") from exc
    if payload.get("typ") != expected_type:
        raise AuthenticationError("令牌类型错误")
    return payload


def token_ttl_seconds(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    return settings.JWT_ACCESS_TTL_MINUTES * 60
