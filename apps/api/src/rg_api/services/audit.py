"""审计写入的统一封装：路由层不需要关心 request_id / IP 的取值细节。"""

from __future__ import annotations

from fastapi import Request
from rg_contracts.audit.service import AuditService
from rg_contracts.config import get_settings
from rg_contracts.db.session import get_session_factory
from rg_contracts.logging_setup import get_logger, get_request_id
from rg_contracts.security.policy import Subject
from sqlalchemy.orm import Session

from rg_api.services.access import client_meta

logger = get_logger(__name__)

# denied / failed 的业务路径随后一定回滚（路由直接抛 PermissionDeniedError
# 或采集失败后整体回滚），若审计写在业务会话上会随回滚一并丢失（P0-4）。
# 这两类结果必须用独立事务落库，保证「拒绝也有留痕」。
_INDEPENDENT_OUTCOMES = frozenset({"denied", "failed"})


def audit_service(session: Session) -> AuditService:
    settings = get_settings()
    return AuditService(session, enabled=settings.SECURITY_AUDIT_ENABLED)


def audit_action(
    request: Request,
    session: Session,
    subject: Subject | None,
    action: str,
    outcome: str,
    project_id: str | None = None,
    reason_code: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    ip, user_agent = client_meta(request)
    if outcome in _INDEPENDENT_OUTCOMES:
        # 独立事务：与业务会话的提交/回滚解耦，拒绝记录不因回滚丢失
        _record_independent(
            business_session=session,
            subject=subject,
            action=action,
            outcome=outcome,
            project_id=project_id,
            reason_code=reason_code,
            resource_type=resource_type,
            resource_id=resource_id,
            ip=ip,
            user_agent=user_agent,
            metadata=metadata,
        )
        return
    _record(
        session,
        subject=subject,
        action=action,
        outcome=outcome,
        project_id=project_id,
        reason_code=reason_code,
        resource_type=resource_type,
        resource_id=resource_id,
        ip=ip,
        user_agent=user_agent,
        metadata=metadata,
    )


def audit_security(
    session: Session,
    subject: Subject | None,
    event_type: str,
    detail: str,
    severity: str = "medium",
    metadata: dict | None = None,
    project_id: str | None = None,
    independent: bool = False,
) -> None:
    """记录安全事件。

    ``independent=True`` 用于「紧接着就会抛异常、业务会话必然回滚」的路径
    （提示词注入/枚举/金丝雀拦截）。这类路径若把事件写在业务会话上，事件会
    随回滚一起消失 —— 攻击者反复试错完全不留痕。独立事务只保证「尽力落库」，
    与 ``audit_action`` 的 denied/failed 语义一致。
    """
    metadata = dict(metadata or {})
    if project_id:
        metadata.setdefault("project_id", project_id)
    if independent:
        _record_independent_security(
            business_session=session,
            subject=subject,
            event_type=event_type,
            detail=detail,
            severity=severity,
            metadata=metadata,
            project_id=project_id,
        )
        return
    audit_service(session).security_event(
        event_type=event_type,
        detail=detail,
        actor=subject,
        severity=severity,
        metadata=metadata,
        project_id=project_id,
    )


def _record(
    session: Session,
    *,
    subject: Subject | None,
    action: str,
    outcome: str,
    project_id: str | None,
    reason_code: str | None,
    resource_type: str | None,
    resource_id: str | None,
    ip: str | None,
    user_agent: str | None,
    metadata: dict | None,
) -> None:
    """把审计行写入给定会话（不负责提交，由调用方事务决定）。"""
    service = audit_service(session)
    service.record(
        action=action,
        outcome=outcome,
        actor=subject,
        resource_type=resource_type,
        resource_id=resource_id,
        project_id=project_id,
        reason_code=reason_code,
        request_id=get_request_id(),
        ip=ip,
        user_agent=user_agent,
        metadata=metadata,
    )
    if outcome == "denied":
        service.security_event(
            event_type=f"access_denied:{action}",
            detail=f"{action} 被拒绝：{reason_code}",
            actor=subject,
            severity="medium",
            metadata={"project_id": project_id, "request_id": get_request_id()},
            project_id=project_id,
        )


# SQLite 写锁竞争的已知错误文本。PostgreSQL 是 MVCC，独立连接与业务事务
# 互不阻塞，不存在这个问题，因此刻意不覆盖 PG 的锁错误文案。
_SQLITE_LOCK_MARKERS = ("database is locked", "database table is locked")


def _is_lock_error(exc: BaseException) -> bool:
    """保守判定「方言内的写锁竞争」，用于决定能否回滚业务会话。

    沿异常链（SQLAlchemy 的 ``orig`` / ``__cause__`` / ``__context__``）
    收集文案，只认 SQLite 的两种已知锁错误。

    刻意保守：拿不准一律返回 False。误判为锁错误会连带回滚业务会话的
    暂存区 —— 归因等路径会因此「返回 200 + id，但库里没有该 id」；
    漏判只会退化为「记日志、审计这一条丢失」，不毁业务数据。
    宁可漏判，不可误判。
    """
    pending: list[BaseException | None] = [exc]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in visited:
            continue
        visited.add(id(current))
        message = str(current).lower()
        if any(marker in message for marker in _SQLITE_LOCK_MARKERS):
            return True
        pending.append(getattr(current, "orig", None))
        pending.append(current.__cause__)
        pending.append(current.__context__)
    return False


def _record_independent(
    *,
    business_session: Session | None = None,
    subject: Subject | None,
    action: str,
    outcome: str,
    project_id: str | None,
    reason_code: str | None,
    resource_type: str | None,
    resource_id: str | None,
    ip: str | None,
    user_agent: str | None,
    metadata: dict | None,
) -> None:
    """用全新会话 + 独立事务写审计，**尽力**让拒绝/失败记录落库。

    契约要说准确（避免"注释承诺了代码没做到"）：
    - 本函数**不保证**审计一定落库。独立写入失败时只记日志并放弃该条，
      这是有意的降级——审计链路故障不应把业务请求也拖垮；
    - 本函数**保证**的是「审计写入失败不会破坏业务数据」：除了 SQLite 写锁
      竞争这一种情况，任何异常都不碰业务会话。

    这段重试纯粹是 **SQLite 单写者模型**的适配：业务会话若持有未提交
    写事务（先 flush 过），独立事务的提交会因写锁失败，此时回滚业务会话
    暂存区以释放写锁再重试一次。PostgreSQL 的 MVCC 不需要这层。

    铁律：**只有 SQLite 写锁竞争才允许碰业务会话**；其他任何异常一律只记
    日志、放弃该条审计——否则业务数据会被审计写入失败牵连丢弃，而 API
    仍返回成功（例如归因记录凭空消失、客户端拿到库里不存在的 id）。
    """
    try:
        _record_independent_once(
            subject=subject,
            action=action,
            outcome=outcome,
            project_id=project_id,
            reason_code=reason_code,
            resource_type=resource_type,
            resource_id=resource_id,
            ip=ip,
            user_agent=user_agent,
            metadata=metadata,
        )
        return
    except Exception as exc:  # noqa: BLE001
        if business_session is None or not _is_lock_error(exc):
            _log_audit_failure(action, outcome, subject)
            return
        # 仅锁竞争：释放业务会话的写锁后重试一次
        business_session.rollback()

    try:
        _record_independent_once(
            subject=subject,
            action=action,
            outcome=outcome,
            project_id=project_id,
            reason_code=reason_code,
            resource_type=resource_type,
            resource_id=resource_id,
            ip=ip,
            user_agent=user_agent,
            metadata=metadata,
        )
    except Exception:  # noqa: BLE001
        _log_audit_failure(action, outcome, subject)


def _record_independent_once(
    *,
    subject: Subject | None,
    action: str,
    outcome: str,
    project_id: str | None,
    reason_code: str | None,
    resource_type: str | None,
    resource_id: str | None,
    ip: str | None,
    user_agent: str | None,
    metadata: dict | None,
) -> None:
    """单次尝试：新会话内写审计行并提交，失败抛给上层处置。"""
    factory = get_session_factory()
    audit_session = factory()
    try:
        _record(
            audit_session,
            subject=subject,
            action=action,
            outcome=outcome,
            project_id=project_id,
            reason_code=reason_code,
            resource_type=resource_type,
            resource_id=resource_id,
            ip=ip,
            user_agent=user_agent,
            metadata=metadata,
        )
        audit_session.commit()
    except Exception:
        audit_session.rollback()
        raise
    finally:
        audit_session.close()


def _record_independent_security(
    *,
    business_session: Session | None = None,
    subject: Subject | None,
    event_type: str,
    detail: str,
    severity: str,
    metadata: dict | None,
    project_id: str | None,
) -> None:
    """独立事务写安全事件：业务会话随后回滚也不会抹掉这条留痕。

    与 ``_record_independent`` 同一套契约与降级策略：
    - 只做「尽力而为」，写失败只记日志，绝不把业务请求拖垮；
    - 仅 SQLite 写锁竞争允许回滚业务会话后重试一次（检索拦截路径上
      业务会话可能已持有拼图账本的写事务）。
    """
    try:
        _record_security_once(
            subject=subject,
            event_type=event_type,
            detail=detail,
            severity=severity,
            metadata=metadata,
            project_id=project_id,
        )
        return
    except Exception as exc:  # noqa: BLE001
        if business_session is None or not _is_lock_error(exc):
            _log_audit_failure(event_type, "failed", subject)
            return
        business_session.rollback()

    try:
        _record_security_once(
            subject=subject,
            event_type=event_type,
            detail=detail,
            severity=severity,
            metadata=metadata,
            project_id=project_id,
        )
    except Exception:  # noqa: BLE001
        _log_audit_failure(event_type, "failed", subject)


def _record_security_once(
    *,
    subject: Subject | None,
    event_type: str,
    detail: str,
    severity: str,
    metadata: dict | None,
    project_id: str | None,
) -> None:
    """单次尝试：新会话内写安全事件并提交，失败抛给上层处置。"""
    factory = get_session_factory()
    event_session = factory()
    try:
        audit_service(event_session).security_event(
            event_type=event_type,
            detail=detail,
            actor=subject,
            severity=severity,
            metadata=metadata,
            project_id=project_id,
        )
        event_session.commit()
    except Exception:
        event_session.rollback()
        raise
    finally:
        event_session.close()


def _log_audit_failure(action: str, outcome: str, subject: Subject | None) -> None:
    logger.error(
        "audit_independent_write_failed",
        extra={
            "extra_fields": {
                "action": action,
                "outcome": outcome,
                "actor": subject.user_id if subject else None,
            }
        },
    )
