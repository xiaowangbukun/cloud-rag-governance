"""审计与安全事件。

审计是合规底线：谁、在何时、以什么权限、访问了什么、被允许还是被拒绝、原因是什么。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_contracts.db.models import AuditLog, SecurityEvent, new_id, ts
from rg_contracts.logging_setup import get_logger
from rg_contracts.security.policy import Subject

logger = get_logger(__name__)


class AuditService:
    def __init__(self, session: Session, enabled: bool = True) -> None:
        self.session = session
        self.enabled = enabled

    def record(
        self,
        action: str,
        outcome: str,
        actor: Subject | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        project_id: str | None = None,
        reason_code: str | None = None,
        request_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLog | None:
        entry = AuditLog(
            id=new_id("aud"),
            ts=ts(),
            request_id=request_id,
            actor_id=actor.user_id if actor else None,
            actor_role=actor.role if actor else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=project_id,
            outcome=outcome,
            reason_code=reason_code,
            ip=ip,
            user_agent=(user_agent or "")[:190] or None,
            metadata_json=metadata or {},
        )
        logger.info(
            "audit_event",
            extra={
                "extra_fields": {
                    "action": action,
                    "outcome": outcome,
                    "actor": entry.actor_id,
                    "reason_code": reason_code,
                }
            },
        )
        if not self.enabled:
            return None
        self.session.add(entry)
        return entry

    def security_event(
        self,
        event_type: str,
        detail: str,
        actor: Subject | None = None,
        severity: str = "medium",
        metadata: dict | None = None,
        project_id: str | None = None,
    ) -> SecurityEvent | None:
        entry = SecurityEvent(
            id=new_id("sec"),
            ts=ts(),
            actor_id=actor.user_id if actor else None,
            project_id=project_id,
            event_type=event_type,
            severity=severity,
            detail=detail,
            metadata_json=metadata or {},
        )
        logger.warning(
            "security_event",
            extra={"extra_fields": {"type": event_type, "severity": severity, "actor": entry.actor_id}},
        )
        if not self.enabled:
            return None
        self.session.add(entry)
        return entry

    def query(
        self,
        actor_id: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        project_id: str | None = None,
        limit: int = 100,
    ) -> list[AuditLog]:
        stmt = select(AuditLog)
        if actor_id:
            stmt = stmt.where(AuditLog.actor_id == actor_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if outcome:
            stmt = stmt.where(AuditLog.outcome == outcome)
        if project_id:
            stmt = stmt.where(AuditLog.project_id == project_id)
        stmt = stmt.order_by(AuditLog.ts.desc()).limit(min(limit, 500))
        return list(self.session.execute(stmt).scalars().all())

    def security_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        project_ids: frozenset[str] | None = None,
    ) -> list[SecurityEvent]:
        """按项目范围读取安全事件。

        ``project_ids=None`` 表示不限项目（仅限全局管理员）；空集合表示什么都看不到。
        项目归属为空（全局）的事件只有不限项目的调用方才能读。
        """
        stmt = select(SecurityEvent)
        if event_type:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
        if project_ids is not None:
            if not project_ids:
                return []
            stmt = stmt.where(SecurityEvent.project_id.in_(sorted(project_ids)))
        stmt = stmt.order_by(SecurityEvent.ts.desc()).limit(min(limit, 500))
        return list(self.session.execute(stmt).scalars().all())


def audit_entry_to_dict(entry: AuditLog) -> dict[str, Any]:
    return {
        "id": entry.id,
        "ts": entry.ts if isinstance(entry.ts, str) else str(entry.ts),
        "request_id": entry.request_id,
        "actor_id": entry.actor_id,
        "actor_role": entry.actor_role,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "project_id": entry.project_id,
        "outcome": entry.outcome,
        "reason_code": entry.reason_code,
        "metadata": entry.metadata_json,
    }


def security_event_to_dict(entry: SecurityEvent) -> dict[str, Any]:
    return {
        "id": entry.id,
        "ts": entry.ts if isinstance(entry.ts, str) else str(entry.ts),
        "actor_id": entry.actor_id,
        # 项目归属必须随事件一起返回：调用方要能核对「这条事件属于哪个项目」，
        # 否则按项目收口后的结果看起来与全局结果没有区别。
        "project_id": entry.project_id,
        "event_type": entry.event_type,
        "severity": entry.severity,
        "detail": entry.detail,
        "metadata": entry.metadata_json,
    }
