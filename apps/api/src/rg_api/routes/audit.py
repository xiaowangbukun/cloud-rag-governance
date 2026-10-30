"""审计与安全事件查询。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from rg_contracts.audit.service import AuditService, audit_entry_to_dict, security_event_to_dict
from rg_contracts.config import get_settings
from rg_contracts.db.session import db_session
from rg_contracts.errors import PermissionDeniedError
from rg_contracts.security.budget import get_budget
from rg_contracts.security.policy import Subject, default_engine
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services.audit import audit_action

router = APIRouter(prefix="/audit", tags=["audit"])
_engine = default_engine()


@router.get("/logs")
def list_logs(
    request: Request,
    action: str | None = None,
    outcome: str | None = None,
    project_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    if not _engine.check_capability(subject, "audit:read").allowed:
        audit_action(request, session, subject, "audit:read", "denied", project_id, "missing_capability")
        raise PermissionDeniedError("当前角色无审计查询权限")

    # 非全局角色只能查看自己或已授权项目的审计
    effective_project = project_id
    if not _engine.build_scope(subject).unrestricted:
        if project_id and project_id not in subject.project_ids:
            audit_action(request, session, subject, "audit:read", "denied", project_id, "project_out_of_scope")
            raise PermissionDeniedError("无该项目访问权限")
        if not project_id:
            effective_project = None

    service = AuditService(session, enabled=get_settings().SECURITY_AUDIT_ENABLED)
    rows = service.query(
        actor_id=None if _engine.build_scope(subject).unrestricted else subject.user_id,
        action=action,
        outcome=outcome,
        project_id=effective_project,
        limit=limit,
    )
    return {"items": [audit_entry_to_dict(row) for row in rows], "count": len(rows)}


@router.get("/security-events")
def list_security_events(
    request: Request,
    event_type: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    if not _engine.check_capability(subject, "security:read").allowed:
        audit_action(request, session, subject, "audit:security_read", "denied", None, "missing_capability")
        raise PermissionDeniedError("当前角色无安全事件查询权限")
    # 安全事件带命中文本，必须按项目收口：只给本项目的事件（全局角色才不限）
    scope = _engine.build_scope(subject)
    project_scope = None if scope.unrestricted else frozenset(scope.project_ids)
    service = AuditService(session, enabled=get_settings().SECURITY_AUDIT_ENABLED)
    rows = service.security_events(
        limit=limit, event_type=event_type, project_ids=project_scope
    )
    return {"items": [security_event_to_dict(row) for row in rows], "count": len(rows)}


@router.get("/budget")
def my_budget(subject: Subject = Depends(current_subject)) -> dict:
    return get_budget().snapshot(subject.user_id)
