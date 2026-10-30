"""治理闭环：差异确认 / 忽略 / 处置，形成可追溯的资源治理流程。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from rg_contracts.config import get_settings
from rg_contracts.db.models import ResourceDiff, ts
from rg_contracts.db.session import db_session
from rg_contracts.enums import PLATFORM_LABELS, GovernanceStatus
from rg_contracts.errors import NotFoundError, PermissionDeniedError
from rg_contracts.security.policy import Subject, default_engine, levels_at_or_below
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services.access import (
    assert_project_access,
    diff_scope_clause,
    enforce_export,
    scoped_project_ids,
)
from rg_api.services.audit import audit_action

router = APIRouter(prefix="/governance", tags=["governance"])
_engine = default_engine()

#: 单次导出的行数硬上限。超出时返回 ``truncated=True`` 而不是静默截断，
#: 调用方要知道自己拿到的是「全部」还是「前 N 条」。
_EXPORT_ROW_CAP = 1000


class ResolveRequest(BaseModel):
    status: str = Field(pattern="^(confirmed|dismissed|remediated|open)$")
    note: str | None = Field(default=None, max_length=1000)
    assignee: str | None = Field(default=None, max_length=64)


@router.get("/board")
def board(
    request: Request,
    project_id: str | None = Query(None),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    project_ids = scoped_project_ids(subject, project_id)
    scope_clause = diff_scope_clause(subject, project_ids)
    if scope_clause is None:
        return {"total": 0, "by_status": {}, "by_kind": {}, "cost_impact_cny": 0, "items": []}
    stmt = select(ResourceDiff).where(scope_clause)
    rows = session.execute(stmt.order_by(ResourceDiff.detected_at.desc()).limit(200)).scalars().all()

    by_status: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    cost = 0.0
    for row in rows:
        by_status[row.status] = by_status.get(row.status, 0) + 1
        by_kind[row.diff_kind] = by_kind.get(row.diff_kind, 0) + 1
        cost += row.cost_delta_cny or 0

    audit_action(request, session, subject, "governance:board", "allowed", project_id, metadata={"count": len(rows)})
    return {
        "project_id": project_id,
        "total": len(rows),
        "by_status": by_status,
        "by_kind": by_kind,
        "cost_impact_cny": round(cost, 2),
        "items": [
            {
                "id": row.id,
                "project_id": row.project_id,
                "platform_label": PLATFORM_LABELS.get(row.platform, row.platform),
                "resource_name": row.resource_name,
                "diff_kind": row.diff_kind,
                # 规则标识（D1…）：时序 diff 为 None。前端据此区分"变化"与
                # "规则命中的治理项"，也是规则级回归的分组键。
                "rule_code": row.rule_code,
                "cost_delta_cny": row.cost_delta_cny,
                "status": row.status,
                "rule_hint": row.rule_hint,
                "detected_at": row.detected_at if isinstance(row.detected_at, str) else "",
            }
            for row in rows[:50]
        ],
    }


@router.post("/diff/{diff_id}/resolve")
def resolve_diff(
    diff_id: str,
    payload: ResolveRequest,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    diff = session.execute(select(ResourceDiff).where(ResourceDiff.id == diff_id)).scalar_one_or_none()
    if diff is None:
        raise NotFoundError("差异记录不存在")
    # 治理状态是审计对象：只读角色不得改写（viewer 曾可直接调用本接口）
    if not _engine.check_capability(subject, "diff:resolve").allowed:
        audit_action(request, session, subject, "governance:resolve", "denied", diff.project_id, "missing_capability")
        raise PermissionDeniedError("当前角色无差异处置权限")
    assert_project_access(subject, diff.project_id)
    if not _engine.check_level(subject, diff.project_id, diff.classification).allowed:
        audit_action(request, session, subject, "governance:resolve", "denied", diff.project_id, "level_exceeded")
        raise PermissionDeniedError("数据密级超出授权上限")

    diff.status = payload.status
    diff.resolved_note = payload.note
    diff.assignee = payload.assignee or subject.display_name
    if payload.status != GovernanceStatus.OPEN.value:
        diff.resolved_at = ts()
    session.commit()
    audit_action(
        request, session, subject, "governance:resolve", "allowed", diff.project_id, None,
        resource_type="resource_diff", resource_id=diff.id, metadata={"status": payload.status},
    )
    return {"id": diff.id, "status": diff.status, "resolved_at": diff.resolved_at}


@router.get("/export")
def export_diffs(
    request: Request,
    project_id: str = Query(...),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    """导出受行数与频次双重限制，且导出内容不含负责人等敏感字段。"""
    assert_project_access(subject, project_id)
    ceiling_levels = levels_at_or_below(subject.ceiling_for(project_id))
    # 单次导出上限取「路由硬上限」与「安全策略行数上限」的较小者：
    # 取大者会让 >SECURITY_EXPORT_LIMIT 的项目永远导不出来（直接 403），
    # 而截断到上限再显式告知 truncated=True 才是可用的降级。
    row_cap = min(_EXPORT_ROW_CAP, get_settings().SECURITY_EXPORT_LIMIT)
    # 排序固定为最新优先：无 ORDER BY 的 limit 在不同方言/索引下取到的行不同，
    # 导出结果不可复现；多取 1 条用于判断是否被上限截断（旧实现静默截断）。
    rows = session.execute(
        select(ResourceDiff)
        .where(ResourceDiff.project_id == project_id)
        .where(ResourceDiff.classification.in_(ceiling_levels))
        .order_by(ResourceDiff.detected_at.desc())
        .limit(row_cap + 1)
    ).scalars().all()
    truncated = len(rows) > row_cap
    rows = rows[:row_cap]
    enforce_export(subject, len(rows))
    audit_action(
        request, session, subject, "governance:export", "allowed", project_id, None,
        metadata={"rows": len(rows), "truncated": truncated},
    )
    return {
        "project_id": project_id,
        "row_count": len(rows),
        "truncated": truncated,
        "row_cap": row_cap,
        "rows": [
            {
                "id": row.id,
                "platform": row.platform,
                "kind": row.kind,
                "diff_kind": row.diff_kind,
                "rule_code": row.rule_code,
                "cost_delta_cny": row.cost_delta_cny,
                "status": row.status,
                "rule_hint": row.rule_hint,
                "detected_at": row.detected_at if isinstance(row.detected_at, str) else "",
                # 导出不含负责人姓名、精确日期与项目内部备注
            }
            for row in rows
        ],
    }


@router.get("/cost-impact")
def cost_impact(
    project_id: str | None = Query(None),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    project_ids = scoped_project_ids(subject, project_id)
    scope_clause = diff_scope_clause(subject, project_ids)
    if scope_clause is None:
        return {"items": [], "total_cny": 0}
    stmt = (
        select(ResourceDiff.diff_kind, func.sum(ResourceDiff.cost_delta_cny), func.count(ResourceDiff.id))
        .where(scope_clause)
    )
    rows = session.execute(stmt.group_by(ResourceDiff.diff_kind)).all()
    items = [
        {"diff_kind": kind, "cost_delta_cny": round(float(total or 0), 2), "count": int(count or 0)}
        for kind, total, count in rows
    ]
    return {
        "project_id": project_id,
        "items": items,
        "total_cny": round(sum(item["cost_delta_cny"] for item in items), 2),
    }


__all__ = ["router"]
