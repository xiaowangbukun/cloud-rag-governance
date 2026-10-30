"""资源与差异查询：所有查询先落授权边界，再下推到 SQL。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from rg_contracts.config import get_settings
from rg_contracts.db.base import TimestampCodec
from rg_contracts.db.models import Project, Resource, ResourceDiff
from rg_contracts.db.session import db_session
from rg_contracts.enums import PLATFORM_LABELS
from rg_contracts.errors import NotFoundError, PermissionDeniedError
from rg_contracts.security.policy import Subject, default_engine
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services import objects
from rg_api.services.access import diff_scope_clause, resolve_scope, scoped_project_ids
from rg_api.services.audit import audit_action

router = APIRouter(prefix="/resources", tags=["resources"])
_engine = default_engine()


class ResourceOut(BaseModel):
    id: str
    platform: str
    platform_label: str
    project_id: str
    name: str
    kind: str
    spec: str | None
    status: str | None
    region: str | None
    monthly_cost_cny: float | None
    classification: str
    last_seen_date: str | None

    @classmethod
    def from_model(cls, row: Resource) -> "ResourceOut":
        return cls(
            id=row.id,
            platform=row.platform,
            platform_label=PLATFORM_LABELS.get(row.platform, row.platform),
            project_id=row.project_id,
            name=row.name,
            kind=row.kind,
            spec=row.spec,
            status=row.status,
            region=row.region,
            monthly_cost_cny=row.monthly_cost_cny,
            classification=row.classification,
            last_seen_date=row.last_seen_date.isoformat() if row.last_seen_date else None,
        )


class DiffOut(BaseModel):
    id: str
    project_id: str
    platform: str
    platform_label: str
    native_id: str
    resource_name: str | None
    kind: str
    diff_kind: str
    #: 判定规则标识（如 ``d1_gpu_utilization_waste``）；时序 diff 为 null。
    rule_code: str | None = None
    detected_at: str | None
    cost_delta_cny: float | None
    rule_hint: str | None
    summary: str | None
    status: str
    classification: str

    @classmethod
    def from_model(cls, row: ResourceDiff) -> "DiffOut":
        return cls(
            id=row.id,
            project_id=row.project_id,
            platform=row.platform,
            platform_label=PLATFORM_LABELS.get(row.platform, row.platform),
            native_id=row.native_id,
            resource_name=row.resource_name,
            kind=row.kind,
            diff_kind=row.diff_kind,
            rule_code=row.rule_code,
            detected_at=row.detected_at if isinstance(row.detected_at, str) else "",
            cost_delta_cny=row.cost_delta_cny,
            rule_hint=row.rule_hint,
            summary=row.summary,
            status=row.status,
            classification=row.classification,
        )


@router.get("/projects")
def list_projects(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    """只返回该用户有权访问的项目，避免通过列表枚举他人项目。"""
    scope = resolve_scope(subject)
    stmt = select(Project)
    if not scope.unrestricted:
        if not scope.project_ids:
            return []
        stmt = stmt.where(Project.id.in_(list(scope.project_ids)))
    rows = session.execute(stmt.order_by(Project.code)).scalars().all()
    return [
        {
            "id": row.id,
            "code": row.code,
            "name": row.name,
            "classification": row.classification,
            "business_criticality": row.business_criticality,
            "monthly_budget_cny": row.monthly_budget_cny,
        }
        for row in rows
    ]


@router.get("", response_model=list[ResourceOut])
def list_resources(
    request: Request,
    project_id: str = Query(..., description="必须指定项目，禁止全库扫描"),
    platform: str | None = None,
    kind: str | None = None,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[ResourceOut]:
    decision = _engine.check_project(subject, project_id)
    if not decision.allowed:
        audit_action(request, session, subject, "resource:list", "denied", project_id, decision.reason_code)
        raise PermissionDeniedError(decision.message)

    stmt = select(Resource).where(Resource.project_id == project_id)
    stmt = _apply_level_filter(stmt, subject, project_id)
    if platform:
        stmt = stmt.where(Resource.platform == platform)
    if kind:
        stmt = stmt.where(Resource.kind == kind)
    if status:
        stmt = stmt.where(Resource.status == status)
    rows = session.execute(stmt.order_by(Resource.name).limit(limit).offset(offset)).scalars().all()
    audit_action(request, session, subject, "resource:list", "allowed", project_id, metadata={"count": len(rows)})
    return [ResourceOut.from_model(row) for row in rows]


@router.get("/stats")
def resource_stats(
    request: Request,
    project_id: str = Query(...),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    decision = _engine.check_project(subject, project_id)
    if not decision.allowed:
        audit_action(request, session, subject, "resource:stats", "denied", project_id, decision.reason_code)
        raise PermissionDeniedError(decision.message)

    stmt = select(Resource.platform, func.count(Resource.id), func.sum(Resource.monthly_cost_cny)).where(
        Resource.project_id == project_id
    )
    # 聚合与明细列表走同一套密级边界，否则统计口径会泄漏超限分级的资源存在性
    stmt = _apply_level_filter(stmt, subject, project_id)
    stmt = stmt.group_by(Resource.platform)
    rows = session.execute(stmt).all()
    by_platform = [
        {
            "platform": platform,
            "platform_label": PLATFORM_LABELS.get(platform, platform),
            "count": int(count or 0),
            "monthly_cost_cny": round(float(cost or 0), 2),
        }
        for platform, count, cost in rows
    ]
    kind_stmt = select(Resource.kind, func.count(Resource.id)).where(
        Resource.project_id == project_id
    )
    kind_stmt = _apply_level_filter(kind_stmt, subject, project_id)
    kind_stmt = kind_stmt.group_by(Resource.kind)
    kind_rows = session.execute(kind_stmt).all()
    return {
        "project_id": project_id,
        "by_platform": by_platform,
        "by_kind": [{"kind": kind, "count": int(count or 0)} for kind, count in kind_rows],
        "total_monthly_cost_cny": round(sum(item["monthly_cost_cny"] for item in by_platform), 2),
    }


@router.get("/diffs", response_model=list[DiffOut])
def list_diffs(
    request: Request,
    project_id: str | None = Query(None),
    diff_kind: str | None = None,
    status: str = Query("open"),
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[DiffOut]:
    settings = get_settings()
    project_ids = scoped_project_ids(subject, project_id)

    span = _engine.check_time_span(start, end, settings.SECURITY_MAX_SPAN_DAYS)
    if not span.allowed:
        audit_action(request, session, subject, "diff:list", "denied", project_id, span.reason_code)
        raise PermissionDeniedError(span.message)

    scope_clause = diff_scope_clause(subject, project_ids)
    if scope_clause is None:
        audit_action(request, session, subject, "diff:list", "denied", project_id, "project_out_of_scope")
        return []

    stmt = select(ResourceDiff).where(scope_clause)
    if diff_kind:
        stmt = stmt.where(ResourceDiff.diff_kind == diff_kind)
    if status:
        stmt = stmt.where(ResourceDiff.status == status)
    # detected_at 在 SQLite 以 ISO-8601 文本存储，比较前需统一编码
    if start:
        stmt = stmt.where(ResourceDiff.detected_at >= TimestampCodec.encode(start))
    if end:
        stmt = stmt.where(ResourceDiff.detected_at <= TimestampCodec.encode(end))
    rows = session.execute(
        stmt.order_by(ResourceDiff.detected_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    audit_action(request, session, subject, "diff:list", "allowed", project_id, metadata={"count": len(rows)})
    return [DiffOut.from_model(row) for row in rows]


@router.get("/diffs/summary")
def diff_summary(
    request: Request,
    project_id: str | None = Query(None),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    project_ids = scoped_project_ids(subject, project_id)
    scope_clause = diff_scope_clause(subject, project_ids)
    if scope_clause is None:
        return {"total": 0, "by_kind": {}, "cost_impact_cny": 0}
    stmt = (
        select(ResourceDiff.diff_kind, func.count(ResourceDiff.id), func.sum(ResourceDiff.cost_delta_cny))
        .where(scope_clause)
    )
    stmt = stmt.group_by(ResourceDiff.diff_kind)
    rows = session.execute(stmt).all()
    by_kind = {kind: int(count or 0) for kind, count, _ in rows}
    cost = sum(float(value or 0) for _, _, value in rows)
    return {
        "project_id": project_id,
        "total": sum(by_kind.values()),
        "by_kind": by_kind,
        "cost_impact_cny": round(cost, 2),
    }


class ResourceDetailOut(ResourceOut):
    """单资源详情：锚点字段 + 属性投影。

    属性/指标/GPU 都不在锚点行上（分表见 ``db/models.py``），读取顺序必须是
    「先过项目与密级两关 → 再授权锚点 → 最后召回内容」。反过来先召回再判权，
    等于把别人的指标读进内存再过滤，审计上说不清。
    """

    #: 锚点行上的通用属性（GPU 专属键在采集时已被剥离到 ``gpu_node``）
    attributes: dict[str, Any]
    #: 指标最新值；缺失表示没采到（不是 0，判定层要判 unknown）
    metrics: dict[str, float]
    #: GPU 属性；该资源不是 GPU 节点或没有属性行时为 None
    gpu: dict[str, Any] | None = None


@router.get("/{resource_id}", response_model=ResourceDetailOut)
def get_resource_detail(
    resource_id: str,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> ResourceDetailOut:
    """单资源详情。

    为什么先查锚点行、再做两次授权：锚点行本身带 ``project_id`` 与
    ``classification``，是唯一能判密级的依据；属性/指标表没有这两列，只能按
    已授权的锚点集合读（``services/objects.py``）。在 PG 上运行角色还会被
    ``resource`` 策略先挡一次，超密级的行直接查不到（返回 404 而不是 403），
    这是有意的：数据库层不该确认「存在但你看不到」。
    """
    row = session.execute(select(Resource).where(Resource.id == resource_id)).scalar_one_or_none()
    if row is None:
        raise NotFoundError("资源不存在")

    decision = _engine.check_project(subject, row.project_id)
    if not decision.allowed:
        audit_action(
            request, session, subject, "resource:detail", "denied", row.project_id, decision.reason_code
        )
        raise PermissionDeniedError(decision.message)
    level = _engine.check_level(subject, row.project_id, row.classification)
    if not level.allowed:
        audit_action(
            request, session, subject, "resource:detail", "denied", row.project_id, level.reason_code,
            resource_type="resource", resource_id=row.id,
        )
        raise PermissionDeniedError(level.message)

    metrics = objects.load_metrics(
        session, project_id=row.project_id, subject=subject, resource_ids=[row.id]
    )
    gpu = objects.load_gpu_nodes(
        session, project_id=row.project_id, subject=subject, resource_ids=[row.id]
    )
    own_metrics = metrics.get(row.id, {})
    audit_action(
        request, session, subject, "resource:detail", "allowed", row.project_id, None,
        resource_type="resource", resource_id=row.id,
        metadata={"metrics": sorted(own_metrics), "gpu": bool(gpu.get(row.id))},
    )
    return ResourceDetailOut(
        **ResourceOut.from_model(row).model_dump(),
        attributes=row.attributes or {},
        metrics=own_metrics,
        gpu=gpu.get(row.id),
    )


def _apply_level_filter(stmt: Any, subject: Subject, project_id: str) -> Any:
    ceiling = subject.ceiling_for(project_id)
    from rg_contracts.security.policy import levels_at_or_below

    return stmt.where(Resource.classification.in_(levels_at_or_below(ceiling)))


def _is_unrestricted(subject: Subject) -> bool:
    return _engine.build_scope(subject).unrestricted


__all__ = ["router"]
