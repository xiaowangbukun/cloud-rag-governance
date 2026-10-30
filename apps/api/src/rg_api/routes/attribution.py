"""差异语义归因：规则先行 + 受控 RAG + 模型网关，输出前 DLP 与金丝雀校验。

安全顺序（不可调换）：
1. 授权边界 → 2. 事实读取 → 3. 安全投影（脱敏）→ 4. 受控检索（预过滤）
5. 金丝雀扫描 → 6. 出网白名单 → 7. 模型调用 → 8. 输出 DLP → 9. 审计落库
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.gateway import AttributionResult, GatewaySettings, ModelGateway
from rg_contracts.ai.retrieval import RetrievalHit, SecureRetriever
from rg_contracts.config import Settings, get_settings
from rg_contracts.db.base import TimestampCodec
from rg_contracts.db.models import Attribution, ModelGatewayConfig, ResourceDiff, ts
from rg_contracts.db.session import db_session
from rg_contracts.enums import EvidenceLevel, ModelProvider
from rg_contracts.errors import NotFoundError, PermissionDeniedError
from rg_contracts.security.budget import get_budget
from rg_contracts.security.dlp import OutputDlp, default_dlp
from rg_contracts.security.jigsaw import JigsawGuard
from rg_contracts.security.policy import Subject, default_engine, levels_at_or_below
from rg_contracts.security.sanitize import Sanitizer
from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services.access import assert_capability, assert_project_access, scoped_project_ids
from rg_api.services.audit import audit_action, audit_security
from rg_api.services.gateways import serialize_gateway_config
from rg_api.startup import get_canary_registry

router = APIRouter(prefix="/attribution", tags=["attribution"])
_engine = default_engine()


class AttributionRequest(BaseModel):
    diff_id: str
    question: str | None = Field(default=None, max_length=500)
    provider: str | None = None
    top_k: int = Field(default=6, ge=1, le=20)


class AttributionOut(BaseModel):
    id: str
    diff_id: str
    project_id: str
    task_id: str
    cause: str
    confidence: float
    explanation: str
    recommended_action: str
    evidence_level: str
    provider: str
    model_name: str
    citations: list[dict]
    blocked: bool
    created_at: str | None
    security: dict


def _load_gateway(session: Session, provider: str | None) -> GatewaySettings:
    stmt = select(ModelGatewayConfig).where(ModelGatewayConfig.enabled.is_(True))
    if provider:
        stmt = stmt.where(ModelGatewayConfig.provider == provider)
    row = (
        session.execute(stmt.order_by(ModelGatewayConfig.is_default.desc())).scalars().first()
    )
    if row is None:
        settings = get_settings()
        return ModelGateway(settings).from_env(provider)
    return ModelGateway(get_settings()).from_row(row)


def _authorize_attribution(
    request: Request,
    session: Session,
    subject: Subject,
    diff_id: str,
) -> tuple[ResourceDiff, list[str]]:
    """步骤 1-2：读取差异记录，授权边界 + 防枚举预算。

    Returns:
        (diff, project_ids)：project_ids 供步骤 4 受控检索的候选预过滤复用。
    """
    diff = session.execute(
        select(ResourceDiff).where(ResourceDiff.id == diff_id)
    ).scalar_one_or_none()
    if diff is None:
        raise NotFoundError("差异记录不存在")

    # 1) 授权边界
    decision = _engine.check_project(subject, diff.project_id)
    if not decision.allowed:
        audit_action(request, session, subject, "attribution:run", "denied", diff.project_id, decision.reason_code)
        raise PermissionDeniedError(decision.message)
    if not _engine.check_level(subject, diff.project_id, diff.classification).allowed:
        audit_action(request, session, subject, "attribution:run", "denied", diff.project_id, "level_exceeded")
        raise PermissionDeniedError("数据密级超出授权上限")
    assert_project_access(subject, diff.project_id)

    # 2) 防枚举预算（用真实项目 ID；受限主体的单项目归因才计入跨项目探测）
    project_ids = scoped_project_ids(subject, diff.project_id)
    unrestricted = _engine.build_scope(subject).unrestricted
    try:
        get_budget().enforce_retrieval(subject.user_id, project_ids, unrestricted)
    except PermissionDeniedError as exc:
        audit_security(
            session,
            subject,
            "enumeration_blocked",
            f"归因检索被防枚举策略拦截：{exc.code}",
            severity="high",
            metadata={"diff_id": diff.id},
            project_id=diff.project_id,
            independent=True,
        )
        audit_action(request, session, subject, "attribution:run", "denied", diff.project_id, exc.code)
        raise
    return diff, project_ids


def _project_diff_text(settings: Settings, diff: ResourceDiff) -> str:
    """步骤 3：安全投影——事实 → 脱敏语义（负责人/精确日期/金额不外流）。"""
    projection = Sanitizer(settings).project_diff(diff)
    return projection.to_text()


def _retrieve_evidence(
    session: Session,
    settings: Settings,
    subject: Subject,
    diff: ResourceDiff,
    project_ids: list[str],
    payload: AttributionRequest,
) -> tuple[list[RetrievalHit], list[str]]:
    """步骤 4：受控检索——先按授权过滤候选，再算相似度。

    Returns:
        (hits, allowed_levels)：allowed_levels 需随响应出域面披露。
    """
    unrestricted = _engine.build_scope(subject).unrestricted
    allowed_projects = [] if unrestricted else project_ids
    allowed_levels = levels_at_or_below(subject.ceiling_for(diff.project_id))
    embedder = get_embedding_service(settings)
    retriever = SecureRetriever(session, settings, embedder)
    hits: list[RetrievalHit] = retriever.search(
        query=payload.question or diff.summary or diff.rule_hint or "资源差异归因",
        subject=subject,
        allowed_project_ids=allowed_projects,
        allowed_levels=allowed_levels,
        top_k=payload.top_k,
        unrestricted=unrestricted,
    )
    return hits, allowed_levels


def _guard_jigsaw(
    session: Session,
    settings: Settings,
    subject: Subject,
    diff: ResourceDiff,
    payload: AttributionRequest,
    hits: list[RetrievalHit],
) -> list[RetrievalHit]:
    """步骤 4.5：拼图防护——归因链路最容易被用来反复累积分片（一次归因 = 一次合法检索）。

    命中后按降密级处置：削减送入模型的证据片段数，风险静默入审计。
    """
    jigsaw_guard = JigsawGuard(session, settings)
    jigsaw_query = payload.question or diff.summary or diff.rule_hint or "资源差异归因"
    jigsaw_risk = jigsaw_guard.assess(subject.user_id, diff.project_id, hits, jigsaw_query)
    if jigsaw_risk.action == "coarsen" and jigsaw_risk.triggered:
        hits = hits[: max(1, settings.SECURITY_JIGSAW_COARSEN_TOP_K)]
        audit_security(
            session, subject, "jigsaw_risk_detected",
            f"归因检索命中拼图风险（{jigsaw_risk.risk}），已降密级削减证据片段",
            severity="high",
            metadata={"diff_id": diff.id, "jigsaw": jigsaw_risk.as_dict()},
        )
    jigsaw_guard.record(subject.user_id, hits, jigsaw_query, downgraded=jigsaw_risk.triggered)
    return hits


def _scan_canary_context(
    request: Request,
    session: Session,
    settings: Settings,
    subject: Subject,
    diff: ResourceDiff,
    projection_text: str,
    hits: list[RetrievalHit],
) -> None:
    """步骤 5：金丝雀扫描——确保净化文本未夹带敏感原文，命中且策略要求时阻断。"""
    canary_registry = get_canary_registry()
    canary_hits = canary_registry.scan(projection_text + " " + " ".join(h.display_text for h in hits))
    if canary_hits and settings.SECURITY_BLOCK_ON_CANARY:
        # 检索账本此前已 flush：先提交暂存区（本次检索确实发生过，
        # 账本记录属于防御数据应保留），再走独立事务写安全事件与拒绝审计，
        # 避免 SQLite 写锁互斥导致留痕丢失
        session.commit()
        audit_security(
            session,
            subject,
            "canary_leak_blocked",
            "归因上下文命中安全金丝雀，已阻断",
            severity="critical",
            metadata={"diff_id": diff.id, "hits": [h.__dict__ for h in canary_hits]},
            project_id=diff.project_id,
            independent=True,
        )
        audit_action(request, session, subject, "attribution:run", "denied", diff.project_id, "canary_leak")
        raise PermissionDeniedError("归因上下文命中安全策略，已阻断并记录")


def _analyze_diff(
    session: Session,
    settings: Settings,
    payload: AttributionRequest,
    diff: ResourceDiff,
    projection_text: str,
    hits: list[RetrievalHit],
    dlp: OutputDlp,
) -> tuple[GatewaySettings, AttributionResult, str]:
    """步骤 6：模型网关——白名单 + 出网前脱敏。

    Returns:
        (gateway_settings, result, task_id)。
    """
    gateway_settings = _load_gateway(session, payload.provider)
    gateway = ModelGateway(settings, dlp)
    task_id = f"task_{uuid.uuid4().hex[:16]}"
    result = gateway.analyze(
        gateway_settings,
        question=payload.question or "请给出该资源差异的可能原因、置信度与处置建议",
        projection_text=projection_text,
        hits=hits,
        fallback_rule=diff.rule_hint,
    )
    return gateway_settings, result, task_id


def _enforce_output_dlp(
    session: Session,
    subject: Subject,
    diff: ResourceDiff,
    result: AttributionResult,
    dlp: OutputDlp,
) -> tuple[bool, str | None]:
    """步骤 7：输出 DLP——模型返回内容同样需要检查，命中则降级为规则级结论。"""
    blocked = False
    block_reason = None
    try:
        safe_explanation = dlp.enforce(result.explanation, subject)
        safe_action = dlp.enforce(result.recommended_action, subject)
        result.explanation = safe_explanation
        result.recommended_action = safe_action
    except Exception as exc:  # noqa: BLE001
        blocked = True
        block_reason = getattr(exc, "code", "leakage_blocked")
        result.explanation = "输出包含敏感信息，已被安全策略拦截"
        result.recommended_action = "请按治理 SOP 人工复核"
        result.evidence_level = EvidenceLevel.RULE.value
        audit_security(
            session,
            subject,
            "output_dlp_blocked",
            f"归因输出被 DLP 拦截：{block_reason}",
            severity="high",
            metadata={"diff_id": diff.id},
        )
    return blocked, block_reason


def _persist_attribution(
    session: Session,
    request: Request,
    subject: Subject,
    diff: ResourceDiff,
    result: AttributionResult,
    task_id: str,
    blocked: bool,
    block_reason: str | None,
    hit_count: int,
) -> Attribution:
    """步骤 8-9：归因结论落库并记审计（blocked 时 outcome 记 denied）。"""
    attribution = Attribution(
        id=f"attr_{uuid.uuid4().hex[:16]}",
        diff_id=diff.id,
        project_id=diff.project_id,
        task_id=task_id,
        cause=result.cause[:190],
        confidence=result.confidence,
        explanation=result.explanation,
        recommended_action=result.recommended_action,
        evidence_level=result.evidence_level,
        provider=result.provider,
        model_name=result.model_name,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        latency_ms=result.latency_ms,
        citations={"items": result.citations},
        blocked=blocked,
        block_reason=block_reason,
        created_at=ts(),
    )
    session.add(attribution)
    audit_action(
        request,
        session,
        subject,
        "attribution:run",
        "denied" if blocked else "allowed",
        diff.project_id,
        block_reason,
        resource_type="resource_diff",
        resource_id=diff.id,
        metadata={
            "provider": result.provider,
            "model": result.model_name,
            "evidence_level": result.evidence_level,
            "hits": hit_count,
            "task_id": task_id,
        },
    )
    session.commit()
    return attribution


@router.post("/run", response_model=AttributionOut)
def run_attribution(
    payload: AttributionRequest,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> AttributionOut:
    """差异归因主编排：按文件头 9 步安全顺序调用私有步骤，自身只做流程编排。"""
    settings = get_settings()
    dlp = default_dlp()

    # 归因会调用模型网关（成本 + 出域面），必须按能力位收口；
    # 此前只校验项目/密级，只读角色可直接触发（QA 实测 viewer 返回 200）。
    assert_capability(subject, "attribution:run", request=request, session=session)

    diff, project_ids = _authorize_attribution(request, session, subject, payload.diff_id)
    projection_text = _project_diff_text(settings, diff)
    hits, allowed_levels = _retrieve_evidence(session, settings, subject, diff, project_ids, payload)
    hits = _guard_jigsaw(session, settings, subject, diff, payload, hits)
    _scan_canary_context(request, session, settings, subject, diff, projection_text, hits)
    gateway_settings, result, task_id = _analyze_diff(
        session, settings, payload, diff, projection_text, hits, dlp
    )
    blocked, block_reason = _enforce_output_dlp(session, subject, diff, result, dlp)
    attribution = _persist_attribution(
        session, request, subject, diff, result, task_id, blocked, block_reason, len(hits)
    )

    return AttributionOut(
        id=attribution.id,
        diff_id=diff.id,
        project_id=diff.project_id,
        task_id=task_id,
        cause=attribution.cause,
        confidence=attribution.confidence,
        explanation=attribution.explanation,
        recommended_action=attribution.recommended_action or "",
        evidence_level=attribution.evidence_level,
        provider=attribution.provider,
        model_name=attribution.model_name or "",
        citations=result.citations,
        blocked=blocked,
        created_at=attribution.created_at if isinstance(attribution.created_at, str) else "",
        security={
            "projection": projection_text,
            "owner_redacted": settings.SECURITY_REDACT_OWNER,
            "canary_scanned": settings.SECURITY_CANARY_ENABLED,
            "canary_hits": 0,
            "allowed_levels": allowed_levels,
            "hits": len(hits),
            "task_isolated": True,
            "output_dlp": "blocked" if blocked else "passed",
            "gateway_provider": gateway_settings.provider,
            "gateway_model": gateway_settings.model,
        },
    )


@router.get("/diff/{diff_id}")
def list_attributions(
    diff_id: str,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    diff = session.execute(
        select(ResourceDiff).where(ResourceDiff.id == diff_id)
    ).scalar_one_or_none()
    if diff is None:
        raise NotFoundError("差异记录不存在")
    if not _engine.check_project(subject, diff.project_id).allowed:
        audit_action(request, session, subject, "attribution:list", "denied", diff.project_id, "project_out_of_scope")
        raise PermissionDeniedError("无该项目访问权限")
    # P1-12：项目内可见 ≠ 密级可读。归因结论含 cause/explanation/recommended_action，
    # 是从事实域推导出的高敏内容，必须按 ceiling_for(project_id) 校验 diff 密级；
    # 越限条目一律不返回（与 run_attribution 的 check_level 同一口径）。
    level = _engine.check_level(subject, diff.project_id, diff.classification)
    if not level.allowed:
        audit_action(request, session, subject, "attribution:list", "denied", diff.project_id, "level_exceeded")
        raise PermissionDeniedError(level.message)
    rows = session.execute(
        select(Attribution).where(Attribution.diff_id == diff_id).order_by(Attribution.created_at.desc())
    ).scalars().all()
    return [
        {
            "id": row.id,
            "task_id": row.task_id,
            "cause": row.cause,
            "confidence": row.confidence,
            "explanation": row.explanation,
            "recommended_action": row.recommended_action,
            "evidence_level": row.evidence_level,
            "provider": row.provider,
            "model_name": row.model_name,
            "blocked": row.blocked,
            # 方言无关序列化：SQLite 为 ISO 文本，PG 为 timestamptz（读回 datetime）
            "created_at": TimestampCodec.encode(row.created_at) or "",
        }
        for row in rows
    ]


@router.get("/gateways")
def list_gateways(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    """网关清单含 base_url / api_key_ref，属出域面敏感配置：仅管理员可读（P1-13）。

    与 admin.py 的 /admin/gateways 同权限口径（admin:config 能力）；
    拒绝经 assert_capability 落 denied 审计。路由保留是为兼容既有 API
    消费方（前端实际只调 /admin/gateways，本端点无前端调用）。
    """
    assert_capability(subject, "admin:config", request=request, session=session)
    rows = session.execute(select(ModelGatewayConfig)).scalars().all()
    return [serialize_gateway_config(row) for row in rows]


__all__ = ["router", "ModelProvider", "GatewaySettings"]
