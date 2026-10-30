"""管理配置：模型网关、目录同步、安全策略视图。"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from rg_contracts.ai.gateway import ModelGateway, mask_secret
from rg_contracts.config import get_settings
from rg_contracts.db.models import DirectorySyncState, ModelGatewayConfig, new_id, ts
from rg_contracts.db.session import db_session
from rg_contracts.errors import (
    ConfigurationError,
    NotFoundError,
    ValidationError,
)
from rg_contracts.security.policy import Subject
from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services.access import assert_capability
from rg_api.services.audit import audit_action
from rg_api.services.gateways import serialize_gateway_config

router = APIRouter(prefix="/admin", tags=["admin"])


class GatewayIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    provider: str = Field(pattern="^(internal|openai_compatible)$")
    base_url: str = Field(min_length=1, max_length=512)
    model: str = Field(min_length=1, max_length=128)
    api_key_ref: str | None = None
    api_key_value: str | None = None
    enabled: bool = True
    is_default: bool = False
    sanitize_before_send: bool = True
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout_seconds: int = 120


def _require_admin(
    subject: Subject,
    *,
    request: Request | None = None,
    session: Session | None = None,
) -> None:
    """管理员校验；给了 request+session 时拒绝会补 denied 审计（QA 实测此前为零留痕）。

    复用 ``assert_capability`` 单一判定口径，不另写一份能力判断。
    """
    assert_capability(subject, "admin:config", request=request, session=session)


def _assert_endpoint_allowed(payload: GatewayIn) -> None:
    """保存前校验：外部模型主机必须已在白名单内，避免配置阶段就埋下出网风险。"""
    gateway = ModelGateway(get_settings()).from_row(
        SimpleNamespace(
            name=payload.name,
            provider=payload.provider,
            base_url=payload.base_url,
            model=payload.model,
            api_key_ref=payload.api_key_ref,
            api_key_masked=None,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            timeout_seconds=payload.timeout_seconds,
            sanitize_before_send=payload.sanitize_before_send,
            extra_headers={},
            is_default=payload.is_default,
        )
    )
    try:
        ModelGateway(get_settings()).assert_endpoint_allowed(gateway)
    except ConfigurationError as exc:
        raise ValidationError(str(exc.detail_message), host=exc.details.get("host")) from exc


@router.get("/config")
def view_config(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    _require_admin(subject, request=request, session=session)
    settings = get_settings()
    safe = settings.model_dump_safe()
    return {
        "app_env": safe["APP_ENV"],
        "auth_mode": safe["AUTH_MODE"],
        "directory_mode": safe["DIRECTORY_MODE"],
        "collector_mode": safe["COLLECTOR_MODE"],
        "embedding_backend": safe["EMBEDDING_BACKEND"],
        "embedding_model": safe["EMBEDDING_MODEL"],
        "security": {
            "max_span_days": safe["SECURITY_MAX_SPAN_DAYS"],
            "query_budget_per_hour": safe["SECURITY_QUERY_BUDGET_PER_HOUR"],
            "export_limit": safe["SECURITY_EXPORT_LIMIT"],
            "canary_enabled": safe["SECURITY_CANARY_ENABLED"],
            "mask_entities": safe["SECURITY_MASK_ENTITIES"],
            "coarse_buckets": safe["SECURITY_COARSE_BUCKETS"],
            "redact_owner": safe["SECURITY_REDACT_OWNER"],
        },
        "model": {
            "allow_public": safe["MODEL_GATEWAY_ALLOW_PUBLIC"],
            "allowed_hosts": settings.allowed_model_hosts,
        },
    }


@router.get("/gateways")
def list_gateways(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    _require_admin(subject, request=request, session=session)
    rows = session.execute(select(ModelGatewayConfig)).scalars().all()
    return [serialize_gateway_config(row) for row in rows]


@router.post("/gateways")
def create_gateway(
    payload: GatewayIn,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    _require_admin(subject, request=request, session=session)
    _assert_endpoint_allowed(payload)
    if payload.is_default:
        for row in session.execute(
            select(ModelGatewayConfig).where(ModelGatewayConfig.is_default.is_(True))
        ).scalars().all():
            row.is_default = False

    rows = session.execute(select(ModelGatewayConfig)).scalars().all()
    is_first = not rows

    row = ModelGatewayConfig(
        id=new_id("mgw"),
        name=payload.name,
        provider=payload.provider,
        base_url=payload.base_url,
        model=payload.model,
        api_key_ref=payload.api_key_ref,
        api_key_masked=mask_secret(payload.api_key_value),
        enabled=payload.enabled,
        is_default=payload.is_default or is_first,
        sanitize_before_send=payload.sanitize_before_send,
        temperature=payload.temperature,
        max_tokens=payload.max_tokens,
        timeout_seconds=payload.timeout_seconds,
        updated_by=subject.user_id,
    )
    session.add(row)
    session.commit()
    audit_action(
        request, session, subject, "admin:gateway_create", "allowed", None, None,
        resource_type="model_gateway_config", resource_id=row.id,
        metadata={"provider": row.provider, "base_url": row.base_url},
    )
    return {"id": row.id, "is_default": row.is_default}


@router.patch("/gateways/{gateway_id}")
def update_gateway(
    gateway_id: str,
    payload: GatewayIn,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    _require_admin(subject, request=request, session=session)
    _assert_endpoint_allowed(payload)
    row = session.execute(
        select(ModelGatewayConfig).where(ModelGatewayConfig.id == gateway_id)
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError("网关配置不存在")
    if payload.is_default:
        for other in session.execute(
            select(ModelGatewayConfig).where(ModelGatewayConfig.is_default.is_(True))
        ).scalars().all():
            other.is_default = False

    row.name = payload.name
    row.provider = payload.provider
    row.base_url = payload.base_url
    row.model = payload.model
    row.api_key_ref = payload.api_key_ref
    if payload.api_key_value:
        row.api_key_masked = mask_secret(payload.api_key_value)
    row.enabled = payload.enabled
    row.is_default = payload.is_default
    row.sanitize_before_send = payload.sanitize_before_send
    row.temperature = payload.temperature
    row.max_tokens = payload.max_tokens
    row.timeout_seconds = payload.timeout_seconds
    row.updated_by = subject.user_id
    session.commit()
    audit_action(
        request, session, subject, "admin:gateway_update", "allowed", None, None,
        resource_type="model_gateway_config", resource_id=row.id,
        metadata={"provider": row.provider, "base_url": row.base_url},
    )
    return {"id": row.id}


@router.post("/gateways/{gateway_id}/test")
def test_gateway(
    gateway_id: str,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    """只做连通性验证，不发送任何业务数据。"""
    _require_admin(subject, request=request, session=session)
    row = session.execute(
        select(ModelGatewayConfig).where(ModelGatewayConfig.id == gateway_id)
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError("网关配置不存在")
    gateway = ModelGateway(get_settings())
    settings_obj = gateway.from_row(row)
    result = gateway.test_connection(settings_obj)
    audit_action(
        request, session, subject, "admin:gateway_test",
        "allowed" if result.get("ok") else "failed", None, None,
        resource_type="model_gateway_config", resource_id=row.id, metadata=result,
    )
    return result


@router.get("/directory/sync")
def directory_sync(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    _require_admin(subject, request=request, session=session)
    settings = get_settings()
    row = session.execute(
        select(DirectorySyncState).where(DirectorySyncState.provider == settings.DIRECTORY_MODE.value)
    ).scalar_one_or_none()
    if row is None:
        return {"provider": settings.DIRECTORY_MODE.value, "status": "idle", "last_sync_at": None}
    return {
        "provider": row.provider,
        "status": row.status,
        "cursor": row.cursor,
        "last_sync_at": row.last_sync_at if isinstance(row.last_sync_at, str) else None,
        "message": row.message,
        "stats": row.stats,
    }


@router.post("/directory/sync")
def trigger_directory_sync(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    """预留：对接公司统一身份接口批量同步组织信息。"""
    _require_admin(subject, request=request, session=session)
    settings = get_settings()
    row = session.execute(
        select(DirectorySyncState).where(DirectorySyncState.provider == settings.DIRECTORY_MODE.value)
    ).scalar_one_or_none()
    if row is None:
        row = DirectorySyncState(
            id=new_id("dir"),
            provider=settings.DIRECTORY_MODE.value,
            status="idle",
        )
        session.add(row)
    row.last_sync_at = ts()
    row.status = "not_configured" if settings.DIRECTORY_MODE.value == "static" else "pending"
    row.message = (
        "静态目录模式无需同步；接入公司统一身份接口时在此触发增量同步"
        if settings.DIRECTORY_MODE.value == "static"
        else "已排队，等待目录服务回调"
    )
    row.stats = {"mode": settings.DIRECTORY_MODE.value}
    session.commit()
    audit_action(
        request, session, subject, "admin:directory_sync", "allowed", None, None,
        metadata={"provider": row.provider, "status": row.status},
    )
    return {"provider": row.provider, "status": row.status, "message": row.message}


__all__ = ["router"]
