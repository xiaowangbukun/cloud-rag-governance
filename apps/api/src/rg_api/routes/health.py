from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, PlainTextResponse
from rg_contracts.config import get_settings
from rg_contracts.db.session import db_session
from rg_contracts.errors import NotFoundError
from rg_contracts.logging_setup import get_request_id
from sqlalchemy import text
from sqlalchemy.orm import Session

from rg_api.metrics import REGISTRY

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    """存活探针：只证明进程还在（不碰依赖，避免依赖故障引发重启风暴）。"""
    return {"status": "ok", "request_id": get_request_id()}


@router.get("/ready")
def ready(session: Session = Depends(db_session)) -> JSONResponse:
    """就绪探针：数据库不可达时返回 **503**，让负载均衡摘掉本副本。

    修复两处：
    - 旧实现无论 DB 是否可用都返回 HTTP 200（``status`` 只是文案），
      K8s readiness 永远不会失败，DB 故障期间流量继续打进来；
    - 旧实现每次探针都做 ``COUNT(*)`` 全表扫描（10s 一次 × 副本数）。
      就绪只关心「连接与查询是否可用」，``SELECT 1`` 足够；知识库规模
      放在独立的运维接口，不应和探针耦合。
    """
    settings = get_settings()
    try:
        session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        # 会话已进入失败态：先回滚成干净状态，否则依赖清理时的 commit 会再抛，
        # 把 503 变成 500（依赖清理异常会覆盖已返回的响应）
        try:
            session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "database": "error",
                "dialect": settings.DB_DIALECT.value,
                "request_id": get_request_id(),
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "database": "ok",
            "dialect": settings.DB_DIALECT.value,
            "request_id": get_request_id(),
        },
    )


@router.get("/metrics", include_in_schema=False)
def metrics() -> PlainTextResponse:
    """Prometheus 抓取端点。

    不做鉴权是刻意的：抓取器通常不便携带凭据。代价是必须保证它只能从
    集群内网访问——Ingress 不路由 ``/metrics``，Namespace 默认拒绝入站。
    关闭开关后返回 404（与从未提供该端点不可区分）。
    """
    if not get_settings().METRICS_ENABLED:
        raise NotFoundError("指标端点未启用")
    return PlainTextResponse(
        REGISTRY.render(),
        media_type="text/plain; version=0.0.4",
    )
