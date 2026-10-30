"""FastAPI 应用装配。"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from rg_contracts.config import Settings, get_settings
from rg_contracts.logging_setup import configure_logging
from starlette.middleware.trustedhost import TrustedHostMiddleware

from rg_api.metrics import MetricsMiddleware
from rg_api.routes import (
    admin,
    attribution,
    audit,
    auth,
    collection,
    governance,
    health,
    knowledge,
    resources,
)
from rg_api.security_headers import SecurityHeadersMiddleware


def _docs_urls(settings: Settings) -> dict[str, str | None]:
    """交互式文档与 OpenAPI 描述的暴露策略。

    生产关闭：``/openapi.json`` 会把全部路由、参数与错误码免费交出去，
    配合 ``/docs`` 还能直接构造请求，等于给攻击者一份免登录的接口说明书
    （内网部署不是豁免理由——横向移动往往就从内网开始）。
    非 prod 保留，本地调试与联调需要它。
    """
    if settings.is_prod:
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings)
    from rg_api.startup import bootstrap

    bootstrap(settings)
    yield

def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings)
    # 幂等引导：保证本地开发、单测与 uvicorn 启动时都完成建表与种子
    from rg_api.startup import ensure_bootstrap

    ensure_bootstrap(settings)
    app = FastAPI(
        title="多云资源治理与安全 RAG 归因平台",
        version="1.0.0",
        description="内网部署：资源采集 / 增量 diff / 安全 RAG 归因 / 治理闭环 / 审计",
        lifespan=lifespan,
        **_docs_urls(settings),
    )
    # Host 头校验：TRUSTED_HOSTS 此前只是配置项、全代码库无人使用，
    # Host 头注入（缓存投毒 / 密码重置链接投毒）没有任何防线。
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_host_list)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
    # 最后注册 = 最外层：TrustedHost 的 400、CORS 预检、错误处理器的响应
    # 都要经过它，避免「正常响应有安全头、报错响应没有」。
    # HSTS 只给 prod：明文 HTTP 环境下发 HSTS 会把浏览器锁在门外。
    # /api/v1/auth/* 带访问令牌，禁止任何中间缓存留存。
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts=settings.is_prod,
        docs_paths=tuple(
            path for path in _docs_urls(settings).values() if path
        ),
        no_store_prefixes=(f"{settings.API_PREFIX}/auth",),
    )
    # 指标放最外层：TrustedHost 的 400、CORS 预检、未捕获的 500 都要计入——
    # 只统计成功进入业务层的请求，会漏掉最需要告警的那部分。
    app.add_middleware(MetricsMiddleware, enabled=settings.METRICS_ENABLED)
    from rg_api.errors import install_error_handlers

    install_error_handlers(app)

    prefix = settings.API_PREFIX
    app.include_router(health.router)
    app.include_router(auth.router, prefix=prefix)
    app.include_router(resources.router, prefix=prefix)
    app.include_router(collection.router, prefix=prefix)
    app.include_router(attribution.router, prefix=prefix)
    app.include_router(knowledge.router, prefix=prefix)
    app.include_router(governance.router, prefix=prefix)
    app.include_router(audit.router, prefix=prefix)
    app.include_router(admin.router, prefix=prefix)
    return app


app = create_app()
