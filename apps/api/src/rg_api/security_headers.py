"""API 安全响应头中间件。

为什么 API 自己要管这些头：`deploy/k8s/05-web.yaml` 的 nginx 已经下发了
CSP / nosniff / XFO，但它只覆盖「经过 web 容器」的流量。集群内直连 Service、
`kubectl port-forward`、SDK/脚本调用都不经过 nginx，此前这些响应一个安全头
都没有——同一套 API，走不同入口得到不同防护等级，属于典型的「防护依赖网络拓扑」。

中间件刻意保持纯 ASGI（不包 ``BaseHTTPMiddleware``）：后者会引入额外的
任务/流式响应语义，而这里只需在 ``http.response.start`` 上追加几个头。
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# API 只返回 JSON：默认拒绝一切资源加载，并禁止被任何页面内嵌。
_STRICT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# /docs、/redoc 的 Swagger UI 依赖 CDN 脚本与内联样式；仅在非 prod 暴露，
# 这里单独放宽，免得本地打开文档页是一片空白（prod 已是 404，不生效）。
_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)
_HSTS = "max-age=31536000; includeSubDomains"

# 与协议、部署域名无关，任何环境都该带上
_BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class SecurityHeadersMiddleware:
    """给所有 HTTP 响应补安全头。

    - ``hsts`` 仅在 prod 打开：HSTS 一旦下发，浏览器会在 max-age 内强制 HTTPS，
      本地/内网明文 HTTP 环境打开会把自己锁在门外。
    - ``no_store_prefixes`` 命中时补 ``Cache-Control: no-store``：登录/刷新响应
      里带访问令牌，落进任何中间缓存都等于泄露。
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts: bool = False,
        docs_paths: tuple[str, ...] = ("/docs", "/redoc", "/openapi.json"),
        no_store_prefixes: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.hsts = hsts
        self.docs_paths = docs_paths
        self.no_store_prefixes = no_store_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        is_docs = any(path == item or path.startswith(f"{item}/") for item in self.docs_paths)
        no_store = any(path.startswith(prefix) for prefix in self.no_store_prefixes)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in _BASE_HEADERS.items():
                    # setdefault 语义：下游若已显式设置（例如未来某个路由
                    # 需要放宽），以路由为准，中间件不覆盖。
                    if key not in headers:
                        headers[key] = value
                if "content-security-policy" not in headers:
                    headers["Content-Security-Policy"] = _DOCS_CSP if is_docs else _STRICT_CSP
                if self.hsts and "strict-transport-security" not in headers:
                    headers["Strict-Transport-Security"] = _HSTS
                if no_store and "cache-control" not in headers:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)
