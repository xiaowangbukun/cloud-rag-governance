"""Prometheus 指标（零第三方依赖）。

为什么自己写 exposition 而不引 ``prometheus_client``：只需要「请求计数 +
耗时直方图」两个指标族，引入客户端库要多背一个依赖与升级面。

与运行期计数（预算 / 登录锁定）不同，这里**进程内计数是正确的**：Prometheus
按 Pod 抓取，再在服务端聚合；跨副本共享反而会让每个 Pod 的数字失真。

安全约束：``/metrics`` 不做鉴权（抓取器通常不便携带凭据），因此它只能经
集群内网访问——Ingress 不路由该路径，Namespace 的默认拒绝入站策略也已生效。
"""

from __future__ import annotations

import time
from threading import Lock
from typing import Iterable

#: 秒级桶：覆盖「本地查询（毫秒级）」到「模型网关超时（几十秒）」两端
_BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


class _Histogram:
    """累计式桶计数 + 总和 + 总数（Prometheus histogram 的最小形态）。"""

    __slots__ = ("buckets", "total", "count")

    def __init__(self) -> None:
        self.buckets = [0] * len(_BUCKETS)
        self.total = 0.0
        self.count = 0

    def observe(self, value: float) -> None:
        self.total += value
        self.count += 1
        for index, boundary in enumerate(_BUCKETS):
            if value <= boundary:
                # 累计桶：命中当前边界即计入所有更大边界，这里只记命中位置，
                # 渲染时再累加（省掉每次写入的 O(n) 回填）。
                self.buckets[index] += 1
                break

    def cumulative(self) -> Iterable[int]:
        running = 0
        for value in self.buckets:
            running += value
            yield running


class MetricsRegistry:
    """进程内指标注册表。"""

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: dict[tuple[str, str, str], int] = {}
        self._durations: dict[str, _Histogram] = {}

    def observe(self, method: str, path: str, status: str, duration: float) -> None:
        with self._lock:
            key = (method, path, status)
            self._requests[key] = self._requests.get(key, 0) + 1
            histogram = self._durations.get(path)
            if histogram is None:
                histogram = _Histogram()
                self._durations[path] = histogram
            histogram.observe(duration)

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()
            self._durations.clear()

    def render(self) -> str:
        """渲染成 Prometheus 文本格式（按标签排序，输出可稳定 diff）。"""
        with self._lock:
            requests = sorted(self._requests.items())
            durations = sorted(self._durations.items())

        lines = [
            "# HELP rg_http_requests_total HTTP 请求总数（按路由模板 / 方法 / 状态码）",
            "# TYPE rg_http_requests_total counter",
        ]
        for (method, path, status), count in requests:
            lines.append(
                f"rg_http_requests_total{_labels(method=method, path=path, status=status)} {count}"
            )

        lines += [
            "# HELP rg_http_request_duration_seconds HTTP 请求耗时（秒）",
            "# TYPE rg_http_request_duration_seconds histogram",
        ]
        for path, histogram in durations:
            for boundary, value in zip(_BUCKETS, histogram.cumulative()):
                lines.append(
                    f"rg_http_request_duration_seconds_bucket"
                    f"{_labels(path=path, le=_format_boundary(boundary))} {value}"
                )
            lines.append(
                f"rg_http_request_duration_seconds_bucket{_labels(path=path, le='+Inf')} "
                f"{histogram.count}"
            )
            lines.append(
                f"rg_http_request_duration_seconds_sum{_labels(path=path)} {histogram.total:.6f}"
            )
            lines.append(
                f"rg_http_request_duration_seconds_count{_labels(path=path)} {histogram.count}"
            )
        # 末尾必须换行，否则解析器会丢弃最后一行
        return "\n".join(lines) + "\n"


def _labels(**values: str) -> str:
    """渲染标签集；转义反斜杠、双引号与换行（Prometheus 文本格式要求）。"""
    if not values:
        return ""
    pairs = []
    for key in sorted(values):
        raw = str(values[key]).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        pairs.append(f'{key}="{raw}"')
    return "{" + ",".join(pairs) + "}"


def _format_boundary(value: float) -> str:
    return f"{value:g}"


#: 全局注册表：中间件写入、``/metrics`` 只读
REGISTRY = MetricsRegistry()


def reset_metrics() -> None:
    """测试用：清空已采集的指标。"""
    REGISTRY.reset()


class MetricsMiddleware:
    """统计每个 HTTP 请求的次数与耗时。

    路由标签取 **路由模板**（``scope["route"].path``）而不是原始路径：
    用原始路径会把 ``/resources/{id}`` 拆成上千个标签，直接打爆 Prometheus
    时序基数。未匹配到路由（404）统一记 ``unmatched``。

    注册为最外层中间件：TrustedHost 拒绝（400）、CORS 预检、未捕获异常
    （500）都要计入——只统计「成功进入业务层」的请求会掩盖最需要告警的部分。
    """

    def __init__(
        self,
        app,
        *,
        registry: MetricsRegistry = REGISTRY,
        enabled: bool = True,
        skip_paths: tuple[str, ...] = ("/metrics",),
    ) -> None:
        self.app = app
        self.registry = registry
        self.enabled = enabled
        self.skip_paths = skip_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.enabled or scope.get("path") in self.skip_paths:
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status = 500  # 应用在发出响应前抛异常时按 500 计

        async def send_with_status(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message.get("status", 500))
            await send(message)

        try:
            await self.app(scope, receive, send_with_status)
        finally:
            route = scope.get("route")
            path = getattr(route, "path", None) or "unmatched"
            self.registry.observe(
                scope.get("method", "GET"),
                path,
                str(status),
                time.perf_counter() - started,
            )


__all__ = ["MetricsMiddleware", "MetricsRegistry", "REGISTRY", "reset_metrics"]
