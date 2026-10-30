from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base typed error. Never raise bare Exception across module boundaries."""

    code = "internal_error"
    http_status = 500
    message = "服务内部错误"

    def __init__(self, message: str | None = None, **details: Any) -> None:
        self.detail_message = message or self.message
        self.details = details
        super().__init__(self.detail_message)

    def to_dict(self) -> dict[str, Any]:
        payload = {"code": self.code, "message": self.detail_message}
        if self.details:
            payload["details"] = self.details
        return payload


class ValidationError(AppError):
    code = "validation_error"
    http_status = 422
    message = "请求参数校验失败"


class NotFoundError(AppError):
    code = "not_found"
    http_status = 404
    message = "资源不存在"


class AuthenticationError(AppError):
    code = "unauthenticated"
    http_status = 401
    message = "未认证或凭证已失效"


class PermissionDeniedError(AppError):
    code = "permission_denied"
    http_status = 403
    message = "无访问权限"


class RateLimitedError(AppError):
    code = "rate_limited"
    http_status = 429
    message = "访问频率超限"


class PolicyDeniedError(PermissionDeniedError):
    code = "policy_denied"
    message = "访问策略拒绝"


class ScopeViolationError(PolicyDeniedError):
    code = "scope_violation"
    message = "查询范围超出授权边界"


class EnumerationDetectedError(PolicyDeniedError):
    code = "enumeration_detected"
    message = "检测到批量枚举行为，已拒绝并记录审计"


class LeakageBlockedError(AppError):
    code = "leakage_blocked"
    http_status = 451
    message = "输出包含敏感信息，已被安全策略拦截"

    #: 详情里**不允许出域**的键：命中样本就是刚被拦下的敏感值本身。
    _UNSAFE_DETAIL_KEYS = frozenset({"sample", "samples", "value", "match", "matched_text"})

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        details = payload.get("details")
        if isinstance(details, dict):
            payload["details"] = {
                key: self._scrub(value) if not key.startswith("_") else value
                for key, value in details.items()
                if key not in self._UNSAFE_DETAIL_KEYS
            }
        return payload

    @classmethod
    def _scrub(cls, value: Any) -> Any:
        """递归去掉 findings 内的样本字段：451 响应会原样交给调用方。"""
        if isinstance(value, dict):
            return {
                key: cls._scrub(item)
                for key, item in value.items()
                if key not in cls._UNSAFE_DETAIL_KEYS
            }
        if isinstance(value, list):
            return [cls._scrub(item) for item in value]
        return value


class CanaryLeakError(LeakageBlockedError):
    code = "canary_leak"


class PromptInjectionError(ValidationError):
    code = "prompt_injection"
    message = "检测到疑似提示词注入"


class ExternalServiceError(AppError):
    code = "external_service_error"
    http_status = 502
    message = "外部服务调用失败"


class ModelGatewayError(ExternalServiceError):
    code = "model_gateway_error"


class EmbeddingError(ExternalServiceError):
    code = "embedding_error"


class CollectorError(ExternalServiceError):
    code = "collector_error"


class ConfigurationError(AppError):
    code = "configuration_error"
    http_status = 500
    message = "配置错误"
