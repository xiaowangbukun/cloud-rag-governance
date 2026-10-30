"""模型网关出域面序列化：admin 与 attribution 两个路由共用同一份字段口径。

历史上两份序列化各写一遍且已漂移（admin 15 字段 / attribution 13 字段，
缺 timeout_seconds 与 updated_by），任何一侧新增字段另一侧都会静默缺失。
网关 base_url / api_key_ref 属出域面敏感配置，两处必须逐字段一致。
"""

from __future__ import annotations

from rg_contracts.ai.gateway import mask_secret, resolve_api_key
from rg_contracts.db.models import ModelGatewayConfig


def serialize_gateway_config(row: ModelGatewayConfig) -> dict:
    """把一行网关配置序列化为出域面 dict（15 字段，权威口径）。

    ``api_key_masked`` 兜底解析：库里未存掩码时按 ``api_key_ref`` 现场解析，
    保证任何写入路径（API 创建 / 种子 / 迁移补录）输出都不出现明文密钥。
    """
    return {
        "id": row.id,
        "name": row.name,
        "provider": row.provider,
        "base_url": row.base_url,
        "model": row.model,
        "api_key_ref": row.api_key_ref,
        "api_key_masked": row.api_key_masked or mask_secret(resolve_api_key(row.api_key_ref)),
        "enabled": row.enabled,
        "is_default": row.is_default,
        "sanitize_before_send": row.sanitize_before_send,
        "temperature": row.temperature,
        "max_tokens": row.max_tokens,
        "timeout_seconds": row.timeout_seconds,
        "updated_by": row.updated_by,
    }
