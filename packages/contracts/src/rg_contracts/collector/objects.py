"""类型专属属性表的写入方：``gpu_node``。

与 ``collector/metrics.py`` 同一套理由：属性分表只保存「类型专属属性」，
锚点（``resource``）上的 ``attributes`` 不再重复存一份，否则两个事实源会
各自漂移。读取侧必须经锚点（见 ``db/models.py`` 的 ``GpuNode`` 注释）。

为什么单独成模块而不是塞进采集路由：条目解析（属性键裁剪、类型转换、
非法值丢弃）是每次新增属性表都要复用一遍的逻辑，放路由里会复制粘贴。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from sqlalchemy.orm import Session

from rg_contracts.db.models import GpuNode, ts

#: ``attributes`` 里属于 ``gpu_node`` 表的键。这些键在锚点行上会被剥离，
#: 避免「属性表改了、锚点 attributes 没改」时两处互相矛盾。
GPU_ATTRIBUTE_KEYS: tuple[str, ...] = (
    "gpu_model",
    "total_gpus",
    "allocated_gpus",
    "driver_version",
    "cuda_version",
    "mig_enabled",
)

_INT_FIELDS = ("total_gpus", "allocated_gpus")


def gpu_details(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """从采集属性里挑出 ``gpu_node`` 字段；非法值与缺省字段一律不出现。"""
    raw = attributes or {}
    details: dict[str, Any] = {}
    for key in ("gpu_model", "driver_version", "cuda_version"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            details[key] = value.strip()[:64]
    for key in _INT_FIELDS:
        number = _as_int(raw.get(key))
        if number is not None and number >= 0:
            details[key] = number
    mig = raw.get("mig_enabled")
    if isinstance(mig, bool):
        details["mig_enabled"] = mig
    return details


def upsert_gpu_node(
    session: Session,
    *,
    resource_id: str,
    attributes: Mapping[str, Any] | None,
    asset_tag: str | None = None,
) -> bool:
    """把 ``gpu_node`` 属性写入（主键即锚点外键，天然 upsert）。

    返回 ``False`` 表示这条属性里没有任何可用字段，因此没有写行——这与
    「值为 0」不同：``total_gpus=0`` 是合法观测，会被写出。
    """
    details = gpu_details(attributes)
    if not details:
        return False
    row = session.get(GpuNode, resource_id)
    if row is None:
        session.add(
            GpuNode(
                resource_id=resource_id,
                updated_at=ts(datetime.now()),
                asset_tag=asset_tag,
                **details,
            )
        )
    else:
        for key, value in details.items():
            setattr(row, key, value)
        row.updated_at = ts(datetime.now())
        if asset_tag:
            row.asset_tag = asset_tag
    return True


def _as_int(value: Any) -> int | None:
    """整数化；``bool`` 与非数值返回 None（``True`` 不该变成 1 张卡）。"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


__all__ = ["GPU_ATTRIBUTE_KEYS", "gpu_details", "upsert_gpu_node"]
