"""采集侧指标写入：``resource_metric`` 的唯一生产写入方。

为什么单独成模块
----------------
``resource_metric`` 的语义是「有值就是最新值，没值就没有行」。这条语义必须由
写入方保证，而不是让读取方去猜：

* **缺失不能补 0**。0 是合法的利用率，用 0 兜底会让「这一轮没采集到」与
  「资源确实空闲」在判定层无法区分，D1 会把未知当成浪费或当成健康，
  两种都是错误结论（见 ``db/models.py`` 的 ``ResourceMetric`` 注释与 PRD §8）。
* **脏值不能静默丢弃**。单个非数值指标不该让整个账号的采集失败（那会连带丢掉
  资源与差异），但丢弃必须留日志——否则判定层看到的是 ``unknown``，
  运维却查不出为什么是 ``unknown``。

指标值本身是敏感信号（QPS 可反推策略活跃度、利用率可反推训练规模），因此本模块
只做写入，不提供任何"按资源批量读出"的快捷函数：读取必须先过锚点
（``resource`` 行）的授权过滤。
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_contracts.db.models import ResourceMetric, new_id, ts
from rg_contracts.logging_setup import get_logger

logger = get_logger(__name__)

#: 未声明单位时的默认单位。当前采集到的利用率类指标都是百分比。
DEFAULT_UNIT = "%"


def valid_metrics(raw: Mapping[str, object] | None) -> dict[str, float]:
    """过滤非法指标值，只保留有限实数。

    允许 ``int`` / ``float``（``bool`` 视为非法：它会被 ``float()`` 悄悄转成 0/1，
    把"布尔开关"当成"利用率"写进指标表）。``NaN`` / ``inf`` 一并丢弃——它们不是
    测量结果，写进去会让任何阈值比较都得到 ``False``，等于静默地判成"健康"。
    """
    out: dict[str, float] = {}
    for name, value in (raw or {}).items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            logger.warning(
                "collection_metric_invalid",
                extra={"extra_fields": {"metric": str(name), "reason": "not_number"}},
            )
            continue
        number = float(value)
        if not math.isfinite(number):
            logger.warning(
                "collection_metric_invalid",
                extra={"extra_fields": {"metric": str(name), "reason": "not_finite"}},
            )
            continue
        out[str(name)] = number
    return out


def upsert_metrics(
    session: Session,
    *,
    resource_id: str,
    metrics: Mapping[str, object] | None,
    units: Mapping[str, str] | None = None,
    observed_at: datetime | None = None,
) -> int:
    """把指标最新值写入 ``resource_metric``（``(resource_id, metric_name)`` 唯一）。

    每轮采集 upsert 最新值，不保留历史明细（历史明细不在 P0 范围）。

    Args:
        session: 采集所在的会话（预演路径由调用方整体回滚即可）。
        resource_id: 锚点行（``resource``）主键；外键保证不会写入孤儿指标。
        metrics: ``{指标名: 数值}``；``None`` / 空字典表示这一轮没有指标，不写任何行。
        units: ``{指标名: 单位}``，缺省 ``%``。
        observed_at: 观测时间，缺省取当前 UTC 时间（与快照 ``taken_at`` 对齐）。

    Returns:
        实际写入或更新的行数。
    """
    clean = valid_metrics(metrics)
    if not clean:
        return 0
    timestamp = ts(observed_at)
    written = 0
    for name, value in clean.items():
        row = session.execute(
            select(ResourceMetric).where(
                ResourceMetric.resource_id == resource_id,
                ResourceMetric.metric_name == name,
            )
        ).scalar_one_or_none()
        unit = (units or {}).get(name, DEFAULT_UNIT)
        if row is None:
            session.add(
                ResourceMetric(
                    id=new_id("rm"),
                    resource_id=resource_id,
                    metric_name=name,
                    value=value,
                    unit=unit,
                    ts=timestamp,
                )
            )
        else:
            row.value = value
            row.unit = unit
            row.ts = timestamp
        written += 1
    return written


__all__ = ["DEFAULT_UNIT", "upsert_metrics", "valid_metrics"]
