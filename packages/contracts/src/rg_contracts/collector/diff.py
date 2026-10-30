"""增量 diff 引擎。

- 指纹比对，避免时间戳/顺序抖动产生假差异
- 差异类型：新增 / 释放 / 规格变更 / 状态变更 / 标签变更 / 责任人变更
- 规则化初判（rule_hint）先落库，LLM 只做语义补充，模型不可用时不影响链路
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from rg_contracts.enums import DiffKind


@dataclass
class DiffRecord:
    native_id: str
    name: str
    kind: str
    platform: str
    project_id: str
    diff_kind: str
    cost_delta_cny: float | None
    rule_hint: str
    summary: str
    payload: dict = field(default_factory=dict)
    resource_id: str | None = None
    #: 判定规则标识（``d1_gpu_utilization_waste`` 等）；时序 diff 为 None。
    #: 落库后用于规则级回归与看板按规则分组（``resource_diff.rule_code``）。
    rule_code: str | None = None


def compute_diff(
    previous: dict[str, dict],
    current: dict[str, dict],
    platform: str,
) -> list[DiffRecord]:
    """按 native_id 对齐，逐字段比对。

    previous/current: native_id -> {fingerprint, name, kind, project_id, spec, status,
    tags, owner, monthly_cost_cny, resource_id}
    """
    records: list[DiffRecord] = []
    for native_id, cur in current.items():
        prev = previous.get(native_id)
        if prev is None:
            records.append(
                DiffRecord(
                    native_id=native_id,
                    name=cur.get("name", ""),
                    kind=cur.get("kind", "other"),
                    platform=platform,
                    project_id=cur.get("project_id", ""),
                    diff_kind=DiffKind.NEW.value,
                    cost_delta_cny=cur.get("monthly_cost_cny"),
                    rule_hint="新增资源：需核对申请单与预算归属",
                    summary=f"新增 {cur.get('kind', '资源')} {cur.get('name', native_id)}",
                    payload={"spec": cur.get("spec"), "status": cur.get("status")},
                    resource_id=cur.get("resource_id"),
                )
            )
            continue
        if prev.get("fingerprint") == cur.get("fingerprint"):
            continue
        records.extend(_changed_fields(prev, cur, platform, native_id))

    for native_id, prev in previous.items():
        if native_id not in current:
            records.append(
                DiffRecord(
                    native_id=native_id,
                    name=prev.get("name", ""),
                    kind=prev.get("kind", "other"),
                    platform=platform,
                    project_id=prev.get("project_id", ""),
                    diff_kind=DiffKind.REMOVED.value,
                    cost_delta_cny=-(prev.get("monthly_cost_cny") or 0),
                    rule_hint="资源释放：确认是否为计划内下线，避免账实不符",
                    summary=f"资源消失 {prev.get('kind', '资源')} {prev.get('name', native_id)}",
                    payload={"last_spec": prev.get("spec"), "last_status": prev.get("status")},
                    resource_id=prev.get("resource_id"),
                )
            )
    return records


def _changed_fields(prev: dict, cur: dict, platform: str, native_id: str) -> list[DiffRecord]:
    records: list[DiffRecord] = []
    base = {
        "native_id": native_id,
        "name": cur.get("name", ""),
        "kind": cur.get("kind", "other"),
        "platform": platform,
        "project_id": cur.get("project_id", prev.get("project_id", "")),
        "resource_id": cur.get("resource_id") or prev.get("resource_id"),
    }

    if prev.get("spec") != cur.get("spec"):
        records.append(
            DiffRecord(
                **base,
                diff_kind=DiffKind.SPEC_CHANGED.value,
                cost_delta_cny=_delta(prev.get("monthly_cost_cny"), cur.get("monthly_cost_cny")),
                rule_hint="规格变更：核对变更单与容量评估",
                summary=f"规格 {prev.get('spec')} → {cur.get('spec')}",
                payload={"from": prev.get("spec"), "to": cur.get("spec")},
            )
        )
    if prev.get("status") != cur.get("status"):
        records.append(
            DiffRecord(
                **base,
                diff_kind=DiffKind.STATE_CHANGED.value,
                cost_delta_cny=_delta(prev.get("monthly_cost_cny"), cur.get("monthly_cost_cny")),
                rule_hint=_status_hint(prev.get("status"), cur.get("status")),
                summary=f"状态 {prev.get('status')} → {cur.get('status')}",
                payload={"from": prev.get("status"), "to": cur.get("status")},
            )
        )
    if (prev.get("tags") or {}) != (cur.get("tags") or {}):
        records.append(
            DiffRecord(
                **base,
                diff_kind=DiffKind.TAG_CHANGED.value,
                cost_delta_cny=None,
                rule_hint="标签变更：核对成本中心归属是否调整",
                summary="资源标签发生变化",
                payload={"from": prev.get("tags"), "to": cur.get("tags")},
            )
        )
    if (prev.get("owner") or None) != (cur.get("owner") or None):
        records.append(
            DiffRecord(
                **base,
                diff_kind=DiffKind.OWNER_CHANGED.value,
                cost_delta_cny=None,
                rule_hint="责任人变更：核对调拨流程是否闭环",
                summary="责任人发生变更（姓名不进入模型上下文）",
                payload={"changed": True},
            )
        )
    return records


def _status_hint(prev_status: Any, cur_status: Any) -> str:
    if prev_status == "running" and cur_status == "stopped":
        return "运行转停止：核对是否为闲置资源，评估下线或释放"
    if prev_status == "stopped" and cur_status == "running":
        return "停止转运行：核对是否为临时扩容或回滚恢复"
    if cur_status == "expired":
        return "已到期：核对续采或释放决策"
    return "状态变更：核对变更记录与业务影响"


def _delta(prev_cost: Any, cur_cost: Any) -> float | None:
    if prev_cost is None and cur_cost is None:
        return None
    return round(float(cur_cost or 0) - float(prev_cost or 0), 2)


def diff_summary(records: Sequence[DiffRecord]) -> dict:
    by_kind: dict[str, int] = {}
    cost_impact = 0.0
    for record in records:
        by_kind[record.diff_kind] = by_kind.get(record.diff_kind, 0) + 1
        cost_impact += record.cost_delta_cny or 0
    return {
        "total": len(records),
        "by_kind": by_kind,
        "cost_impact_cny": round(cost_impact, 2),
    }


__all__ = ["DiffRecord", "compute_diff", "diff_summary", "Iterable"]
