"""治理判定编排：规则层的唯一调用方。

分工：
- 规则层（``rg_contracts.governance.rules``）是纯函数，只管「阈值与对象属性」；
- 本模块负责构造锚点视图、去重、把治理项落进 ``resource_diff``。

去重口径：同一资源 + 同一 ``rule_code`` 已存在 **open** 治理项时不再新建。
原因是不去重的话每轮采集都会把看板灌满同一条结论；反过来，规则命中后人工
处置（resolve）再采集会重新产出——这是有意的回归提醒，不是重复记录。
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from rg_contracts.collector import metrics as metric_writer
from rg_contracts.collector import objects as object_writer
from rg_contracts.collector.diff import DiffRecord
from rg_contracts.db.models import ResourceDiff, new_id, ts
from rg_contracts.enums import GovernanceStatus
from rg_contracts.governance import rules
from rg_contracts.governance.rules import RuleAnchor
from sqlalchemy import select
from sqlalchemy.orm import Session


def build_anchors(
    items: Sequence[Any],
    *,
    resource_ids: Mapping[str, str],
    levels: Mapping[str, str],
) -> list[RuleAnchor]:
    """把采集结果映射成规则可见的锚点视图。

    ``classification`` 取**项目目录密级**（``levels``），不取调用者上限：治理项
    若带错密级，``diff_scope_clause`` 会以「治理项」形态泄漏高密级对象的存在性。
    指标在这里再过滤一遍：报告里给出的脏值不能绕过写入层的校验进到判定逻辑。
    """
    anchors: list[RuleAnchor] = []
    for item in items:
        resource_id = resource_ids.get(item.native_id)
        project_id = item.project_id
        if resource_id is None or project_id not in levels:
            continue
        anchors.append(
            RuleAnchor(
                resource_id=resource_id,
                native_id=item.native_id,
                project_id=project_id,
                classification=levels[project_id],
                name=item.name,
                kind=item.kind,
                platform=item.platform,
                monthly_cost_cny=item.monthly_cost_cny,
                metrics=metric_writer.valid_metrics(item.metrics),
                details=object_writer.gpu_details(item.attributes),
            )
        )
    return anchors


def open_rule_keys(
    session: Session, *, resource_ids: Sequence[str], rule_codes: Sequence[str]
) -> set[tuple[str | None, str | None]]:
    """查已存在的 open 治理项键 ``(resource_id, rule_code)``，用于去重。"""
    if not resource_ids or not rule_codes:
        return set()
    rows = session.execute(
        select(ResourceDiff.resource_id, ResourceDiff.rule_code)
        .where(ResourceDiff.status == GovernanceStatus.OPEN.value)
        .where(ResourceDiff.resource_id.in_(list(resource_ids)))
        .where(ResourceDiff.rule_code.in_(list(rule_codes)))
    ).all()
    return {(row.resource_id, row.rule_code) for row in rows}


def run_rules(
    session: Session,
    *,
    items: Sequence[Any],
    resource_ids: Mapping[str, str],
    levels: Mapping[str, str],
    snapshot_id: str,
    settings: Any,
) -> int:
    """跑一遍全部规则并把新增治理项落库，返回新写入条数。

    落库走普通业务事务（与锚点、指标同一提交边界）：规则命中与它依据的指标
    必须原子可见，否则重放快照时会得到「有治理项、但当时的指标对不上」。
    """
    anchors = build_anchors(items, resource_ids=resource_ids, levels=levels)
    records = rules.evaluate(
        anchors,
        gpu_idle_util_threshold=settings.GOVERNANCE_GPU_IDLE_UTIL_THRESHOLD,
    )
    if not records:
        return 0

    existing = open_rule_keys(
        session,
        resource_ids=[record.resource_id for record in records if record.resource_id],
        rule_codes=sorted({record.rule_code for record in records if record.rule_code}),
    )
    written = 0
    for record in records:
        key = (record.resource_id, record.rule_code)
        if key in existing:
            continue
        session.add(to_diff_model(record, snapshot_id, levels[record.project_id]))
        existing.add(key)
        written += 1
    return written


def to_diff_model(record: DiffRecord, snapshot_id: str, classification: str) -> ResourceDiff:
    """``DiffRecord`` → ``ResourceDiff`` 行（时序 diff 与治理项共用一条写入路径）。"""
    return ResourceDiff(
        id=new_id("diff"),
        project_id=record.project_id,
        platform=record.platform,
        resource_id=record.resource_id,
        native_id=record.native_id,
        resource_name=record.name,
        kind=record.kind,
        diff_kind=record.diff_kind,
        base_snapshot_id=None,
        target_snapshot_id=snapshot_id,
        detected_at=ts(),
        cost_delta_cny=record.cost_delta_cny,
        classification=classification,
        rule_hint=record.rule_hint,
        summary=record.summary,
        payload=record.payload,
        status=GovernanceStatus.OPEN.value,
        rule_code=record.rule_code,
    )


__all__ = ["build_anchors", "open_rule_keys", "run_rules", "to_diff_model"]
