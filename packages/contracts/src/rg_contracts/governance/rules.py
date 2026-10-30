"""治理判定规则（D1/D2/D4/D5/D6/D7）。

规则层只做「纯函数判定」：入参是已经过授权过滤的锚点、属性与指标，出参是
``DiffRecord``。这样设计有三个原因：

1. **授权在规则之外**。规则拿不到 ``Session``，也就不可能为了省事写
   ``select(GpuNode).where(...)`` 绕开锚点过滤——这是属性表「密级只在锚点上」
   这套安全基座的最后一段。
2. **可单测**。判定逻辑不碰数据库，构造几个锚点就能覆盖阈值边界。
3. **不跨项目聚合**。``RuleContext`` 只承载单个 ``project_id``，规则天然拼不出
   跨项目画像（拼图攻击的合法出口之一就是"规则层顺手做了全集群统计"）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from rg_contracts.collector.diff import DiffRecord
from rg_contracts.enums import DiffKind, ResourceKind

#: D1 治理项的规则标识（写入 ``resource_diff.rule_code``）。
D1_GPU_UTILIZATION_WASTE = "d1_gpu_utilization_waste"


@dataclass(frozen=True)
class RuleAnchor:
    """规则可见的单个资源视图（**密级取对象有效密级，不是调用者上限**）。

    ``metrics`` 缺失某个指标时就是「这一轮没采到」，不是 0；``details`` 是类型
    专属属性（如 ``allocated_gpus``），没有对应属性行时为空字典。
    """

    resource_id: str
    native_id: str
    project_id: str
    classification: str
    name: str
    kind: str
    platform: str
    monthly_cost_cny: float | None = None
    metrics: Mapping[str, float] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleContext:
    """一次判定上下文：单项目 + 该项目内已过滤的锚点。"""

    project_id: str
    classification: str
    anchors: Sequence[RuleAnchor]
    #: D1 阈值（百分比）：利用率低于该值且确实分配了 GPU，判为浪费。
    gpu_idle_util_threshold: float = 10.0


class GovernanceRule(Protocol):
    """规则协议：给定上下文，产出治理项（可能为空）。"""

    dim: str
    code: str

    def evaluate(self, ctx: RuleContext) -> list[DiffRecord]: ...


class D1UtilizationWasteRule:
    """D1：GPU 已分配但利用率长期偏低 → 浪费治理项。

    三个必要条件缺一不可，缺任何一个都**不产出**（宁可漏报，不可误报）：

    - 资源类型是 ``gpu_node``；
    - ``gpu_utilization`` 指标存在（缺失 ≠ 0，见 ``collector/metrics.py``）；
    - ``allocated_gpus`` 明确大于 0（不知道分配情况时无法断言"浪费"）。
    """

    dim = "D1"
    code = D1_GPU_UTILIZATION_WASTE

    def evaluate(self, ctx: RuleContext) -> list[DiffRecord]:
        records: list[DiffRecord] = []
        for anchor in ctx.anchors:
            if anchor.kind != ResourceKind.GPU_NODE.value:
                continue
            utilization = anchor.metrics.get("gpu_utilization")
            if utilization is None:
                continue
            allocated = _as_int(anchor.details.get("allocated_gpus"))
            if allocated is None or allocated <= 0:
                continue
            if utilization >= ctx.gpu_idle_util_threshold:
                continue
            records.append(
                DiffRecord(
                    native_id=anchor.native_id,
                    name=anchor.name,
                    kind=anchor.kind,
                    platform=anchor.platform,
                    project_id=anchor.project_id,
                    diff_kind=DiffKind.UTILIZATION_WASTE.value,
                    cost_delta_cny=None,
                    rule_hint="GPU 利用率偏低：核对业务是否需要该规格，评估缩容或释放",
                    summary=(
                        f"已分配 {allocated} 张 GPU，利用率 {utilization:g}% "
                        f"（阈值 {ctx.gpu_idle_util_threshold:g}%）"
                    ),
                    payload={
                        "gpu_utilization": utilization,
                        "allocated_gpus": allocated,
                        "threshold": ctx.gpu_idle_util_threshold,
                    },
                    resource_id=anchor.resource_id,
                    rule_code=self.code,
                )
            )
        return records


#: 规则注册表：新增维度只需在协议下实现并登记。
RULES: tuple[GovernanceRule, ...] = (D1UtilizationWasteRule(),)


def evaluate(
    anchors: Sequence[RuleAnchor],
    *,
    gpu_idle_util_threshold: float = 10.0,
) -> list[DiffRecord]:
    """按 ``project_id`` 分组跑全部规则。

    分组是必要的：``RuleContext`` 只能承载单项目，规则层因此拿不到跨项目视图。
    """
    by_project: dict[str, list[RuleAnchor]] = {}
    for anchor in anchors:
        by_project.setdefault(anchor.project_id, []).append(anchor)

    records: list[DiffRecord] = []
    for project_id, group in by_project.items():
        classification = group[0].classification
        ctx = RuleContext(
            project_id=project_id,
            classification=classification,
            anchors=group,
            gpu_idle_util_threshold=gpu_idle_util_threshold,
        )
        for rule in RULES:
            records.extend(rule.evaluate(ctx))
    return records


def _as_int(value: Any) -> int | None:
    """把属性值转成整数；``bool`` 与非数值一律视为未知（返回 None）。

    ``bool`` 单独排除的原因与指标写入相同：``True`` 会被 ``int()`` 悄悄当成 1，
    把「开关」读成「分配了 1 张卡」。
    """
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


__all__ = [
    "D1_GPU_UTILIZATION_WASTE",
    "D1UtilizationWasteRule",
    "GovernanceRule",
    "RULES",
    "RuleAnchor",
    "RuleContext",
    "evaluate",
]
