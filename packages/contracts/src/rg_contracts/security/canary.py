"""安全金丝雀（canary）：验证敏感字段不会进入 embedding / Prompt / 模型输出。

机制：
- 每个项目在种子阶段植入唯一诱饵值（项目代号、负责人姓名、精确金额、里程碑日期）
- 所有进入模型或向量的文本都必须先通过 canary 扫描
- 命中即阻断并写入安全事件，形成可度量的泄露防线
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Canary:
    project_id: str
    kind: str
    value: str
    description: str


@dataclass
class CanaryHit:
    project_id: str
    kind: str
    description: str
    matched_preview: str


class CanaryRegistry:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._canaries: list[Canary] = []
        self._patterns: list[tuple[re.Pattern[str], Canary]] = []

    def register(self, canary: Canary) -> None:
        self._canaries.append(canary)
        pattern = re.compile(re.escape(canary.value))
        self._patterns.append((pattern, canary))

    def register_many(self, canaries: Iterable[Canary]) -> None:
        for canary in canaries:
            self.register(canary)

    @property
    def count(self) -> int:
        return len(self._canaries)

    def scan(self, text: str) -> list[CanaryHit]:
        if not self.enabled or not text:
            return []
        hits: list[CanaryHit] = []
        for pattern, canary in self._patterns:
            match = pattern.search(text)
            if match:
                start = max(0, match.start() - 8)
                preview = text[start : match.end() + 8]
                hits.append(
                    CanaryHit(
                        project_id=canary.project_id,
                        kind=canary.kind,
                        description=canary.description,
                        matched_preview=preview,
                    )
                )
        return hits

    def assert_clean(self, text: str, stage: str) -> None:
        """命中即抛错，由上层转为阻断 + 审计。"""
        from rg_contracts.errors import CanaryLeakError

        hits = self.scan(text)
        if hits:
            raise CanaryLeakError(
                f"安全金丝雀在 {stage} 阶段被命中，已阻断",
                stage=stage,
                hits=[hit.__dict__ for hit in hits],
            )


@dataclass
class CanarySet:
    """一个项目的诱饵集合。"""

    project_id: str
    items: list[Canary] = field(default_factory=list)

    def build(self, code: str, owner: str, milestone: str, amount: str, secret_note: str) -> "CanarySet":
        self.items = [
            Canary(self.project_id, "project_code", code, "项目代号诱饵"),
            Canary(self.project_id, "owner", owner, "负责人姓名诱饵"),
            Canary(self.project_id, "milestone", milestone, "里程碑日期诱饵"),
            Canary(self.project_id, "amount", amount, "精确金额诱饵"),
            Canary(self.project_id, "secret_note", secret_note, "内部备注诱饵"),
        ]
        return self


def build_registry(sets: Iterable[CanarySet], enabled: bool = True) -> CanaryRegistry:
    registry = CanaryRegistry(enabled=enabled)
    for item in sets:
        registry.register_many(item.items)
    return registry
