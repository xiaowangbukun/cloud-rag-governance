"""Access policy engine (RBAC + ABAC).

关键约束：
- 检索前先做授权预过滤（allowed_project_ids / allowed_levels），禁止「先召回再过滤」
- 角色只决定能力边界，数据边界由 project_id + 密级共同决定
- 所有拒绝都返回 reason_code，供审计与前端提示
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Sequence

from rg_contracts.enums import (
    CLASSIFICATION_ORDER,
    Classification,
    Role,
    classification_rank,
    level_allows,
)

ROLE_CAPABILITIES: dict[str, set[str]] = {
    Role.ADMIN.value: {
        "resource:read",
        "resource:write",
        "diff:read",
        "diff:resolve",
        "attribution:run",
        "knowledge:read",
        "knowledge:write",
        "knowledge:reindex",
        "collection:run",
        "collection:read",
        "audit:read",
        "security:read",
        "admin:config",
        "export:standard",
    },
    Role.GOVERNANCE.value: {
        "resource:read",
        "diff:read",
        "diff:resolve",
        "attribution:run",
        "knowledge:read",
        "knowledge:write",
        "collection:run",
        "collection:read",
        "audit:read",
        "security:read",
        "export:standard",
    },
    Role.PM.value: {
        "resource:read",
        "diff:read",
        "diff:resolve",
        "attribution:run",
        "knowledge:read",
    },
    Role.AUDITOR.value: {
        "resource:read",
        "diff:read",
        "knowledge:read",
        "audit:read",
        "security:read",
    },
    Role.VIEWER.value: {"resource:read", "diff:read", "knowledge:read"},
}


@dataclass(frozen=True)
class Subject:
    """Authenticated principal with resolved organization context."""

    user_id: str
    subject: str
    display_name: str
    role: str
    org_id: str | None
    classification_ceiling: str
    project_ids: frozenset[str] = frozenset()
    visible_ceilings: dict[str, str] = field(default_factory=dict)
    auth_mode: str = "dev"
    attributes: dict = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        return capability in ROLE_CAPABILITIES.get(self.role, set())

    def ceiling_for(self, project_id: str) -> str:
        """项目级密级上限 = min(用户总体上限, 项目内上限)。"""
        project_ceiling = self.visible_ceilings.get(project_id)
        if not project_ceiling:
            return self.classification_ceiling
        if classification_rank(project_ceiling) < classification_rank(self.classification_ceiling):
            return project_ceiling
        return self.classification_ceiling


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_code: str
    message: str
    details: dict = field(default_factory=dict)

    @classmethod
    def allow(cls, reason_code: str = "allowed", **details) -> "Decision":
        return cls(True, reason_code, "允许访问", details)

    @classmethod
    def deny(cls, reason_code: str, message: str, **details) -> "Decision":
        return cls(False, reason_code, message, details)


@dataclass(frozen=True)
class AccessScope:
    """授权边界：所有查询必须先落到这里。"""

    project_ids: frozenset[str]
    max_level: str
    unrestricted: bool = False

    def allows_project(self, project_id: str | None) -> bool:
        if self.unrestricted:
            return True
        return project_id in self.project_ids if project_id else False

    def allows_level(self, level: str) -> bool:
        if self.unrestricted:
            return True
        return level_allows(self.max_level, level)

    def as_filters(self) -> dict:
        return {
            "project_ids": sorted(self.project_ids),
            "max_level": self.max_level,
            "unrestricted": self.unrestricted,
        }


class PolicyEngine:
    def __init__(self, capabilities: dict[str, set[str]] | None = None) -> None:
        self.capabilities = capabilities or ROLE_CAPABILITIES

    # ------------------------------------------------------------- capabilities
    def check_capability(self, subject: Subject, capability: str) -> Decision:
        # 以引擎自身的能力表为准，保证可注入自定义策略进行隔离测试
        if capability in self.capabilities.get(subject.role, set()):
            return Decision.allow("capability_granted", capability=capability)
        return Decision.deny(
            "missing_capability",
            f"角色 {subject.role} 不具备能力 {capability}",
            capability=capability,
        )

    # ------------------------------------------------------------------- scope
    def build_scope(self, subject: Subject) -> AccessScope:
        """管理员/治理角色覆盖全部项目，但仍受密级上限约束。"""
        unrestricted = subject.role in (Role.ADMIN.value, Role.GOVERNANCE.value)
        return AccessScope(
            project_ids=subject.project_ids,
            max_level=subject.classification_ceiling,
            unrestricted=unrestricted,
        )

    def check_project(self, subject: Subject, project_id: str | None) -> Decision:
        scope = self.build_scope(subject)
        if scope.unrestricted:
            return Decision.allow("unrestricted_scope")
        if not project_id:
            return Decision.deny("project_required", "请求必须限定到具体项目")
        if project_id not in scope.project_ids:
            # 不泄露项目是否存在
            return Decision.deny("project_out_of_scope", "无该项目访问权限")
        return Decision.allow("project_in_scope")

    def check_level(self, subject: Subject, project_id: str, level: str) -> Decision:
        ceiling = subject.ceiling_for(project_id)
        if not level_allows(ceiling, level):
            return Decision.deny(
                "level_exceeded",
                "数据密级超出授权上限",
                ceiling=ceiling,
                level=level,
            )
        return Decision.allow("level_ok", ceiling=ceiling)

    # ------------------------------------------------------------------ 范围类
    def check_time_span(self, start: datetime | None, end: datetime | None, max_days: int) -> Decision:
        if start and end:
            if end < start:
                return Decision.deny("invalid_range", "结束时间早于开始时间")
            if (end - start).days > max_days:
                return Decision.deny(
                    "span_too_large",
                    f"查询跨度超过 {max_days} 天，禁止跨周期拼图",
                    days=(end - start).days,
                )
        return Decision.allow("span_ok")

    def check_scope_request(
        self, subject: Subject, project_ids: Sequence[str] | None, levels: Sequence[str] | None
    ) -> Decision:
        scope = self.build_scope(subject)
        if scope.unrestricted:
            return Decision.allow("unrestricted_scope")
        if not project_ids:
            return Decision.deny("project_required", "查询必须指定授权项目范围")
        for pid in project_ids:
            if pid not in scope.project_ids:
                return Decision.deny("project_out_of_scope", "包含未授权项目")
        for level in levels or []:
            if classification_rank(level) > classification_rank(scope.max_level):
                return Decision.deny("level_exceeded", "包含超出密级的检索目标")
        return Decision.allow("scope_ok")

    # ------------------------------------------------------------------ 导出
    def check_export(self, subject: Subject, row_count: int, limit: int) -> Decision:
        if not subject.has_capability("export:standard"):
            return Decision.deny("export_forbidden", "当前角色无导出权限")
        if row_count > limit:
            return Decision.deny(
                "export_limit_exceeded",
                f"导出行数 {row_count} 超过单批上限 {limit}",
                row_count=row_count,
                limit=limit,
            )
        return Decision.allow("export_ok")


def levels_at_or_below(ceiling: str) -> list[str]:
    rank = classification_rank(ceiling)
    return [
        level.value
        for level in Classification
        if CLASSIFICATION_ORDER[level.value] <= rank
    ]


def normalize_levels(levels: Iterable[str] | None, ceiling: str) -> list[str]:
    requested = list(levels) if levels else []
    allowed = set(levels_at_or_below(ceiling))
    filtered = [lv for lv in requested if lv in allowed]
    return filtered or levels_at_or_below(ceiling)


def default_engine() -> PolicyEngine:
    return PolicyEngine()
