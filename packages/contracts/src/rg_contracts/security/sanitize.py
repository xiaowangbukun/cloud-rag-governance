"""安全投影：把事实域数据转换为可进入向量库/模型上下文的脱敏语义。

核心手段：
1. 标识符令牌化（HMAC-SHA256 + 盐），不可逆，跨文档一致但不可反推
2. 日期泛化到季度/月份，禁止精确日期与里程碑
3. 数值区间化，禁止精确规模与金额
4. 负责人姓名脱敏，禁止身份关联
5. 进度/计划类语义改写为治理语义，不保留排期信息
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Iterable

from rg_contracts.config import Settings, get_settings
from rg_contracts.security.detectors import (
    RE_ACCESS_KEY,
    RE_CN_MOBILE,
    RE_DATE,
    RE_EMAIL,
    RE_HOST,
    RE_ID_CARD,
    RE_IPV4,
    RE_IPV6,
    RE_MAC,
    RE_MONEY,
    RE_QUARTER,
    RE_SECRET_KEY,
    detect_injection,
    neutralize_progress,
    strip_secrets,
)

_TOKEN_PREFIX = {
    "project": "PRJ",
    "system": "SYS",
    "owner": "OWN",
    "resource": "RES",
    "account": "ACC",
}


@dataclass
class SanitizeOptions:
    mask_entities: bool = True
    coarse_buckets: bool = True
    redact_owner: bool = True
    max_text_len: int = 1200


@dataclass
class SanitizeResult:
    text: str
    removed: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


@dataclass
class SafeProjection:
    """进入模型上下文的最小事实摘要（不含原文级敏感字段）。"""

    project_token: str
    platform: str
    kind: str
    diff_kind: str
    spec_bucket: str
    cost_bucket: str
    period_bucket: str
    region: str | None
    owner_token: str | None
    tags: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        parts = [
            f"项目:{self.project_token}",
            f"平台:{self.platform}",
            f"类型:{self.kind}",
            f"变更:{self.diff_kind}",
            f"规格:{self.spec_bucket}",
            f"成本:{self.cost_bucket}",
            f"周期:{self.period_bucket}",
        ]
        if self.region:
            parts.append(f"地域:{self.region}")
        if self.owner_token:
            parts.append(f"责任人:{self.owner_token}")
        if self.tags:
            parts.append("标签:" + ",".join(self.tags))
        return " ".join(parts)


class Sanitizer:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._salt = self.settings.SECURITY_TOKEN_SALT.encode()

    # ------------------------------------------------------------------ tokens
    def tokenize(self, kind: str, value: str | None) -> str:
        if not value:
            return f"{_TOKEN_PREFIX.get(kind, 'ENT')}-UNKNOWN"
        digest = hmac.new(self._salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
        return f"{_TOKEN_PREFIX.get(kind, 'ENT')}-{digest[:10]}"

    # -------------------------------------------------------------- generalizers
    def month_bucket(self, value: date | datetime | str | None) -> str:
        parsed = _coerce_date(value)
        if parsed is None:
            return "未知周期"
        if self.settings.SECURITY_COARSE_BUCKETS:
            return f"{parsed.year}Q{(parsed.month - 1) // 3 + 1}"
        return f"{parsed.year}-{parsed.month:02d}"

    def span_days(self, start: date | datetime | None, end: date | datetime | None) -> str:
        s, e = _coerce_date(start), _coerce_date(end)
        if s is None or e is None:
            return "未知区间"
        days = (e - s).days
        return bucketize_number(days, (7, 30, 90, 180, 365), ("周内", "月内", "季度内", "半年内", "一年内", "超一年"))

    def cost_bucket(self, amount: float | None) -> str:
        if amount is None:
            return "未知"
        return bucketize_number(
            amount,
            (100, 1000, 10000, 100000, 1000000),
            ("百元级", "千元级", "万元级", "十万元级", "百万元级", "千万元级"),
        )

    @staticmethod
    def normalize_amount(text: str) -> float | None:
        """把「128万元 / 3.5亿元 / 8500元」统一折算为元，避免单位被截断导致区间误判。"""
        import re

        match = re.search(r"(\d+(?:\.\d+)?)\s*(亿元|万元|元|CNY|RMB|USD)", text, re.IGNORECASE)
        if not match:
            return _first_number(text)
        value = float(match.group(1))
        unit = match.group(2).lower()
        return value * {"元": 1.0, "cny": 1.0, "rmb": 1.0, "usd": 7.2, "万元": 1e4, "亿元": 1e8}.get(unit, 1.0)

    def spec_bucket(self, spec: str | None) -> str:
        if not spec:
            return "未知规格"
        text = spec.strip()
        # 注意：中文是 \w，不能用 \b 做边界，改用「非字母/非数字」断言
        cpu = _extract_int(
            text,
            (
                r"(\d+)\s*[Cc][Pp][Uu]",
                r"(\d+)\s*核(?!\d)",
                r"(\d+)\s*[Cc](?![A-Za-z])",
                r"(?<![A-Za-z])[Cc](\d+)",
                r"(?<![A-Za-z])[Ss]\d+\.[A-Z]+(\d+)",
            ),
        )
        mem = _extract_int(
            text,
            (
                r"(\d+)\s*[Gg][Bb](?!\d)",
                r"(\d+)\s*G内存",
                r"(?<![A-Za-z])mem(\d+)",
                r"(\d+)\s*[Cc]\d*\s*[Gg](?![A-Za-z])",
            ),
        )
        if cpu or mem:
            return (
                "cpu:"
                + bucketize_number(cpu or 0, (2, 4, 8, 16), ("小规格", "常规", "中大型", "大型", "超大型"))
                + " 内存:"
                + bucketize_number(mem or 0, (4, 8, 16, 32), ("小规格", "常规", "中大型", "大型", "超大型"))
            )
        return "标准规格"

    # ------------------------------------------------------------------ text
    def sanitize_text(self, text: str, options: SanitizeOptions | None = None) -> SanitizeResult:
        """把任意文本净化到可安全向量化的程度。"""
        opts = options or SanitizeOptions(
            mask_entities=self.settings.SECURITY_MASK_ENTITIES,
            coarse_buckets=self.settings.SECURITY_COARSE_BUCKETS,
            redact_owner=self.settings.SECURITY_REDACT_OWNER,
        )
        result = text or ""
        removed: list[str] = []
        actions: list[str] = []

        # 顺序固定：凭据 → 注入 → 进度语义 → 日期/金额泛化 → 实体掩码 → 截断
        result = strip_secrets(result)
        if RE_SECRET_KEY.search(text) or RE_ACCESS_KEY.search(text):
            removed.append("credential")
            actions.append("remove_credential")

        injections = detect_injection(result)
        if injections:
            actions.append("neutralize_injection")
            result = _regex_sub_keep(
                result,
                r"忽略(?:上面|之前|以上|所有)(?:的)?(?:指令|规则|要求|提示)|"
                r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions",
                "[已拦截指令]",
            )
            removed.append("prompt_injection")

        if opts.mask_entities:
            for regex, label in (
                (RE_ID_CARD, "证件号"),
                (RE_CN_MOBILE, "手机号"),
                (RE_EMAIL, "邮箱"),
                (RE_IPV4, "IP"),
                (RE_IPV6, "IP"),
                (RE_MAC, "MAC"),
                (RE_HOST, "域名"),
            ):
                if regex.search(result):
                    result = regex.sub(f"[已脱敏{label}]", result)
                    removed.append(label)
            actions.append("mask_entities")

        if opts.coarse_buckets:
            # 先做时间与金额泛化，再做进度语义改写：
            # 否则「上线时间2026-08-12」会被整段吞掉，丢失可用的粗粒度周期
            if RE_DATE.search(result):
                result = RE_DATE.sub(
                    lambda m: self.month_bucket(f"{m.group(1)}-{m.group(2)}-{m.group(3)}"),
                    result,
                )
                removed.append("exact_date")
            if RE_QUARTER.search(result):
                result = RE_QUARTER.sub(lambda m: f"{m.group(1)}Q{m.group(2)}", result)
            if RE_MONEY.search(result):
                result = RE_MONEY.sub(
                    lambda m: self.cost_bucket(self.normalize_amount(m.group(0))), result
                )
                removed.append("exact_amount")
            result, progress_hits = neutralize_progress(result)
            if progress_hits:
                removed.append("progress_term")
                actions.append("rewrite_progress_semantics")
            actions.append("generalize_numbers")

        if len(result) > opts.max_text_len:
            result = result[: opts.max_text_len] + "..."
            actions.append("truncate")
        return SanitizeResult(text=result.strip(), removed=sorted(set(removed)), actions=actions)

    def sanitize_terms(self, terms: Iterable[str]) -> list[str]:
        return [self.sanitize_text(t).text for t in terms if t]

    # ------------------------------------------------------------- projections
    def project_resource(self, resource: Any) -> SafeProjection:
        return SafeProjection(
            project_token=self.tokenize("project", str(getattr(resource, "project_id", ""))),
            platform=getattr(resource, "platform", "") or "unknown",
            kind=getattr(resource, "kind", "") or "other",
            diff_kind="NONE",
            spec_bucket=self.spec_bucket(getattr(resource, "spec", None)),
            cost_bucket=self.cost_bucket(getattr(resource, "monthly_cost_cny", None)),
            period_bucket=self.month_bucket(getattr(resource, "last_seen_date", None)),
            region=_coarse_region(getattr(resource, "region", None)),
            owner_token=(
                None
                if self.settings.SECURITY_REDACT_OWNER
                else self.tokenize("owner", getattr(resource, "owner", None))
            ),
            tags=_safe_tags(getattr(resource, "attributes", {}) or {}),
        )

    def project_diff(self, diff: Any) -> SafeProjection:
        return SafeProjection(
            project_token=self.tokenize("project", str(getattr(diff, "project_id", ""))),
            platform=getattr(diff, "platform", "") or "unknown",
            kind=getattr(diff, "kind", "") or "other",
            diff_kind=getattr(diff, "diff_kind", "") or "UNKNOWN",
            spec_bucket=self.spec_bucket((getattr(diff, "payload", {}) or {}).get("spec")),
            cost_bucket=self.cost_bucket(getattr(diff, "cost_delta_cny", None)),
            period_bucket=self.month_bucket(getattr(diff, "detected_at", None)),
            region=_coarse_region((getattr(diff, "payload", {}) or {}).get("region")),
            owner_token=None,
            tags=_safe_tags(getattr(diff, "payload", {}) or {}),
        )


def bucketize_number(value: float, edges: tuple[float, ...], labels: tuple[str, ...]) -> str:
    if value is None or value <= 0:
        return labels[0]
    for idx, edge in enumerate(edges):
        if value <= edge:
            return labels[idx]
    return labels[-1]


def _coerce_date(value: date | datetime | str | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.fromisoformat(str(value)).date()
    except ValueError:
        return None


def _extract_int(text: str, patterns: tuple[str, ...]) -> int | None:
    import re

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            try:
                return int(match.group(1))
            except (TypeError, ValueError):
                return None
    return None


def _first_number(text: str) -> float | None:
    import re

    match = re.search(r"\d+(?:\.\d+)?", text)
    return float(match.group(0)) if match else None


def _regex_sub_keep(text: str, pattern: str, replacement: str) -> str:
    import re

    return re.sub(pattern, replacement, text, flags=re.IGNORECASE)


def _coarse_region(region: str | None) -> str | None:
    if not region:
        return None
    return region.split("-")[0]


def _safe_tags(attributes: dict) -> list[str]:
    tags = attributes.get("tags") if isinstance(attributes, dict) else None
    if not isinstance(tags, dict):
        return []
    allowed = {"env", "tier", "business_line", "cost_center"}
    return [f"{k}={v}" for k, v in tags.items() if k in allowed and isinstance(v, str)]
