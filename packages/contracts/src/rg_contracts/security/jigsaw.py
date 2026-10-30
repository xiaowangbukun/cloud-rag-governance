"""拼图攻击（mosaic / salami-slicing）防护。

威胁模型：攻击者不越权，只用合法权限反复发起小范围检索，把
「A 项目的成本 + B 项目的拓扑 + C 项目的负责人」等碎片拼出高于授权密级的全貌。
单次查询都合规，因此单点检测（注入、枚举意图、预算）拦不住，必须做**跨查询累积视图**。

三道防线：
1. 检索侧累积覆盖（coverage）：同一主体在时间窗口内见过的唯一分片 / 可见分片数
2. 输出侧重组检测（reassembly）：跨查询敏感维度共现，达到组合数即判定「可拼出画像」
3. 入库侧切片规避（slicing）：先净化再切片，并对「敏感值被切片切断」做扫描

处置（按配置）：coarsen=降密级返回 / deny=拒绝 / none=仅记录。
静默模式下风险只在审计留痕，响应体不回显，避免攻击者据此调整策略。
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from rg_contracts.config import Settings, get_settings
from rg_contracts.db.models import KnowledgeChunk, RetrievalLedger, new_id, ts
from rg_contracts.logging_setup import get_logger
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
    RE_PERCENT,
    RE_PROJECT_CODE,
    RE_SECRET_KEY,
)
from rg_contracts.security.sanitize import SanitizeOptions, Sanitizer

logger = get_logger(__name__)

# 敏感维度：一个维度代表一类可被拼合的事实。
# 单维度泄露不致命，但维度数达到阈值就意味着攻击者手里已有一张可拼装的画像。
DIMENSION_RULES: tuple[tuple[str, tuple[object, ...], str], ...] = (
    ("identity", (RE_EMAIL, RE_CN_MOBILE, RE_ID_CARD, RE_PROJECT_CODE), "high"),
    ("credential", (RE_ACCESS_KEY, RE_SECRET_KEY), "critical"),
    ("timing", (RE_DATE,), "medium"),
    ("scale", (RE_MONEY, RE_PERCENT), "medium"),
    ("location", (RE_IPV4, RE_IPV6, RE_MAC, RE_HOST), "low"),
)

DIMENSION_WEIGHT: dict[str, float] = {
    "identity": 1.0,
    "credential": 1.5,
    "timing": 0.8,
    "scale": 0.8,
    "location": 0.5,
}

RISK_NONE = "none"
RISK_WATCH = "watch"
RISK_ELEVATED = "elevated"
RISK_CRITICAL = "critical"

_RISK_ORDER = {RISK_NONE: 0, RISK_WATCH: 1, RISK_ELEVATED: 2, RISK_CRITICAL: 3}


@dataclass(frozen=True)
class DimensionHit:
    """文本中的敏感维度共现情况。"""

    dimensions: dict[str, int]

    @property
    def count(self) -> int:
        return len([k for k, v in self.dimensions.items() if v > 0])

    @property
    def weight(self) -> float:
        return sum(DIMENSION_WEIGHT.get(k, 0.5) for k, v in self.dimensions.items() if v > 0)

    def as_dict(self) -> dict:
        return {k: v for k, v in self.dimensions.items() if v > 0}


def detect_dimensions(text: str) -> DimensionHit:
    """统计文本命中的敏感维度。比 detect_sensitive_values 更粗，但更适合做组合判定。"""
    counts: dict[str, int] = {}
    for name, patterns, _severity in DIMENSION_RULES:
        total = 0
        for pattern in patterns:
            total += len(pattern.findall(text or ""))
        counts[name] = total
    return DimensionHit(counts)


@dataclass(frozen=True)
class JigsawRisk:
    """一次检索触发的拼图风险评估结果。"""

    risk: str = RISK_NONE
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    coverage: float = 0.0
    unique_chunks: int = 0
    visible_chunks: int = 0
    dimensions: dict = field(default_factory=dict)
    dimension_count: int = 0
    action: str = "none"

    @property
    def triggered(self) -> bool:
        return _RISK_ORDER.get(self.risk, 0) >= _RISK_ORDER[RISK_ELEVATED]

    def as_dict(self) -> dict:
        return {
            "risk": self.risk,
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "coverage": round(self.coverage, 3),
            "unique_chunks": self.unique_chunks,
            "visible_chunks": self.visible_chunks,
            "dimensions": self.dimensions,
            "action": self.action,
        }


@dataclass
class SlicingScan:
    """入库侧切片规避扫描结果。"""

    split_evasion: bool = False
    cross_chunk_reassembly: bool = False
    doc_dimensions: dict = field(default_factory=dict)
    max_chunk_dimensions: int = 0
    split_values: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def risky(self) -> bool:
        return self.split_evasion or self.cross_chunk_reassembly

    def as_dict(self) -> dict:
        return {
            "split_evasion": self.split_evasion,
            "cross_chunk_reassembly": self.cross_chunk_reassembly,
            "doc_dimensions": self.doc_dimensions,
            "max_chunk_dimensions": self.max_chunk_dimensions,
            "split_values": self.split_values[:10],
            "reasons": self.reasons,
        }


class JigsawGuard:
    """跨查询累积视图：账本 + 覆盖度 + 维度共现 + 降密级处置。

    session 可为 None（仅用于入库侧切片扫描，该路径不落账本）。
    """

    def __init__(self, session: Session | None = None, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self._sanitizer = Sanitizer(self.settings)

    # --------------------------------------------------------------- 账本写入
    def record(
        self,
        actor_id: str,
        hits: Sequence,
        query: str = "",
        downgraded: bool = False,
    ) -> int:
        """把本次命中的分片写入检索账本（跨请求、跨副本可见）。"""
        if not hits or not actor_id or self.session is None:
            return 0
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16] if query else None
        written = 0
        for hit in hits:
            chunk_id = getattr(hit, "chunk_id", None) or ""
            if not chunk_id:
                continue
            dims = detect_dimensions(getattr(hit, "display_text", "") or "")
            exists = self.session.execute(
                select(RetrievalLedger.id).where(
                    RetrievalLedger.actor_id == actor_id,
                    RetrievalLedger.chunk_id == chunk_id,
                )
            ).scalar_one_or_none()
            if exists:
                continue
            self.session.add(
                RetrievalLedger(
                    id=new_id("rl"),
                    ts=ts(),
                    actor_id=actor_id,
                    chunk_id=chunk_id,
                    document_id=getattr(hit, "document_id", None),
                    project_id=getattr(hit, "project_id", None),
                    classification=getattr(hit, "classification", None),
                    dimensions=dims.as_dict(),
                    query_hash=query_hash,
                    downgraded=downgraded,
                )
            )
            written += 1
        self._maybe_prune(actor_id)
        # sessionmaker 配置为 autoflush=False，必须显式 flush，
        # 否则同一事务内的幂等查询与 assess 的累积视图都看不到刚写入的账本
        if self.session is not None:
            self.session.flush()
        return written

    # ------------------------------------------------------------------ 评估
    def assess(
        self,
        actor_id: str,
        project_id: str | None,
        hits: Sequence,
        query: str = "",
    ) -> JigsawRisk:
        """基于窗口内已见分片 + 本次命中，评估拼图风险。"""
        cfg = self.settings
        if not cfg.SECURITY_JIGSAW_ENABLED or not actor_id:
            return JigsawRisk()

        window_start = _utc_minus(cfg.SECURITY_JIGSAW_WINDOW_MINUTES)
        # 同一事务内先前写入的账本需要 flush 后才能进入本次查询结果
        if self.session is not None:
            self.session.flush()
        seen = self._seen_in_window(actor_id, window_start)
        unique_chunks = len({row.chunk_id for row in seen})
        dimensions = _merge_dimensions([row.dimensions for row in seen])
        for hit in hits:
            dimensions = _merge_dimensions(
                [dimensions, detect_dimensions(getattr(hit, "display_text", "") or "").dimensions]
            )
        dimension_count = len([k for k, v in dimensions.items() if v > 0])

        coverage, visible = self._coverage(actor_id, project_id, window_start)
        reasons: list[str] = []

        risk = RISK_NONE
        if unique_chunks >= cfg.SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS:
            risk = RISK_ELEVATED
            reasons.append(
                f"窗口内已见唯一分片 {unique_chunks} 达到上限 {cfg.SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS}"
            )
        elif unique_chunks >= cfg.SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS * 0.7:
            risk = RISK_WATCH
            reasons.append(f"窗口内已见唯一分片 {unique_chunks}，接近上限")

        # 小知识库可见分片太少，覆盖率天然偏高，不启用覆盖率判定避免误报
        coverage_active = visible >= cfg.SECURITY_JIGSAW_MIN_VISIBLE_CHUNKS
        if coverage_active and coverage >= cfg.SECURITY_JIGSAW_COVERAGE_LIMIT:
            risk = _max_risk(risk, RISK_ELEVATED)
            reasons.append(f"单项目分片覆盖率 {coverage:.0%} 超过上限 {cfg.SECURITY_JIGSAW_COVERAGE_LIMIT:.0%}")
        elif coverage_active and coverage >= cfg.SECURITY_JIGSAW_COVERAGE_LIMIT * 0.7 and risk == RISK_NONE:
            risk = RISK_WATCH
            reasons.append(f"单项目分片覆盖率 {coverage:.0%}，接近上限")

        if dimension_count >= cfg.SECURITY_JIGSAW_COMBO_DIMENSIONS:
            risk = _max_risk(risk, RISK_ELEVATED)
            reasons.append(
                f"跨查询敏感维度共现 {dimension_count} 种（{sorted(dimensions)}），"
                f"达到可重组阈值 {cfg.SECURITY_JIGSAW_COMBO_DIMENSIONS}"
            )
        elif dimension_count == cfg.SECURITY_JIGSAW_COMBO_DIMENSIONS - 1 and risk == RISK_NONE:
            risk = RISK_WATCH
            reasons.append(f"敏感维度共现 {dimension_count} 种，逼近可重组阈值")

        action = "none"
        if risk in (RISK_ELEVATED, RISK_CRITICAL):
            action = cfg.SECURITY_JIGSAW_ACTION
        return JigsawRisk(
            risk=risk,
            score=min(1.0, unique_chunks / max(1, cfg.SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS) * 0.5
                      + coverage / max(cfg.SECURITY_JIGSAW_COVERAGE_LIMIT, 0.01) * 0.3
                      + dimension_count / max(cfg.SECURITY_JIGSAW_COMBO_DIMENSIONS, 1) * 0.4),
            reasons=reasons,
            coverage=coverage,
            unique_chunks=unique_chunks,
            visible_chunks=visible,
            dimensions={k: v for k, v in dimensions.items() if v > 0},
            dimension_count=dimension_count,
            action=action,
        )

    # ------------------------------------------------------------- 降密级返回
    def coarsen(self, hits: Sequence) -> list[dict]:
        """降密级返回：只保留少量片段，且文本降级为治理语义摘要（去实体 + 区间化）。"""
        limit = max(1, self.settings.SECURITY_JIGSAW_COARSEN_TOP_K)
        out: list[dict] = []
        for hit in list(hits)[:limit]:
            raw = getattr(hit, "display_text", "") or ""
            summary = self._sanitizer.sanitize_text(raw).text
            summary = _truncate(summary, 120)
            out.append(
                {
                    "chunk_id": getattr(hit, "chunk_id", ""),
                    "document_id": getattr(hit, "document_id", ""),
                    "project_id": getattr(hit, "project_id", None),
                    "classification": getattr(hit, "classification", None),
                    "score": round(float(getattr(hit, "score", 0.0)), 4),
                    "text": summary,
                    "coarsened": True,
                    "metadata": {
                        **(getattr(hit, "metadata", {}) or {}),
                        "jigsaw_coarsened": True,
                        "original_length": len(raw),
                    },
                }
            )
        return out

    # ------------------------------------------------------------- 入库侧扫描
    def scan_ingest(self, content: str, chunk_texts: Sequence[str]) -> SlicingScan:
        """切片规避扫描：检测「先切片后净化」导致的敏感值切断与跨分片重组。"""
        cfg = self.settings
        if not cfg.SECURITY_JIGSAW_ENABLED:
            return SlicingScan()

        doc_dims = detect_dimensions(content)
        chunk_dims = [detect_dimensions(text).dimensions for text in chunk_texts]
        max_chunk_dimensions = max(
            (len([k for k, v in d.items() if v > 0]) for d in chunk_dims), default=0
        )
        scan = SlicingScan(
            doc_dimensions=doc_dims.as_dict(),
            max_chunk_dimensions=max_chunk_dimensions,
        )

        # 1) 敏感值被切片切断：全文能匹配到的值，在任何单个分片里都不完整出现
        for pattern, label in (
            (RE_CN_MOBILE, "手机号"),
            (RE_ID_CARD, "证件号"),
            (RE_EMAIL, "邮箱"),
            (RE_IPV4, "IP"),
            (RE_ACCESS_KEY, "访问密钥"),
        ):
            for value in pattern.findall(content or ""):
                if not any(value in (text or "") for text in chunk_texts):
                    scan.split_values.append(f"{label}:{value[:3]}***")
                    scan.split_evasion = True
        if scan.split_evasion:
            scan.reasons.append(
                f"{len(scan.split_values)} 个敏感值被切片切断，单分片无法识别，"
                "须改为先净化再切片"
            )

        # 2) 跨分片重组：文档整体维度数高于任一单分片，说明必须拼起来才构成敏感画像
        doc_dimension_count = doc_dims.count
        if doc_dimension_count >= cfg.SECURITY_JIGSAW_COMBO_DIMENSIONS > max_chunk_dimensions:
            scan.cross_chunk_reassembly = True
            scan.reasons.append(
                f"文档敏感维度 {doc_dimension_count} 种高于单分片最大 {max_chunk_dimensions} 种，"
                "存在跨分片重组风险，已按最高维度处置"
            )
        return scan

    # ------------------------------------------------------------------ 内部
    def _seen_in_window(self, actor_id: str, window_start: datetime) -> list[RetrievalLedger]:
        """取窗口内账本（window_start 为 aware UTC datetime）。

        SQL 侧仍只按 actor 取最近若干条（desc + limit），时间过滤在应用层做，
        且**永远在 datetime 空间比较**：TS() 列在 SQLite 是 TEXT（ISO 字符串），
        在 PG 是 timestamptz（aware datetime），把时间条件下推 SQL 会绑定失败，
        而把两侧都规范成 datetime 再比较则双方言正确。

        历史事故（P0-3）：旧实现用 ``str(row.ts) >= window_start`` 做字符串比较。
        PG 读出的 timestamptz 是本地时区 aware datetime，``str()`` 形如
        '2026-10-17 21:33:51+08:00'（空格分隔），而 window_start 是 UTC ISO
        '2026-10-17T12:33:51+00:00'（T 分隔）——空格 0x20 < 'T' 使当日行恒被
        漏检，安全判据永不触发；即便统一分隔符，同一时刻的本地串与 UTC 串
        方向也会翻转。因此必须解析为 datetime 对象后比较，杜绝字符串比较。
        """
        rows = (
            self.session.execute(
                select(RetrievalLedger)
                .where(RetrievalLedger.actor_id == actor_id)
                .order_by(RetrievalLedger.ts.desc())
                .limit(300)
            )
            .scalars()
            .all()
        )
        # 含边界（>=）：与 SQLite 文本时代的语义一致，作为回归基准
        return [
            row
            for row in rows
            if (row_dt := _as_aware(row.ts)) is not None and row_dt >= window_start
        ]

    def _coverage(
        self, actor_id: str, project_id: str | None, window_start: datetime
    ) -> tuple[float, int]:
        """窗口内该主体在指定项目（或全局）的可见分片覆盖率。"""
        stmt = select(func.count()).select_from(KnowledgeChunk)
        if project_id:
            stmt = stmt.where(KnowledgeChunk.project_id == project_id)
        else:
            stmt = stmt.where(KnowledgeChunk.project_id.is_(None))
        visible = int(self.session.execute(stmt).scalar() or 0)
        if visible <= 0:
            return 0.0, 0
        seen_rows = self._seen_in_window(actor_id, window_start)
        seen = len(
            {
                row.chunk_id
                for row in seen_rows
                if (row.project_id or None) == (project_id or None)
            }
        )
        return min(1.0, seen / visible), visible

    def _maybe_prune(self, actor_id: str) -> None:
        """低频清理过期账本，防止表无限增长。

        时间比较同样在 datetime 空间做（见 _seen_in_window 的 P0-3 记录）：
        ts 解析不了的行不删——与 P0-1 迁移「不静默丢数据」同一原则。
        """
        import random

        if random.random() > 0.02:
            return
        cutoff = _utc_minus(self.settings.SECURITY_JIGSAW_RETENTION_DAYS * 24 * 60)
        rows = (
            self.session.execute(
                select(RetrievalLedger.id, RetrievalLedger.ts).where(
                    RetrievalLedger.actor_id == actor_id
                )
            )
            .all()
        )
        stale = [
            row[0]
            for row in rows
            if (row_dt := _as_aware(row[1])) is not None and row_dt < cutoff
        ]
        if stale:
            self.session.execute(
                delete(RetrievalLedger).where(RetrievalLedger.id.in_(stale))
            )
        logger.debug("jigsaw ledger pruned", extra={"extra_fields": {"actor": actor_id}})


def sanitize_before_chunking(
    content: str,
    settings: Settings | None = None,
    options: SanitizeOptions | None = None,
) -> tuple[str, list[str]]:
    """先净化再切片：从根上消除「切片切断敏感值」的规避面。

    旧实现是先 split 再逐片 sanitize，跨片边界的敏感值（手机号、IP）会同时
    在两个分片里都不完整，从而绕过检测。此函数给出修正后的顺序。

    注意 max_text_len：入库场景必须显式放大，否则 sanitize_text 默认的 1200 字
    截断会把长文档的后半段静默丢弃（既不落库也不向量化）。
    """
    sanitizer = Sanitizer(settings or get_settings())
    result = sanitizer.sanitize_text(content, options)
    return result.text, result.removed


def _utc_minus(minutes: float) -> datetime:
    """当前 UTC 时刻前移 minutes 分钟，返回 aware UTC datetime。

    时间窗口/保留期的起点一律用 datetime 表示（P0-3）：旧实现返回 ISO
    字符串并与 ``str(row.ts)`` 做字符串比较，在 PG 上因分隔符与时区渲染
    差异双重失配，详见 _seen_in_window 的 docstring。
    """
    from rg_contracts.db.base import utcnow

    return utcnow() - timedelta(minutes=max(0, minutes))


def _as_aware(value: str | datetime | None) -> datetime | None:
    """把账本时间值规范为可比较的 aware datetime（无值时返回 None）。

    **不做时区换算**，只做"aware 化"——这正是函数名从 ``_as_utc`` 改名为
    ``_as_aware`` 的原因：它给 naive 值打 UTC 标签，但 aware 值保留原 tzinfo
    （例如 +08:00 不会转成 UTC）。对时间窗比较而言这是充分的：aware
    datetime 之间的比较按绝对时刻进行，跨时区无需显式换算。

    - ``datetime``：naive 的按 UTC 假设，aware 的原样保留
    - ``str``：``datetime.fromisoformat`` 解析后同上；解析失败返回 None
    - ``None``：返回 None

    不复用 ``TimestampCodec.decode``：它对 naive 值不做 UTC 假设，直接与
    aware 的 window_start 比较会抛 ``TypeError``；且它属于 TS() 方言层
    共享编解码，不应为本场景修改其语义。SQLite 的 TS() 文本与 PG 的
    timestamptz 读出值（aware datetime）在这里被规范到同一比较空间。
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _merge_dimensions(items: Iterable[dict | None]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for item in items:
        if not item:
            continue
        for key, value in item.items():
            try:
                merged[key] = merged.get(key, 0) + int(value)
            except (TypeError, ValueError):
                continue
    return merged


def _max_risk(current: str, candidate: str) -> str:
    return candidate if _RISK_ORDER.get(candidate, 0) > _RISK_ORDER.get(current, 0) else current


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def lower_level(level: str | None) -> str:
    """把密级下调一档（用于降密级返回时的授权收紧）。"""
    from rg_contracts.enums import Classification

    ordered = [lv.value for lv in Classification]
    idx = ordered.index(level) if level in ordered else 0
    if idx <= 0:
        return ordered[0]
    return ordered[idx - 1]


__all__ = [
    "DimensionHit",
    "JigsawGuard",
    "JigsawRisk",
    "SlicingScan",
    "detect_dimensions",
    "lower_level",
    "sanitize_before_chunking",
]
