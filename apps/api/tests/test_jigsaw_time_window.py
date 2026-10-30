"""P0-3 回归：jigsaw 时间窗/保留期比较必须在 datetime 空间做。

覆盖 QA 在真实 PG 上发现的精确失败模式：账本 ts 从 PG 读出为本地时区
aware datetime（``str()`` 形如 '2026-10-17 21:33:51+08:00'，空格分隔），
旧实现与 UTC ISO 字符串（'T' 分隔）做字符串比较，导致当日行恒被漏检、
拼图累积判据永不触发；截止日当天的账本还会被误判过期删除。

这些用例双方言（SQLite / PostgreSQL）都必须通过：SQLite 的 TS() 是
ISO 文本，PG 的 TS() 是 timestamptz，规范化后进入同一比较空间。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from conftest import is_pg
from rg_contracts.db.models import RetrievalLedger, new_id, ts
from rg_contracts.security.jigsaw import JigsawGuard, _as_aware, _utc_minus
from sqlalchemy import select

# 同一时刻的三种渲染：UTC ISO 串 / 带 +08:00 偏移的 aware datetime /
# PG 读出后再 str() 的形态（空格分隔 + 本地偏移）
_UTC_ISO = "2026-10-17T13:00:00+00:00"
_AWARE_PLUS8 = datetime(2026, 10, 17, 21, 0, 0, tzinfo=timezone(timedelta(hours=8)))
_PG_STYLE_STR = "2026-10-17 21:00:00+08:00"


def _mk_guard(session, **overrides):
    from rg_contracts.config import Settings

    base = {
        "APP_ENV": "test",
        "AUTH_MODE": "dev",
        "SECRET_KEY": "test-secret-key",
        "SECURITY_TOKEN_SALT": "test-token-salt",
        "SECURITY_JIGSAW_ENABLED": True,
        "SECURITY_JIGSAW_MAX_UNIQUE_CHUNKS": 4,
        "SECURITY_JIGSAW_COMBO_DIMENSIONS": 3,
        "SECURITY_JIGSAW_COVERAGE_LIMIT": 0.35,
        "SECURITY_JIGSAW_MIN_VISIBLE_CHUNKS": 8,
        "SECURITY_JIGSAW_WINDOW_MINUTES": 60,
        "SECURITY_JIGSAW_RETENTION_DAYS": 7,
    }
    base.update(overrides)
    return JigsawGuard(session, Settings(**base))


def _add_ledger(session, actor_id: str, chunk_id: str, ts_value, project_id: str | None = None):
    row = RetrievalLedger(
        id=new_id("rl"),
        ts=ts_value,
        actor_id=actor_id,
        chunk_id=chunk_id,
        document_id=f"doc-{chunk_id}",
        project_id=project_id,
        classification="L2_INTERNAL",
        dimensions={},
        query_hash=None,
        downgraded=False,
    )
    session.add(row)
    return row


# ------------------------------------------------------------ _as_aware 规范化
def test_as_aware_normalizes_offsets_and_separators():
    """不同偏移/分隔符的同一瞬间，规范化后必须相等。

    命名说明：函数由 ``_as_utc`` 更名为 ``_as_aware``（QA 复核 P2）——
    它对 aware 值保留原 tzinfo、不做时区换算，只是把 naive 打上 UTC 标签，
    因此「aware 化」才是准确描述；比较仍按绝对时刻进行。
    """
    normalized = _as_aware(_PG_STYLE_STR)
    assert normalized == datetime(2026, 10, 17, 13, 0, 0, tzinfo=timezone.utc)
    assert normalized == _as_aware(_UTC_ISO)
    assert normalized == _as_aware(_AWARE_PLUS8)
    # naive datetime 按 UTC 假设，避免与 aware 比较抛 TypeError
    assert _as_aware(datetime(2026, 10, 17, 13, 0, 0)) == normalized
    # Z 后缀与空格分隔都可解析
    assert _as_aware("2026-10-17T13:00:00Z") == normalized
    assert _as_aware("2026-10-17 13:00:00+00:00") == normalized
    # 无值/不可解析 -> None（调用方据此跳过，绝不静默丢弃或误判）
    assert _as_aware(None) is None
    assert _as_aware("not-a-timestamp") is None
    assert _as_aware("") is None


def test_as_aware_keeps_original_tzinfo_without_conversion():
    """忠实固化修复后的语义：aware 值原样保留 tzinfo（+08:00 不转 UTC）。

    这是 #命名与行为一致 的锚点：若未来有人把实现改成
    ``.astimezone(timezone.utc)``，本断言会提醒他先确认下游比较逻辑
    仍按绝对时刻工作，而不是悄悄改变返回值的 tzinfo 表示。
    """
    result = _as_aware(_AWARE_PLUS8)
    assert result is not None
    assert result.utcoffset() == timedelta(hours=8)
    assert result == datetime(2026, 10, 17, 13, 0, 0, tzinfo=timezone.utc)


def test_string_comparison_failure_mode_is_documented():
    """固化 QA 发现的失败模式：旧实现的字符串比较会把窗内行误判为窗外。

    '2026-10-17 21:00:00+08:00' 与 '2026-10-17T13:00:00+00:00' 是同一瞬间，
    但空格 0x20 < 'T' 使前者在字符串序上更小 -> 旧代码恒判窗外。
    datetime 比较则方向正确。此断言用于告诫后人不要回到字符串比较。
    """
    assert _PG_STYLE_STR < _UTC_ISO  # 旧实现的错误结论：行在窗口外
    assert _as_aware(_PG_STYLE_STR) >= datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)


# ------------------------------------------------------- _seen_in_window 边界
def test_seen_in_window_boundary_is_inclusive(session):
    """恰在 window_start 的行计入；早 1 微秒不计入（与 SQLite 文本时代一致）。"""
    actor = "u-tw-boundary"
    window_start = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
    _add_ledger(session, actor, "kc_at", ts(window_start))
    _add_ledger(session, actor, "kc_before", ts(window_start - timedelta(microseconds=1)))
    _add_ledger(session, actor, "kc_after", ts(window_start + timedelta(seconds=1)))
    session.flush()

    guard = _mk_guard(session)
    seen = {row.chunk_id for row in guard._seen_in_window(actor, window_start)}
    assert seen == {"kc_at", "kc_after"}


def test_pg_style_local_timestamp_counts_in_utc_window(session):
    """PG 读出形态（本地偏移 aware datetime）在 UTC 窗口内必须被计入。

    这是 P0-3 的核心回归：旧实现在 PG 上此场景返回 0 行。
    """
    actor = "u-tw-pgstyle"
    window_start = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
    # 13:00Z == 21:00+08:00，落在 [12:00Z, +60min) 窗口内
    _add_ledger(session, actor, "kc_in", ts(datetime(2026, 10, 17, 21, 0, 0, tzinfo=timezone(timedelta(hours=8)))))
    # 11:00Z == 19:00+08:00，早于窗口起点
    _add_ledger(session, actor, "kc_out", ts(datetime(2026, 10, 17, 19, 0, 0, tzinfo=timezone(timedelta(hours=8)))))
    session.flush()

    guard = _mk_guard(session)
    seen = {row.chunk_id for row in guard._seen_in_window(actor, window_start)}
    assert seen == {"kc_in"}


# --------------------------------------------------------- record/assess 集成
def _hits(count: int, prefix: str, project_id: str | None = "prj_tw"):
    from types import SimpleNamespace

    return [
        SimpleNamespace(
            chunk_id=f"{prefix}_{i}",
            document_id=f"doc-{prefix}_{i}",
            project_id=project_id,
            platform="aliyun",
            classification="L2_INTERNAL",
            score=0.9,
            display_text=f"治理基线检查通过，无异常变更 {i}",
            metadata={},
        )
        for i in range(count)
    ]


def test_record_then_assess_counts_window_rows(session):
    """窗口内账本进入累积视图：unique_chunks 等于写入条数并按配置触发。"""
    actor = "u-tw-assess"
    guard = _mk_guard(session)
    assert guard.record(actor, _hits(5, "kc_a"), "q1") == 5
    risk = guard.assess(actor, "prj_tw", [], "")
    assert risk.unique_chunks == 5
    assert risk.triggered is True
    assert risk.action == "coarsen"
    assert any("唯一分片" in r for r in risk.reasons)


def test_zero_minute_window_excludes_everything(session, monkeypatch):
    """窗口为 0 时任何已写账本都不计入——证明窗口过滤真实生效。

    时钟用假值钉住（写入后推前 1 秒）：``_seen_in_window`` 的边界含等号
    （>=，见 test_seen_in_window_boundary_is_inclusive），而 Windows 时钟
    粒度下 ``record`` 最后一次 ``ts()`` 与 ``assess`` 的 ``utcnow()`` 可能
    落在同一 tick——用真实时钟时最后一条账本会恰等于 window_start 被计入，
    表现为偶发 ``unique_chunks == 1``（全量跑中实测复现）。推前 1 秒后
    「窗口 0 ⇒ 已写账本一律不计入」的语义被确定性地锁定。
    """
    actor = "u-tw-zero"
    clock = {"now": datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)}

    def fake_utcnow() -> datetime:
        return clock["now"]

    # _utc_minus 在函数体内 from db.base import utcnow；ts() 用 models 模块级引用，
    # 两处都要钉，否则写入与求窗仍各走各的真实时钟。
    monkeypatch.setattr("rg_contracts.db.base.utcnow", fake_utcnow)
    monkeypatch.setattr("rg_contracts.db.models.utcnow", fake_utcnow)

    guard = _mk_guard(session, SECURITY_JIGSAW_WINDOW_MINUTES=0)
    assert guard.record(actor, _hits(3, "kc_z"), "q1") == 3
    clock["now"] += timedelta(seconds=1)
    risk = guard.assess(actor, "prj_tw", [], "")
    assert risk.unique_chunks == 0
    assert risk.triggered is False


# --------------------------------------------------------------- _maybe_prune
def test_prune_keeps_fresh_and_cutoff_day_rows_deletes_genuinely_stale(session, monkeypatch):
    """截止日当天但时刻更新的行不再被误删；真正过期的行仍被清理。"""
    monkeypatch.setattr("random.random", lambda: 0.0)  # 绕过 2% 低频门
    actor = "u-tw-prune"
    retention_minutes = 7 * 24 * 60
    cutoff = _utc_minus(retention_minutes)

    _add_ledger(session, actor, "kc_fresh", ts(_utc_minus(0)))
    # 与 cutoff 同一天但时刻更新：旧字符串比较会误判过期（空格 < 'T'）
    _add_ledger(session, actor, "kc_cutoff_day", ts(cutoff + timedelta(hours=1)))
    _add_ledger(session, actor, "kc_stale", ts(cutoff - timedelta(days=1)))
    session.flush()

    guard = _mk_guard(session)
    guard._maybe_prune(actor)
    session.flush()

    surviving = {
        row.chunk_id
        for row in session.execute(
            select(RetrievalLedger).where(RetrievalLedger.actor_id == actor)
        )
        .scalars()
        .all()
    }
    assert "kc_fresh" in surviving
    assert "kc_cutoff_day" in surviving  # P0-3 误删点：必须保留
    assert "kc_stale" not in surviving  # 真正过期的仍要清理


@pytest.mark.skipif(is_pg(), reason="PG 的 timestamptz 列无法存入不可解析文本，该守护仅 SQLite 可构造")
def test_prune_never_deletes_unparseable_rows(session, monkeypatch):
    """ts 解析不了的行不删（与 P0-1 迁移「不静默丢数据」同一原则）。"""
    monkeypatch.setattr("random.random", lambda: 0.0)
    actor = "u-tw-garbage"
    garbage = _add_ledger(session, actor, "kc_garbage", "not-a-timestamp")
    session.flush()

    guard = _mk_guard(session)
    guard._maybe_prune(actor)
    session.flush()

    row = session.get(RetrievalLedger, garbage.id)
    assert row is not None
