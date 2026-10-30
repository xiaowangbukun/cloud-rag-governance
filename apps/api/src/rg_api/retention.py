"""数据保留策略的执行入口（K8s CronJob / 运维手工触发）。

只删除**口径已确定**的数据，口径未定的一律只统计、不删除：

- 检索账本：超过 ``SECURITY_JIGSAW_RETENTION_DAYS`` 即删（拼图窗口只有 1 小时）；
- OIDC 登录 state：过期即删（一次性凭据，过期后已无法用于任何校验）；
- 运行期滑动窗口计数：超过 ``RETENTION_RUNTIME_STATE_HOURS`` 即删；
- 快照明细：超过 ``RETENTION_SNAPSHOT_DETAIL_MONTHS`` 的月份，每个
  (云账号, 月份) 只保留「最后一份成功快照」的明细，其余删除。保留基线是硬约束：
  ``resource_diff`` 靠 ``snapshot_state`` 重放「当时有哪些资源」，全删就再也无法追溯；
- ``audit_log`` / ``security_event``：**不删**。取证要求下通常只能归档不能删，
  业务口径未定；这里只报告超期行数，供归档方案落地前评估规模。

执行结果写入 ``audit_log``（``action=retention_run``）：清理本身就是一次需要
留痕的系统动作，不能只打日志。

用法::

    python -m rg_api.retention              # 真正删除（表由 API 启动时已建好）
    python -m rg_api.retention --dry-run    # 只统计
    python -m rg_api.retention --bootstrap  # 空库首次使用时先建表/灌种子
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from typing import Iterable

from rg_contracts.audit.service import AuditService
from rg_contracts.config import Settings, get_settings
from rg_contracts.db.base import TimestampCodec, ts_lt, utcnow
from rg_contracts.db.models import (
    AuditLog,
    OidcLoginState,
    RetrievalLedger,
    RuntimeCounter,
    SecurityEvent,
    Snapshot,
    SnapshotState,
)
from rg_contracts.db.session import session_scope
from rg_contracts.logging_setup import get_logger
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

logger = get_logger(__name__)

#: 单批删除行数：避免一条 DELETE 持锁过久
_DELETE_CHUNK = 500


def run_retention(settings: Settings | None = None, dry_run: bool = False) -> dict:
    """执行一次保留策略，返回可序列化的报告。

    报告同时用于审计留痕与运维核对：每个键都给出 ``candidates``（命中条数）
    与 ``deleted``（实际删除条数），dry-run 下后者恒为 0。
    """
    settings = settings or get_settings()
    now = utcnow()
    with session_scope() as session:
        dialect = session.get_bind().dialect.name
        report: dict = {"dry_run": dry_run}
        report["retrieval_ledger"] = _purge_retrieval_ledger(session, settings, now, dialect, dry_run)
        report["oidc_login_state"] = _purge_oidc_states(session, now, dialect, dry_run)
        report["runtime_counter"] = _purge_runtime_counters(session, settings, now, dialect, dry_run)
        report["snapshot_state"] = _prune_snapshot_states(session, settings, now, dialect, dry_run)
        report["audit_log"] = _report_overflow(
            session, AuditLog, AuditLog.ts, settings.RETENTION_AUDIT_DAYS, now, dialect
        )
        report["security_event"] = _report_overflow(
            session, SecurityEvent, SecurityEvent.ts, settings.RETENTION_SECURITY_EVENT_DAYS, now, dialect
        )
        AuditService(session, enabled=settings.SECURITY_AUDIT_ENABLED).record(
            action="retention_run",
            outcome="dry_run" if dry_run else "success",
            metadata=report,
        )
    logger.info("retention_run", extra={"extra_fields": {"dry_run": dry_run}})
    return report


def _purge_retrieval_ledger(
    session: Session,
    settings: Settings,
    now: datetime,
    dialect: str,
    dry_run: bool,
) -> dict:
    days = max(1, settings.SECURITY_JIGSAW_RETENTION_DAYS)
    cutoff = now - timedelta(days=days)
    ids = _ids_older_than(session, RetrievalLedger.id, RetrievalLedger.ts, cutoff, dialect)
    deleted = 0 if dry_run else _delete_ids(session, RetrievalLedger, ids)
    return {"retention_days": days, "candidates": len(ids), "deleted": deleted}


def _purge_oidc_states(session: Session, now: datetime, dialect: str, dry_run: bool) -> dict:
    ids = _ids_older_than(session, OidcLoginState.id, OidcLoginState.expires_at, now, dialect)
    deleted = 0 if dry_run else _delete_ids(session, OidcLoginState, ids)
    return {"candidates": len(ids), "deleted": deleted}


def _purge_runtime_counters(
    session: Session,
    settings: Settings,
    now: datetime,
    dialect: str,
    dry_run: bool,
) -> dict:
    hours = max(1, settings.RETENTION_RUNTIME_STATE_HOURS)
    cutoff = now - timedelta(hours=hours)
    ids = _ids_older_than(session, RuntimeCounter.id, RuntimeCounter.ts, cutoff, dialect)
    deleted = 0 if dry_run else _delete_ids(session, RuntimeCounter, ids)
    return {"retention_hours": hours, "candidates": len(ids), "deleted": deleted}


def _prune_snapshot_states(
    session: Session,
    settings: Settings,
    now: datetime,
    dialect: str,
    dry_run: bool,
) -> dict:
    """按月保留快照明细：每个月只留最后一份成功快照的 state 行。

    为什么必须保留基线：``resource_diff.base_snapshot_id`` 指向历史快照，
    没有 state 行就无法重放「当时有哪些资源」，取证链条会断。
    时间无法解析的行一律不删（不静默丢数据）。
    """
    months = max(1, settings.RETENTION_SNAPSHOT_DETAIL_MONTHS)
    cutoff = _months_ago(now, months)

    snapshots = session.execute(select(Snapshot)).scalars().all()
    baselines: dict[tuple[str, int, int], tuple[datetime, str]] = {}
    for snapshot in snapshots:
        taken_at = TimestampCodec.decode(snapshot.taken_at)
        if taken_at is None or snapshot.status != "success":
            continue
        key = (snapshot.account_id, taken_at.year, taken_at.month)
        current = baselines.get(key)
        if current is None or taken_at > current[0]:
            baselines[key] = (taken_at, snapshot.id)

    baseline_ids = {snapshot_id for _, snapshot_id in baselines.values()}
    rows = session.execute(
        select(SnapshotState.id, SnapshotState.snapshot_id)
        .join(Snapshot, Snapshot.id == SnapshotState.snapshot_id)
        .where(ts_lt(Snapshot.taken_at, cutoff, dialect))
    ).all()
    candidates = [
        state_id
        for state_id, snapshot_id in rows
        if snapshot_id not in baseline_ids
    ]
    deleted = 0 if dry_run else _delete_ids(session, SnapshotState, candidates)
    return {
        "retention_months": months,
        "candidates": len(candidates),
        "deleted": deleted,
        "baseline_snapshots_kept": len(baseline_ids),
    }


def _report_overflow(
    session: Session,
    model,
    timestamp_column,
    target_days: int,
    now: datetime,
    dialect: str,
) -> dict:
    """只统计超期行数，不删除（审计 / 安全事件的口径待业务确认）。"""
    cutoff = now - timedelta(days=max(1, target_days))
    count = int(
        session.execute(
            select(func.count()).select_from(model).where(ts_lt(timestamp_column, cutoff, dialect))
        ).scalar()
        or 0
    )
    return {
        "target_days": target_days,
        "rows_older_than_target": count,
        "deleted": 0,
        "note": "policy_pending：取证场景通常只能归档不能删",
    }


def _ids_older_than(session: Session, id_column, timestamp_column, cutoff: datetime, dialect: str) -> list[str]:
    return list(
        session.execute(select(id_column).where(ts_lt(timestamp_column, cutoff, dialect))).scalars().all()
    )


def _delete_ids(session: Session, model, ids: Iterable[str]) -> int:
    values = list(ids)
    deleted = 0
    for start in range(0, len(values), _DELETE_CHUNK):
        chunk = values[start : start + _DELETE_CHUNK]
        result = session.execute(delete(model).where(model.id.in_(chunk)))
        deleted += int(result.rowcount or 0)
    return deleted


def _months_ago(now: datetime, months: int) -> datetime:
    """返回 months 个月前的**月初**（UTC），作为「早于该月」的切分点。"""
    year, month = now.year, now.month - months
    while month <= 0:
        month += 12
        year -= 1
    return datetime(year, month, 1, tzinfo=now.tzinfo)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="执行数据保留策略（默认真删；--dry-run 只统计）"
    )
    parser.add_argument("--dry-run", action="store_true", help="只统计候选行，不删除任何数据")
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="执行前先跑启动引导（建表/种子）。默认关闭：清理任务不该顺带建种子数据",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    if args.bootstrap:
        from rg_api.startup import bootstrap

        bootstrap(settings)
    report = run_retention(settings, dry_run=args.dry_run)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - 由 K8s CronJob 调用
    raise SystemExit(main())
