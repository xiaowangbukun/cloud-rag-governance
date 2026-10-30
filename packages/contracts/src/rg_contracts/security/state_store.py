"""跨副本运行期状态：滑动窗口计数的落库实现。

为什么不用进程内计数、也不用 Redis：

- 进程内：``replicas: 2`` + HPA 下阈值按副本数放大，登录锁定与查询预算
  都是安全控制，不能随副本数漂移；
- Redis：多一个必须在内网自建、单独做高可用与凭证管理的组件，而这里的
  写入量只有每秒个位数，PostgreSQL 完全够用，且已有备份与监控面。

接口刻意做窄（record / count / distinct / purge），换成 Redis 时只需替换
本模块，调用方（预算、登录锁定、保留任务）不动。

**写入一律用独立会话并立即提交**：预算与登录失败都发生在「紧接着抛异常、
业务会话必然回滚」的路径上；若复用业务会话，计数会随回滚一起消失，攻击者
只要让请求失败就能把窗口清零。
"""

from __future__ import annotations

import random
import time
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import delete, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from rg_contracts.db.base import ts_gte, ts_lt, utcnow
from rg_contracts.db.models import RuntimeCounter, new_id, ts
from rg_contracts.db.session import get_session_factory
from rg_contracts.logging_setup import get_logger

logger = get_logger(__name__)

#: 计数域常量：集中定义，避免调用方拼错字符串后静默失效
SCOPE_RETRIEVAL = "retrieval"
SCOPE_RETRIEVAL_PROJECT = "retrieval_project"
SCOPE_RETRIEVAL_BLOCKED = "retrieval_blocked"
SCOPE_EXPORT = "export"
SCOPE_LOGIN_FAILURE = "login_failure"

#: 写入侧概率清理：与拼图账本同策略（低频、非阻塞），兜底两次定时任务之间
#: 被刷爆的情况。1/50 的写入会顺带清理一次。
_PRUNE_PROBABILITY = 0.02
#: 单批删除上限，避免一次 DELETE 长时间持锁
_PRUNE_BATCH = 500
#: 兜底保留期：远大于任何业务窗口（最长 1 小时），只用于控制表体积
_DEFAULT_PRUNE_HOURS = 24

#: SQLite 单写者模型的锁错误文案（与审计独立事务的判定保持一致）
_SQLITE_LOCK_MARKERS = ("database is locked", "database table is locked")


class RuntimeStateStore:
    """滑动窗口计数的存储门面。

    ``session_factory`` 可注入（测试用固定会话工厂）；默认取全局工厂。
    """

    def __init__(self, session_factory: sessionmaker[Session] | None = None) -> None:
        self._factory = session_factory

    def _session(self) -> Session:
        factory = self._factory or get_session_factory()
        return factory()

    # ------------------------------------------------------------------ write

    def record(
        self,
        scope: str,
        subject: str,
        value: str | None = None,
        at: datetime | None = None,
    ) -> None:
        """追加一条窗口事件并立即提交（独立事务，不参与调用方事务）。"""
        row = RuntimeCounter(
            id=new_id("rc"),
            scope=scope[:32],
            subject=str(subject)[:190],
            value=str(value)[:190] if value else None,
            ts=ts(at),
        )
        self._write(row)
        self._maybe_prune()

    def _write(self, row: RuntimeCounter) -> None:
        attempts = 2
        for attempt in range(attempts):
            session = self._session()
            try:
                session.add(row)
                session.commit()
                return
            except OperationalError as exc:
                session.rollback()
                # SQLite 单写者：业务会话可能正持写锁，稍候重试一次即可；
                # PG 的 MVCC 不需要这层。重试仍失败就上抛（计数是安全控制，
                # 宁可让请求失败，也不静默放行）。
                if attempt + 1 >= attempts or not _is_lock_error(exc):
                    raise
                time.sleep(0.05)
            finally:
                session.close()

    # ------------------------------------------------------------------- read

    def count(
        self,
        scope: str,
        subject: str,
        window_seconds: float,
        now: datetime | None = None,
    ) -> int:
        """窗口内的事件数（滑动窗口，含当前时刻）。"""
        cutoff = (now or utcnow()) - timedelta(seconds=max(0, window_seconds))
        session = self._session()
        try:
            stmt = select(func.count()).select_from(RuntimeCounter).where(
                RuntimeCounter.scope == scope,
                RuntimeCounter.subject == str(subject)[:190],
                ts_gte(RuntimeCounter.ts, cutoff, _dialect(session)),
            )
            return int(session.execute(stmt).scalar() or 0)
        finally:
            session.close()

    def distinct(
        self,
        scope: str,
        subject: str,
        window_seconds: float,
        now: datetime | None = None,
    ) -> int:
        """窗口内 ``value`` 的去重数量（如短时间触及了多少个项目）。"""
        cutoff = (now or utcnow()) - timedelta(seconds=max(0, window_seconds))
        session = self._session()
        try:
            stmt = (
                select(RuntimeCounter.value)
                .where(
                    RuntimeCounter.scope == scope,
                    RuntimeCounter.subject == str(subject)[:190],
                    RuntimeCounter.value.is_not(None),
                    ts_gte(RuntimeCounter.ts, cutoff, _dialect(session)),
                )
                .distinct()
            )
            return len([value for value in session.execute(stmt).scalars().all() if value])
        finally:
            session.close()

    # ------------------------------------------------------------------ purge

    def purge_subject(self, scope: str, subject: str) -> int:
        """清空某主体在某计数域下的全部事件（测试重置 / 登录成功后清零）。"""
        session = self._session()
        try:
            result = session.execute(
                delete(RuntimeCounter).where(
                    RuntimeCounter.scope == scope,
                    RuntimeCounter.subject == str(subject)[:190],
                )
            )
            session.commit()
            return int(result.rowcount or 0)
        finally:
            session.close()

    def purge(
        self,
        scopes: Iterable[str] | None = None,
        older_than: datetime | None = None,
        limit: int | None = None,
    ) -> int:
        """按计数域与时间窗批量删除，返回删除行数。

        ``older_than=None`` 表示删除该域全部行（仅用于测试/运维重置）。
        ``limit`` 用于单次清理批次上限；到上限即停，由下一次调用继续。
        """
        scope_list = [scope for scope in (scopes or ()) if scope]
        session = self._session()
        try:
            stmt = select(RuntimeCounter.id)
            if scope_list:
                stmt = stmt.where(RuntimeCounter.scope.in_(scope_list))
            if older_than is not None:
                stmt = stmt.where(ts_lt(RuntimeCounter.ts, older_than, _dialect(session)))
            stmt = stmt.limit(limit or _PRUNE_BATCH)
            ids = list(session.execute(stmt).scalars().all())
            if not ids:
                return 0
            result = session.execute(delete(RuntimeCounter).where(RuntimeCounter.id.in_(ids)))
            session.commit()
            return int(result.rowcount or 0)
        finally:
            session.close()

    def _maybe_prune(self) -> None:
        if random.random() > _PRUNE_PROBABILITY:
            return
        try:
            removed = self.purge(older_than=utcnow() - timedelta(hours=_DEFAULT_PRUNE_HOURS))
            if removed:
                logger.debug(
                    "runtime_counter_pruned",
                    extra={"extra_fields": {"removed": removed}},
                )
        except Exception:  # noqa: BLE001
            # 清理是纯兜底动作，失败不得影响正在进行的计数写入
            logger.warning("runtime_counter_prune_failed")


def _dialect(session: Session) -> str:
    """时间戳比较所需的方言名（唯一来源：当前会话绑定的引擎）。"""
    return session.get_bind().dialect.name


def _is_lock_error(exc: BaseException) -> bool:
    """保守判定 SQLite 写锁竞争；拿不准返回 False。"""
    message = str(exc).lower()
    return any(marker in message for marker in _SQLITE_LOCK_MARKERS)


__all__ = [
    "SCOPE_EXPORT",
    "SCOPE_LOGIN_FAILURE",
    "SCOPE_RETRIEVAL",
    "SCOPE_RETRIEVAL_BLOCKED",
    "SCOPE_RETRIEVAL_PROJECT",
    "RuntimeStateStore",
]
