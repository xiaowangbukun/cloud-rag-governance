"""查询预算与防枚举：阻止通过多次小查询拼出项目全貌。"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from threading import Lock
from typing import Deque

from rg_contracts.config import Settings, get_settings
from rg_contracts.db.base import utcnow
from rg_contracts.security.state_store import (
    SCOPE_EXPORT,
    SCOPE_RETRIEVAL,
    SCOPE_RETRIEVAL_BLOCKED,
    SCOPE_RETRIEVAL_PROJECT,
    RuntimeStateStore,
)

#: 小时统计窗口（检索 / 导出预算）
HOUR_SECONDS = 3600
#: 跨项目探测的短窗口
PROBE_WINDOW_SECONDS = 600
#: 短窗口内触及的不同项目数上限
DISTINCT_PROJECT_LIMIT = 12
#: 每小时导出次数上限
EXPORT_WINDOW_LIMIT = 10


def _raise_blocked(ok: bool, reason: str, details: dict) -> None:
    """把判定结果翻译成异常；两种预算实现共用，保证行为一致。"""
    if ok:
        return
    from rg_contracts.errors import EnumerationDetectedError, RateLimitedError

    if reason == "hourly_budget_exceeded":
        raise RateLimitedError("检索查询超出小时预算", **details)
    raise EnumerationDetectedError("检测到跨项目批量探测", **details)


@dataclass
class BudgetCounters:
    retrievals: Deque[float] = field(default_factory=deque)
    distinct_projects: Deque[tuple[float, str]] = field(default_factory=deque)
    exports: Deque[float] = field(default_factory=deque)
    blocked: int = 0


class QueryBudget:
    """**进程内**滑动窗口。

    仅用于纯逻辑单测、离线演示与「不想落库」的嵌入式调用。多副本部署下
    路由层走 :class:`DbQueryBudget`（``get_budget()`` 的默认返回值），
    否则预算会按副本数放大。
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._lock = Lock()
        self._counters: dict[str, BudgetCounters] = {}

    def _counters_for(self, actor: str) -> BudgetCounters:
        if actor not in self._counters:
            self._counters[actor] = BudgetCounters()
        return self._counters[actor]

    @staticmethod
    def _trim(window: Deque[float], now: float, window_seconds: float) -> None:
        while window and now - window[0] > window_seconds:
            window.popleft()

    @staticmethod
    def _trim_pairs(window: Deque[tuple[float, str]], now: float, window_seconds: float) -> None:
        while window and now - window[0][0] > window_seconds:
            window.popleft()

    def check_retrieval(
        self,
        actor: str,
        project_ids: Sequence[str] = (),
        unrestricted: bool = False,
    ) -> tuple[bool, str, dict]:
        """记一次检索并判定是否超预算。

        ``project_ids`` 必须是**真实项目 ID**：此前的实现用
        ``range(project_count)`` 造合成 ID，同一项目连续查 20 次也只记到同一个
        合成键，``cross_project_probing`` 永远不可能触发（真正的跨项目探测反而
        不受限）；而一次覆盖 13 个项目的查询却直接 429（治理管理员被误伤）。

        跨项目探测只在两种情况记账：
        - 主体**没有全局范围**（项目受限用户才需要防枚举；全局角色跨项目查询
          是其职责，由小时预算兜底）；
        - 本次请求收敛到**单个项目**（一次查询覆盖多个授权项目属于正常用法，
          记进去会把「合法的一次性多项目检索」误判成探测）。
        """
        now = time.time()
        with self._lock:
            counters = self._counters_for(actor)
            self._trim(counters.retrievals, now, HOUR_SECONDS)
            counters.retrievals.append(now)
            if len(counters.retrievals) > self.settings.SECURITY_QUERY_BUDGET_PER_HOUR:
                counters.blocked += 1
                return False, "hourly_budget_exceeded", {
                    "count": len(counters.retrievals),
                    "limit": self.settings.SECURITY_QUERY_BUDGET_PER_HOUR,
                }

            # 短时间跨多项目探测 = 拼图信号（只统计真实、且收敛到单项目的检索）
            self._trim_pairs(counters.distinct_projects, now, PROBE_WINDOW_SECONDS)
            targets = {pid for pid in project_ids if pid}
            if not unrestricted and len(targets) == 1:
                counters.distinct_projects.append((now, next(iter(targets))))
            distinct = len({pid for _, pid in counters.distinct_projects})
            if distinct > DISTINCT_PROJECT_LIMIT:
                counters.blocked += 1
                return False, "cross_project_probing", {"distinct": distinct}

        return True, "ok", {"count": len(counters.retrievals)}

    def enforce_retrieval(
        self,
        actor: str,
        project_ids: Sequence[str] = (),
        unrestricted: bool = False,
    ) -> None:
        ok, reason, details = self.check_retrieval(actor, project_ids, unrestricted)
        _raise_blocked(ok, reason, details)

    def check_export(self, actor: str, row_count: int) -> tuple[bool, str]:
        now = time.time()
        with self._lock:
            counters = self._counters_for(actor)
            self._trim(counters.exports, now, HOUR_SECONDS)
            total = sum(1 for _ in counters.exports)
            if row_count > self.settings.SECURITY_EXPORT_LIMIT:
                return False, "batch_too_large"
            if total >= EXPORT_WINDOW_LIMIT:
                return False, "export_budget_exceeded"
            counters.exports.append(now)
        return True, "ok"

    def snapshot(self, actor: str) -> dict:
        with self._lock:
            counters = self._counters_for(actor)
            return {
                "retrievals_last_hour": len(counters.retrievals),
                "exports_last_hour": len(counters.exports),
                "blocked": counters.blocked,
            }

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


class DbQueryBudget:
    """**落库**的滑动窗口预算：多副本共享同一窗口。

    与 :class:`QueryBudget` 判定语义逐条对齐（窗口、上限、记账条件），
    差异只在存储：每次判定先写一条事件（独立事务、立即提交），再按窗口
    计数。写入独立提交是必须的——预算超限会抛异常，业务会话随之回滚，
    复用业务会话会让计数一起消失。

    边界说明（有意接受）：
    - 并发请求可能同时读到「未超限」而一起放行，超出的尾部会多放几条。
      这是滑动窗口 + 非原子的固有边界；把窗口做成严格互斥需要行锁，
      代价与收益不匹配。
    """

    def __init__(
        self,
        settings: Settings | None = None,
        store: RuntimeStateStore | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.store = store or RuntimeStateStore()

    def check_retrieval(
        self,
        actor: str,
        project_ids: Sequence[str] = (),
        unrestricted: bool = False,
    ) -> tuple[bool, str, dict]:
        actor = str(actor)
        now = utcnow()
        self.store.record(SCOPE_RETRIEVAL, actor, at=now)
        used = self.store.count(SCOPE_RETRIEVAL, actor, HOUR_SECONDS, now=now)
        if used > self.settings.SECURITY_QUERY_BUDGET_PER_HOUR:
            self.store.record(SCOPE_RETRIEVAL_BLOCKED, actor, at=now)
            return False, "hourly_budget_exceeded", {
                "count": used,
                "limit": self.settings.SECURITY_QUERY_BUDGET_PER_HOUR,
            }

        targets = {pid for pid in project_ids if pid}
        if not unrestricted and len(targets) == 1:
            self.store.record(
                SCOPE_RETRIEVAL_PROJECT, actor, value=next(iter(targets)), at=now
            )
        distinct = self.store.distinct(
            SCOPE_RETRIEVAL_PROJECT, actor, PROBE_WINDOW_SECONDS, now=now
        )
        if distinct > DISTINCT_PROJECT_LIMIT:
            self.store.record(SCOPE_RETRIEVAL_BLOCKED, actor, at=now)
            return False, "cross_project_probing", {"distinct": distinct}

        return True, "ok", {"count": used}

    def enforce_retrieval(
        self,
        actor: str,
        project_ids: Sequence[str] = (),
        unrestricted: bool = False,
    ) -> None:
        ok, reason, details = self.check_retrieval(actor, project_ids, unrestricted)
        _raise_blocked(ok, reason, details)

    def check_export(self, actor: str, row_count: int) -> tuple[bool, str]:
        actor = str(actor)
        now = utcnow()
        if row_count > self.settings.SECURITY_EXPORT_LIMIT:
            return False, "batch_too_large"
        used = self.store.count(SCOPE_EXPORT, actor, HOUR_SECONDS, now=now)
        if used >= EXPORT_WINDOW_LIMIT:
            return False, "export_budget_exceeded"
        self.store.record(SCOPE_EXPORT, actor, at=now)
        return True, "ok"

    def snapshot(self, actor: str) -> dict:
        actor = str(actor)
        now = utcnow()
        return {
            "retrievals_last_hour": self.store.count(SCOPE_RETRIEVAL, actor, HOUR_SECONDS, now=now),
            "exports_last_hour": self.store.count(SCOPE_EXPORT, actor, HOUR_SECONDS, now=now),
            "blocked": self.store.count(SCOPE_RETRIEVAL_BLOCKED, actor, HOUR_SECONDS, now=now),
        }

    def reset(self) -> None:
        """仅用于测试/运维：清空预算相关计数域。"""
        self.store.purge(
            scopes=(
                SCOPE_RETRIEVAL,
                SCOPE_RETRIEVAL_PROJECT,
                SCOPE_RETRIEVAL_BLOCKED,
                SCOPE_EXPORT,
            )
        )


_budget: DbQueryBudget | None = None


def get_budget() -> DbQueryBudget:
    """路由层使用的预算实现：落库，跨副本共享同一窗口。"""
    global _budget
    if _budget is None:
        _budget = DbQueryBudget()
    return _budget
