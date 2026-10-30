"""迁移互斥锁回归（第三批）：多进程/多 Pod 并发迁移时「先到者执行、后到者跳过」。

为什么必须测这个
----------------
迁移函数本身是幂等的，但 ``ALTER TABLE`` 是 DDL：两个 Pod 同时启动（或部署 Job
与手工重跑撞车）会并发执行，PG 上可能互相阻塞甚至留下半套结构。因此
``apply_pending`` 在 PG 分支先抢**会话级** advisory lock，抢不到就整体跳过
（返回 ``[]``），由持锁进程把 schema 改到目标状态。

用例的判别力来自「先删一条版本记录制造待执行迁移」：抢不到锁时返回 ``[]``
且版本行仍然缺失，才能证明是**真的没执行**，而不是「恰好没有待执行项」。
锁释放后同一条迁移必须能正常执行并把版本行补回来——同时验证锁没有泄漏。

SQLite 分支无会话级锁语义（单文件、单进程），直接跳过；那条路径的行为由
``packages/contracts/tests/test_schema_migrations.py`` 覆盖。
"""

from __future__ import annotations

import pytest
from conftest import is_pg
from rg_contracts.db.models import SchemaVersion
from rg_contracts.db.schema_migrations import (
    LOCK_KEY,
    apply_pending,
    pending_migrations,
)
from rg_contracts.db.session import get_engine
from sqlalchemy import delete, text
from sqlalchemy.orm import Session

#: 拿来做「可重跑」探针的迁移：``json_string_scalars`` 是 PG 专属的数据修复，
#: 幂等，重跑无副作用，且它的执行不依赖任何业务数据。
PROBE_VERSION = 3


def _lock_sql() -> str:
    return "SELECT pg_try_advisory_lock(hashtext(:key))"


def _unlock_sql() -> str:
    return "SELECT pg_advisory_unlock(hashtext(:key))"


@pytest.mark.skipif(not is_pg(), reason="advisory lock 是 PG 会话级锁，SQLite 无此语义")
def test_apply_pending_skips_while_another_connection_holds_lock():
    engine = get_engine()

    # 制造一条待执行迁移：删掉版本记录（迁移幂等，重跑安全，见模块文档）
    with Session(engine) as session:
        session.execute(delete(SchemaVersion).where(SchemaVersion.version == PROBE_VERSION))
        session.commit()
    assert [m.version for m in pending_migrations(engine)] == [PROBE_VERSION]

    blocker = engine.connect()
    restored: list[int] = []
    try:
        acquired = blocker.execute(text(_lock_sql()), {"key": LOCK_KEY}).scalar_one()
        assert acquired is True
        # 会话级锁不受 commit 影响；立刻 commit 让连接处于 idle，避免长事务
        blocker.commit()

        # 别的进程持锁：本次必须整体跳过
        assert apply_pending(engine) == []
        with Session(engine) as session:
            assert session.get(SchemaVersion, PROBE_VERSION) is None, (
                "抢不到锁时必须整体跳过，不能在内部偷偷执行"
            )
    finally:
        blocker.execute(text(_unlock_sql()), {"key": LOCK_KEY})
        blocker.commit()
        blocker.close()
        # 无论断言是否通过都恢复版本登记（避免污染后续用例），
        # 同时这也是「锁释放后能正常执行」的证据
        restored = apply_pending(engine)

    assert restored == [PROBE_VERSION]
    with Session(engine) as session:
        assert session.get(SchemaVersion, PROBE_VERSION) is not None


@pytest.mark.skipif(not is_pg(), reason="advisory lock 是 PG 会话级锁，SQLite 无此语义")
def test_apply_pending_releases_lock_after_run():
    """跑完迁移必须释放锁：否则下一次启动/手工重跑会永久被「跳过」。"""
    engine = get_engine()

    assert apply_pending(engine) == []  # 已是最新，空执行

    with engine.connect() as conn:
        acquired = conn.execute(text(_lock_sql()), {"key": LOCK_KEY}).scalar_one()
        try:
            assert acquired is True, "apply_pending 返回后锁仍然被持有——锁泄漏"
        finally:
            conn.execute(text(_unlock_sql()), {"key": LOCK_KEY})
            conn.commit()
