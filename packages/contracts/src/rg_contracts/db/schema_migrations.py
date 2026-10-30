"""schema 版本记录 + 显式迁移注册表（``docs/schema-bootstrap-governance.md`` 方案 2 部件 A）。

为什么不用 Alembic
------------------
该文档 §3 方案 3 明确「P0 不采纳」，并写了切换判据：迁移数 > 8–10 个、出现第一次
需要回滚、出现改列类型/删列/改约束、团队 ≥3 人并行。当前仓库只有 4 条 ``_migrate_*``
迁移，判据一条都没满足；文档同时指出**最致命的缺口是「无版本记录」，不是「没有工具」**。
所以这里补的是版本表 + 注册表，而不是引入 Alembic。``apps/api/pyproject.toml``
里原有的 ``alembic>=1.13`` 属预留声明、全仓零调用，已连同传递依赖一并移除。

这个模块解决什么
----------------
- **R5 无版本**：``schema_version`` 表逐条记录「哪个迁移、什么时候、在哪个方言上执行了」；
- **R7 定义了没调用**：迁移函数进注册表即执行，注册表是唯一入口，写新迁移不可能「忘了接线」；
- **R10 离线清单**：``pending_migrations`` 供 ``python -m rg_contracts.db.migrate --plan``
  打印待执行清单，客户拿去做变更评审（只打印、不执行）。

刻意没做原子化
--------------
每条迁移函数自带事务（它们历史上就是 ``def _migrate_x(engine: Engine)`` 的形态），
所以「执行 DDL」与「写 version 行」不在同一个事务里。这里不强行合并，是因为所有迁移
函数都被设计成**幂等**（introspection 判断后再 ALTER）：万一在两步之间进程被杀，
下一次运行会重放同一条迁移（空操作）并补登记版本，结果仍然收敛。

「一次性」语义
--------------
版本登记过就不再执行（``pending_migrations`` 用 ``applied_versions`` 过滤）。这与
历史实现「每次启动都跑一遍全部 ``_migrate_*``」不同：数据修复类迁移
（``json_string_scalars``）因此不再每次启动自愈。收益是省掉每次启动的全表扫描；
代价是滚动更新窗口内旧 Pod 写入的历史坏形态行不会自动修复。需要重跑某条迁移时，
删掉 ``schema_version`` 里对应 version 行再执行 ``python -m rg_contracts.db.migrate``
即可（迁移本身幂等）。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy import select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from rg_contracts.db.models import SchemaVersion, ts
from rg_contracts.logging_setup import get_logger, log_event

logger = get_logger(__name__)

#: 迁移互斥锁的键。**会话级** advisory lock（``pg_try_advisory_lock``），
#: 与 ``apps/api/tests/conftest.py`` 的写法一致：拿不到锁说明别的 Pod / 别的
#: 运维会话正在跑迁移，本次直接跳过。
#:
#: 为什么需要它：``create_all`` + ``ALTER TABLE`` 是 DDL，多 Pod 同时启动（或
#: Job 与手工重跑撞车）会并发执行；迁移本身幂等，但并发 DDL 在 PG 上会互相
#: 阻塞甚至因竞争拿到不一致的表结构。加锁后行为退化为「先到者执行、后到者跳过」
#: ——跳过是安全的，因为先到者跑完后 schema 就是目标状态。
LOCK_KEY = "rg_contracts.db.schema_migrations"


def _try_advisory_lock(engine: Engine) -> Connection | None:
    """PG：尝试拿会话级锁。拿到返回**持锁连接**（调用方负责释放/关闭）。

    非 PG 方言返回 ``None`` 且不做任何事：SQLite 是单文件、单进程语义明确
    （测试库另有 destructive-reset 闸门），没有行为变化。
    """
    if engine.dialect.name != "postgresql":
        return None
    lock_conn = engine.connect()
    acquired = bool(
        lock_conn.execute(
            text("SELECT pg_try_advisory_lock(hashtext(:key))"), {"key": LOCK_KEY}
        ).scalar()
    )
    # 立即使事务进入 idle：会话级锁不受 commit 影响，但悬着的事务会让
    # ``idle_in_transaction_session_timeout`` 有理由杀掉连接（锁随之静默丢失）。
    lock_conn.commit()
    if not acquired:
        lock_conn.close()
        return None
    return lock_conn


def _release_advisory_lock(lock_conn: Connection) -> None:
    try:
        lock_conn.execute(
            text("SELECT pg_advisory_unlock(hashtext(:key))"), {"key": LOCK_KEY}
        )
        lock_conn.commit()
    except Exception:  # noqa: BLE001 —— 释放失败不应掩盖迁移结果；连接关闭也会释放
        log_event(logger, logging.WARNING, "migration lock release failed", key=LOCK_KEY)
    finally:
        lock_conn.close()


@dataclass(frozen=True)
class Migration:
    """一条可执行、可登记、可打印的 schema 迁移。"""

    version: int
    name: str
    #: 迁移函数：接受 Engine、内部自行开事务（幂等）
    apply: Callable[[Engine], None]
    #: 适用方言；``None`` = 双方言（SQLite + PostgreSQL）
    dialect: str | None = None
    #: 给 ``--plan`` 用的一句话说明（离线客户做变更评审时看的是这个）
    description: str = ""


def registry() -> tuple[Migration, ...]:
    """迁移注册表：**唯一**的执行入口，按 version 升序。

    为什么函数引用要延迟导入：``session.ensure_schema`` 会导入本模块（拿
    ``apply_pending``），而迁移函数本体仍在 ``session.py`` 里（历史上就在那儿，
    ``test_migrations.py`` 直接引用它们）。模块级互相导入会成环，放在函数体内
    解析即可，代价可忽略。
    """
    from rg_contracts.db.session import (
        _migrate_expansion_columns,
        _migrate_json_string_scalars,
        _migrate_knowledge_columns,
        _migrate_legacy_vector_columns,
    )

    return (
        Migration(
            version=1,
            name="knowledge_columns",
            apply=_migrate_knowledge_columns,
            description=(
                "knowledge_document/knowledge_chunk 补出处列"
                "（source_type/source_path/page_count/section_path/page_no/char_start/char_end）"
            ),
        ),
        Migration(
            version=2,
            name="expansion_columns",
            apply=_migrate_expansion_columns,
            description="resource 补 owner_team/asset_tag、resource_diff 补 rule_code、security_event 补 project_id",
        ),
        Migration(
            version=3,
            name="json_string_scalars",
            apply=_migrate_json_string_scalars,
            dialect="postgresql",
            description="把历史 JSON 字符串标量规范为 JSONB 标量（PG 方言专属）",
        ),
        Migration(
            version=4,
            name="legacy_vector_columns",
            apply=_migrate_legacy_vector_columns,
            dialect="postgresql",
            description="把早期 vector 列类型收敛为 vector(dim)（PG 方言专属）",
        ),
    )


def applied_versions(engine: Engine) -> dict[int, str]:
    """已登记的版本 → 迁移名。表还不存在时返回空字典（首次部署路径）。"""
    from sqlalchemy import inspect

    if SchemaVersion.__tablename__ not in set(inspect(engine).get_table_names()):
        return {}
    with Session(engine) as session:
        rows = session.execute(select(SchemaVersion.version, SchemaVersion.name)).all()
    return {int(version): str(name) for version, name in rows}


def pending_migrations(engine: Engine) -> list[Migration]:
    """本方言下还没登记的迁移，按 version 升序。

    ``--plan`` 与 ``apply_pending`` 共用这一个判定，避免「看到要跑 A、实际跑了 B」。
    """
    done = set(applied_versions(engine))
    dialect = engine.dialect.name
    return [
        migration
        for migration in registry()
        if migration.version not in done
        and (migration.dialect is None or migration.dialect == dialect)
    ]


def _record(engine: Engine, migration: Migration, duration_ms: int) -> None:
    with Session(engine) as session:
        session.add(
            SchemaVersion(
                version=migration.version,
                name=migration.name,
                applied_at=ts(),
                dialect=engine.dialect.name,
                duration_ms=duration_ms,
            )
        )
        session.commit()


def apply_pending(engine: Engine) -> list[int]:
    """按 version 顺序执行未登记的迁移并逐条登记，返回**本次实际执行**的 version。

    ``schema_version`` 表必须已存在：它由 ``create_all`` 建出（表在 ORM 元数据里，
    不存在鸡生蛋问题）。调用顺序因此固定为「先 create_all、再 apply_pending」。

    PG 上加一把**会话级 advisory lock**：抢不到锁说明别的进程正在迁移本库，
    本次返回空列表（跳过）并记一条 warning。跳过是安全的——迁移幂等，先到者
    跑完后 schema 即目标状态；而不加锁的并发 DDL 会互相阻塞甚至留下半套结构。
    """
    if engine.dialect.name == "postgresql":
        lock_conn = _try_advisory_lock(engine)
        if lock_conn is None:
            log_event(
                logger,
                logging.WARNING,
                "migration skipped: another process holds the lock",
                key=LOCK_KEY,
                impact="本次不执行迁移；schema 由持锁进程改写",
            )
            return []
        try:
            return _apply_all(engine)
        finally:
            _release_advisory_lock(lock_conn)
    return _apply_all(engine)


def _apply_all(engine: Engine) -> list[int]:
    """实际的执行体：按 version 顺序执行 + 逐条登记（调用方负责加锁）。"""
    applied: list[int] = []
    for migration in pending_migrations(engine):
        started = time.perf_counter()
        migration.apply(engine)
        duration_ms = int((time.perf_counter() - started) * 1000)
        _record(engine, migration, duration_ms)
        applied.append(migration.version)
    return applied


def describe_plan(engine: Engine) -> list[dict[str, Any]]:
    """``--plan`` 的数据形态：待执行清单 + 已登记版本，供 CLI 打印与测试断言。"""
    return [
        {
            "version": migration.version,
            "name": migration.name,
            "dialect": migration.dialect or "all",
            "description": migration.description,
        }
        for migration in pending_migrations(engine)
    ]


__all__ = [
    "Migration",
    "applied_versions",
    "apply_pending",
    "describe_plan",
    "pending_migrations",
    "registry",
]
