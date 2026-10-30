"""``schema_version`` 表 + 显式迁移注册表单测（``docs/schema-bootstrap-governance.md`` 方案 2 部件 A）。

为什么必须测这三件事：
- **注册表即唯一入口**（关闭 R7「定义了没调用」）：如果将来有人新写了一个
  ``_migrate_*`` 却没登记进注册表，它永远不会执行，且没有任何报错。这里用一条
  「注册表恰好覆盖 session 里全部 ``_migrate_*``」的断言把这个洞焊死。
- **版本真的被记下来**（关闭 R5「无版本记录」）：跑完 ``ensure_schema`` 后
  ``schema_version`` 必须按方言记录实际执行过的迁移，且二次调用不重复记录。
- **``--plan`` 只打印不执行**（R10 离线清单）：客户要拿它做变更评审，
  一旦它偷偷建了表/跑了 DDL，就不再有「预演」意义。

这些用例一律用 SQLite 内存库：被测逻辑（注册表、版本表读写、方言过滤）与
PG 无关；PG 专属的两条迁移只断言「在 SQLite 上被过滤掉」。
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine

from rg_contracts.db import migrate
from rg_contracts.db import session as session_module
from rg_contracts.db.schema_migrations import (
    applied_versions,
    apply_pending,
    describe_plan,
    pending_migrations,
    registry,
)
from rg_contracts.db.session import ensure_schema


def _sqlite_engine() -> Engine:
    return create_engine("sqlite:///:memory:")


def _table_names(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def test_registry_versions_are_unique_and_ascending() -> None:
    """① 注册表版本号唯一、严格升序 —— ``apply_pending`` 的顺序就是它给的。"""
    migrations = registry()
    versions = [migration.version for migration in migrations]

    assert versions == sorted(versions)
    assert len(set(versions)) == len(versions)
    assert versions[0] == 1, "版本号从 1 连续起步，方便对照 runbook 的升级步骤"
    for migration in migrations:
        assert migration.name and migration.description


def test_registry_covers_every_migrate_function() -> None:
    """② 注册表与 ``session`` 里的 ``_migrate_*`` 一一对应（防「写了没接线」）。

    这是本模块存在的核心价值：注册表是**唯一**执行入口，新增迁移函数只要
    忘记登记，这条断言立刻失败，而不是等到某次升级才发现老库缺列。
    """
    defined = {name for name in dir(session_module) if name.startswith("_migrate_")}
    registered = {migration.apply.__name__ for migration in registry()}

    assert defined == registered, (
        "session 里有未被注册表登记的迁移函数（它们永远不会执行）："
        f"{sorted(defined - registered)}"
    )


def test_applied_versions_is_empty_before_version_table_exists() -> None:
    """③ 首次部署：``schema_version`` 表还不存在时返回空字典，不抛异常。"""
    engine = _sqlite_engine()

    assert applied_versions(engine) == {}


def test_pending_migrations_filters_postgres_only_migrations() -> None:
    """④ 方言过滤：SQLite 上只待执行 2 条，PG 专属的 2 条不出现。"""
    engine = _sqlite_engine()
    pending = pending_migrations(engine)

    assert [migration.version for migration in pending] == [1, 2]
    pg_only = [migration.version for migration in registry() if migration.dialect == "postgresql"]
    assert pg_only == [3, 4]
    assert not [m for m in pending if m.dialect == "postgresql"]


def test_ensure_schema_records_versions_and_is_idempotent() -> None:
    """⑤ 新库跑一次：按方言记录版本；再跑一次返回空列表（不重复登记）。"""
    engine = _sqlite_engine()

    first = ensure_schema(engine)
    assert first == [1, 2], "SQLite 上 PG 专属的两条迁移不执行、也不登记"

    recorded = applied_versions(engine)
    assert sorted(recorded) == [1, 2]
    assert recorded[1] == "knowledge_columns"
    assert recorded[2] == "expansion_columns"

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT version, name, dialect, duration_ms, applied_at FROM schema_version")
        ).all()
    assert len(rows) == 2
    for version, name, dialect, duration_ms, applied_at in rows:
        assert name in {"knowledge_columns", "expansion_columns"}
        assert dialect == "sqlite"
        assert duration_ms >= 0
        assert applied_at, "applied_at 是排查「同版本在不同库上表现不同」的时间锚点"

    assert ensure_schema(engine) == []
    assert applied_versions(engine) == recorded


def test_apply_pending_on_fully_migrated_engine_is_noop() -> None:
    """⑥ 直接调 ``apply_pending`` 也幂等（它是 ``ensure_schema`` 的实际执行体）。"""
    engine = _sqlite_engine()
    assert ensure_schema(engine) == [1, 2]

    assert apply_pending(engine) == []
    assert sorted(applied_versions(engine)) == [1, 2]


def test_describe_plan_does_not_execute_any_ddl() -> None:
    """⑦ ``--plan`` 的数据源只读：空库上调用后依然没有建表。"""
    engine = _sqlite_engine()
    before = _table_names(engine)

    plan = describe_plan(engine)

    assert _table_names(engine) == before
    assert "schema_version" not in _table_names(engine)
    assert [item["version"] for item in plan] == [1, 2]
    for item in plan:
        assert set(item) == {"version", "name", "dialect", "description"}
        assert item["dialect"] in {"all", "postgresql"}


def test_describe_plan_after_apply_is_empty() -> None:
    """⑧ 迁移都登记完之后，plan 为空 —— 与 ``apply_pending`` 共用同一判定。"""
    engine = _sqlite_engine()
    ensure_schema(engine)

    assert describe_plan(engine) == []


def test_plan_subcommand_prints_plan_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """⑨ CLI ``--plan``：打印待执行清单与「未执行任何 DDL」，退出码 0。"""
    engine = _sqlite_engine()

    assert migrate._cmd_plan(engine) == 0

    out = capsys.readouterr().out
    assert "dry-run" in out
    assert "knowledge_columns" in out
    assert "expansion_columns" in out
    # PG 专属迁移在 SQLite 上不列出来
    assert "json_string_scalars" not in out


def test_verify_subcommand_fails_before_schema_and_passes_after(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """⑩ CLI ``--verify``：缺表返回 1（不建表）；建好后返回 0。"""
    engine = _sqlite_engine()
    before = _table_names(engine)

    assert migrate._cmd_verify(engine) == 1
    err = capsys.readouterr().err
    assert "verify failed" in err
    assert "schema 未就绪" in err
    assert "python -m rg_contracts.db.migrate" in err  # 报错里给出修复命令
    assert _table_names(engine) == before, "--verify 只校验，不允许建表"

    ensure_schema(engine)
    assert migrate._cmd_verify(engine) == 0
    out = capsys.readouterr().out
    assert "verify ok" in out and "applied=[1, 2]" in out


def test_plan_and_verify_flags_are_mutually_exclusive() -> None:
    """⑪ argparse：``--plan`` 与 ``--verify`` 不能同时给（两者语义互斥）。"""
    parser = migrate._build_parser()

    assert parser.parse_args(["--plan"]).plan is True
    assert parser.parse_args(["--verify"]).verify is True
    assert parser.parse_args([]).plan is False and parser.parse_args([]).verify is False
    with pytest.raises(SystemExit):
        parser.parse_args(["--plan", "--verify"])
