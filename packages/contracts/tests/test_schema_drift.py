"""列级 schema 漂移比对（``docs/schema-bootstrap-governance.md`` 方案 2 部件 B / R4）。

为什么必须有这一组用例
----------------------
``create_all`` 只建**缺失的表**：它既不补列、也不改列类型。旧版 ``verify_schema``
只比表名，于是「模型新增了一列但部署 Job 没跑」这种最常见的事故全程无信号——
应用启动成功，第一次碰到那列的查询才 500。这组用例把「漂移能被看见」变成断言：

- 新建库上漂移必须为空（否则比对本身有假阳性，``/ready`` 会长期挂红）；
- 多出来的列、被删掉的列都必须被命名级定位（table + column 一起给出，才可操作）；
- 缺表时 ``verify_schema`` 仍 fail-fast，且报错里带修复命令。

一律用 SQLite 内存库：被测逻辑是「元数据 ↔ introspection 的比对」，与方言无关；
PG 上的同一断言由 ``apps/api`` 的套件在真实库上跑（那边才有 PG 夹具）。
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from rg_contracts.db.session import (
    DRIFT_EXTRA_COLUMN,
    DRIFT_MISSING_COLUMN,
    DRIFT_MISSING_TABLE,
    DRIFT_TYPE_MISMATCH,
    ensure_schema,
    schema_drift,
    verify_schema,
)


def _sqlite_engine() -> Engine:
    return create_engine("sqlite:///:memory:")


def test_fresh_schema_has_no_drift() -> None:
    """新库（``create_all`` + 两条 SQLite 迁移）必须一条漂移都没有。

    这条用例的真正作用是**守住假阳性**：``TS()`` 的 ``with_variant``、
    ``JsonDict()`` 的 ``String↔JSONB``、``Vector`` 的 ``JSON↔vector`` 都会让
    「元数据渲染」与「反射结果」在字符串上不一致。哪次引入新类型导致比对误报，
    这条会先在 CI 红，而不是等到生产 ``/ready`` 上一直挂着假漂移。
    """
    engine = _sqlite_engine()
    ensure_schema(engine)

    assert schema_drift(engine) == []


def test_missing_table_is_reported_and_verify_fails_fast() -> None:
    """空库：每张模型表都报 ``missing_table``；``verify_schema`` 必须抛错。"""
    engine = _sqlite_engine()
    drift = schema_drift(engine)

    assert drift, "空库上必须报漂移"
    assert {item["kind"] for item in drift} == {DRIFT_MISSING_TABLE}
    assert all(item["table"] and not item["column"] for item in drift)

    with pytest.raises(RuntimeError) as excinfo:
        verify_schema(engine)
    message = str(excinfo.value)
    assert "schema 未就绪" in message
    assert "python -m rg_contracts.db.migrate" in message


def test_extra_column_is_reported_with_table_and_column() -> None:
    """库里多出来的列必须被命名级定位（只有表名不足以修复）。"""
    engine = _sqlite_engine()
    ensure_schema(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE resource_diff ADD COLUMN legacy_probe VARCHAR(32)"))

    drift = schema_drift(engine)

    extras = [item for item in drift if item["kind"] == DRIFT_EXTRA_COLUMN]
    assert [(item["table"], item["column"]) for item in extras] == [
        ("resource_diff", "legacy_probe")
    ]
    assert "VARCHAR(32)" in extras[0]["detail"]
    # 多余列不阻断就绪（存量库可能带着历史列正常运行），所以 verify 仍通过
    assert verify_schema(engine) == drift
    assert all(item["kind"] != DRIFT_MISSING_COLUMN for item in drift)


def test_missing_column_is_reported_and_verify_fails_fast() -> None:
    """模型有、库里没有的列：查询必然 500，必须在启动时就挡住。

    比文档原方案更严一点：文档把 ``missing_column`` 归为「可自动加」，但那要求
    启动时还有 DDL 权限；生产运行角色没有 DDL 权限，缺列就是纯粹的运行时 500，
    因此这里与缺表同等待遇（fail-fast，报错里给出迁移命令）。
    """
    engine = _sqlite_engine()
    ensure_schema(engine)
    with engine.begin() as conn:
        # 该列上有索引，SQLite 要求先删索引才能 DROP COLUMN
        conn.execute(text("DROP INDEX ix_resource_asset_tag"))
        conn.execute(text("ALTER TABLE resource DROP COLUMN asset_tag"))

    drift = schema_drift(engine)

    missing = [item for item in drift if item["kind"] == DRIFT_MISSING_COLUMN]
    assert [(item["table"], item["column"]) for item in missing] == [
        ("resource", "asset_tag")
    ]

    with pytest.raises(RuntimeError) as excinfo:
        verify_schema(engine)
    message = str(excinfo.value)
    assert "缺少" in message and "resource.asset_tag" in message
    assert "python -m rg_contracts.db.migrate" in message


def test_type_render_keeps_length_and_normalizes_synonyms() -> None:
    """类型渲染只合并同义写法，**绝不**合并长度/精度差异。

    误合并的后果是 ``VARCHAR(32)`` 被悄悄当成 ``VARCHAR(255)``：截断写入的
    半套结构在漂移清单里永远消失，这正是漂移治理最怕的「看起来没问题」。
    """
    from sqlalchemy import Integer, String

    engine = _sqlite_engine()
    dialect = engine.dialect

    assert schema_drift(engine, include_extra=False)[0]["kind"] == DRIFT_MISSING_TABLE
    from rg_contracts.db.session import _render_type

    assert _render_type(Integer(), dialect) == "INTEGER"
    assert _render_type(String(32), dialect) == "VARCHAR(32)"
    assert _render_type(String(255), dialect) == "VARCHAR(255)"
    assert _render_type(String(32), dialect) != _render_type(String(255), dialect)


def test_include_extra_false_hides_extra_columns_only() -> None:
    """``include_extra=False`` 只影响「多余列」这一类，其余差异照报。"""
    engine = _sqlite_engine()
    ensure_schema(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE project ADD COLUMN legacy_probe VARCHAR(32)"))

    full = schema_drift(engine)
    partial = schema_drift(engine, include_extra=False)

    assert any(item["kind"] == DRIFT_EXTRA_COLUMN for item in full)
    assert all(item["kind"] != DRIFT_EXTRA_COLUMN for item in partial)
    assert {item["kind"] for item in full} - {DRIFT_EXTRA_COLUMN} == {
        item["kind"] for item in partial
    }


def test_type_mismatch_kind_is_exported_for_callers() -> None:
    """``type_mismatch`` 的常量必须是对外契约的一部分（``/ready`` 按它分级）。"""
    assert DRIFT_TYPE_MISMATCH in {
        DRIFT_MISSING_TABLE,
        DRIFT_MISSING_COLUMN,
        DRIFT_TYPE_MISMATCH,
        DRIFT_EXTRA_COLUMN,
    }
