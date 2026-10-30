"""S1 回归：资源治理扩展的域模型与幂等迁移。

守四条：
1. 新表在双方言上都被 `ensure_schema()` 建出来，且索引齐全；
2. **迁移幂等** —— `ensure_schema()` 连跑多次不报错、不重复加列；
3. 存量库补列路径真的会补（用legacy 形状的临时库验证 ADD COLUMN 分支）；
4. **安全基座**：属性表与指标表**物理上不持有** `project_id` / `classification`
   —— 这是方案 A′ 的根基，裸查构造不出密级条件，"漏过滤"只能查不到而不泄露。

FK 与级联也一并钉住：属性行不可能指向不存在的锚点；锚点删除时属性/指标行级联删除。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from conftest import is_pg
from rg_contracts.db.models import (
    GpuNode,
    Resource,
    ResourceMetric,
    new_id,
    ts,
)
from rg_contracts.db.session import ensure_schema
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

#: 属性表/指标表：方案 A′ 要求它们不持有任何密级或项目列
_GOVERNED_DETAIL_TABLES = ("gpu_node", "resource_metric")
_FORBIDDEN_COLUMNS = ("project_id", "classification")


def _columns(session, table: str) -> set[str]:
    bind = session.get_bind()
    return {str(column["name"]) for column in inspect(bind).get_columns(table)}


def _index_names(session, table: str) -> set[str]:
    bind = session.get_bind()
    return {str(index["name"]) for index in inspect(bind).get_indexes(table)}


@pytest.fixture
def anchor(session):
    """造一个锚点行。

    复用演示种子里的 project 与 cloud_account（种子在双方言都由 conftest 灌入），
    自建 org/project/account 会引入一串 FK 清理顺序问题——本用例只关心
    「属性行 ↔ 锚点」这一对关系，不必再建组织树。
    """
    resource = Resource(
        id=new_id("res"),
        platform="bluking",
        account_id="acc_bk",
        project_id="prj_core_policy",
        native_id="node-s1-1",
        name="gpu-node-s1-1",
        kind="gpu_node",
        classification="L3_CONFIDENTIAL",
        owner_team="ai-platform",
        asset_tag="CMDB-S1-0001",
    )
    session.add(resource)
    session.flush()
    ids = {"resource": resource.id, "project": "prj_core_policy"}
    yield ids
    session.rollback()
    for model in (GpuNode, ResourceMetric):
        for row in session.execute(
            select(model).where(model.resource_id == resource.id)
        ).scalars().all():
            session.delete(row)
    existing = session.get(Resource, resource.id)
    if existing is not None:
        session.delete(existing)
    session.commit()


def test_new_tables_exist_after_ensure_schema(session):
    """双方言：gpu_node / resource_metric 都由 create_all 建出来。"""
    columns = _columns(session, "gpu_node")
    assert {"resource_id", "gpu_model", "total_gpus", "allocated_gpus"} <= columns
    metric_columns = _columns(session, "resource_metric")
    assert {"id", "resource_id", "metric_name", "value", "unit", "ts"} <= metric_columns


def test_ensure_schema_is_idempotent(session):
    """连跑 3 次：无异常，且不重复加列（列集合保持稳定）。"""
    before = _columns(session, "resource")
    bind = session.get_bind()
    for _ in range(3):
        ensure_schema(bind)
    assert _columns(session, "resource") == before
    assert "owner_team" in before and "asset_tag" in before


def test_expansion_columns_are_present_on_every_dialect(session):
    """resource.owner_team / asset_tag 与 resource_diff.rule_code 必须存在。

    PG 上额外用 information_schema 直查一次（方案文档的验收口径）。
    """
    assert {"owner_team", "asset_tag"} <= _columns(session, "resource")
    assert "rule_code" in _columns(session, "resource_diff")

    if not is_pg():
        return
    rows = session.execute(
        text(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND ("
            "  (table_name = 'resource' AND column_name IN ('owner_team', 'asset_tag'))"
            "  OR (table_name = 'resource_diff' AND column_name = 'rule_code'))"
        )
    ).all()
    found = {(str(row[0]), str(row[1])) for row in rows}
    assert found == {
        ("resource", "owner_team"),
        ("resource", "asset_tag"),
        ("resource_diff", "rule_code"),
    }


def test_expansion_indexes_exist(session):
    """新增索引（board 主路径 / 密级过滤主路径）在双方言上都建出来。"""
    resource_indexes = _index_names(session, "resource")
    assert "ix_resource_project_kind" in resource_indexes, resource_indexes
    assert "ix_resource_project_level" in resource_indexes, resource_indexes
    diff_indexes = _index_names(session, "resource_diff")
    assert "ix_diff_project_status_detected" in diff_indexes, diff_indexes


def test_detail_tables_have_no_classification_columns(session):
    """★ 安全基座：属性表与指标表物理上不持有 project_id / classification。

    漏了这条，"裸查属性表"就能构造出密级条件，方案 A′ 的 fail-safe 前提即失效。
    """
    for table in _GOVERNED_DETAIL_TABLES:
        columns = _columns(session, table)
        leaked = [column for column in _FORBIDDEN_COLUMNS if column in columns]
        assert not leaked, f"{table} 出现了密级/项目列：{leaked}（方案 A′ 的安全基座被破坏）"


def test_detail_row_requires_existing_anchor(session, anchor):
    """PK=FK：属性行不可能指向不存在的锚点。"""
    session.add(GpuNode(resource_id="res_does_not_exist", gpu_model="A100"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_deleting_anchor_cascades_to_details(session, anchor):
    """ON DELETE CASCADE：锚点删除后属性行与指标行一并删除，不留孤儿。"""
    resource_id = anchor["resource"]
    # updated_at 是 NOT NULL 且无数据库默认值：由唯一写入口（S2 的
    # upsert_governed_object）负责赋值，这里手工构造也要显式给
    session.add(
        GpuNode(resource_id=resource_id, gpu_model="A100", total_gpus=8, updated_at=ts())
    )
    session.add(
        ResourceMetric(
            id=new_id("rm"),
            resource_id=resource_id,
            metric_name="gpu_utilization",
            value=5.0,
            ts=ts(),
        )
    )
    session.commit()

    session.delete(session.get(Resource, resource_id))
    session.commit()
    assert session.execute(
        select(GpuNode).where(GpuNode.resource_id == resource_id)
    ).scalars().all() == []
    assert session.execute(
        select(ResourceMetric).where(ResourceMetric.resource_id == resource_id)
    ).scalars().all() == []


def test_legacy_database_gets_new_columns_added():
    """存量库补列分支：legacy 形状（缺新列）的库跑完 ensure_schema 后列被补上。

    只在 SQLite 上构造临时库验证：PG 需要另建 database/schema 才能造 legacy 形状，
    风险与权限成本不划算；PG 侧由上一条"列必须存在"用例 + 幂等用例覆盖。
    """
    if is_pg():
        pytest.skip("legacy 补列分支的临时库验证仅 SQLite 可构造（PG 需另建库/模式）")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "legacy.db"
        engine = create_engine(f"sqlite:///{path.as_posix()}")
        with engine.begin() as conn:
            # 手工造 legacy 形状（不含本次新增的列）
            conn.execute(
                text(
                    "CREATE TABLE resource ("
                    "id VARCHAR(64) PRIMARY KEY, platform VARCHAR(32) NOT NULL,"
                    "account_id VARCHAR(64) NOT NULL, project_id VARCHAR(64) NOT NULL,"
                    "native_id VARCHAR(128) NOT NULL, name VARCHAR(190) NOT NULL,"
                    "kind VARCHAR(32) NOT NULL, classification VARCHAR(32) NOT NULL)"
                )
            )
            conn.execute(
                text(
                    # detected_at 是既有列（新索引要用它），legacy 库必然已有
                    "CREATE TABLE resource_diff ("
                    "id VARCHAR(64) PRIMARY KEY, project_id VARCHAR(64) NOT NULL,"
                    "native_id VARCHAR(128) NOT NULL, kind VARCHAR(32) NOT NULL,"
                    "diff_kind VARCHAR(32) NOT NULL, classification VARCHAR(32) NOT NULL,"
                    "detected_at VARCHAR(64) NOT NULL, status VARCHAR(32) NOT NULL)"
                )
            )
            conn.execute(
                text(
                    # 本轮新增 project_id：存量库若缺列，security-events 查询会直接
                    # 「no such column」；ts 是既有列（新索引要用它）
                    "CREATE TABLE security_event ("
                    "id VARCHAR(64) PRIMARY KEY, ts VARCHAR(64) NOT NULL,"
                    "event_type VARCHAR(64) NOT NULL, severity VARCHAR(16) NOT NULL,"
                    "detail VARCHAR(500) NOT NULL, actor_id VARCHAR(64))"
                )
            )

        ensure_schema(engine)
        with engine.begin() as conn:
            resource_columns = {row[1] for row in conn.execute(text("PRAGMA table_info(resource)"))}
            diff_columns = {
                row[1] for row in conn.execute(text("PRAGMA table_info(resource_diff)"))
            }
        assert {"owner_team", "asset_tag"} <= resource_columns, resource_columns
        assert "rule_code" in diff_columns, diff_columns
        with engine.begin() as conn:
            event_columns = {
                row[1] for row in conn.execute(text("PRAGMA table_info(security_event)"))
            }
            event_indexes = {row[1] for row in conn.execute(text("PRAGMA index_list(security_event)"))}
        assert "project_id" in event_columns, event_columns
        assert "ix_security_event_project_ts" in event_indexes, event_indexes

        # 新表由 create_all 一并建出
        with engine.begin() as conn:
            tables = set(inspect(conn).get_table_names())
        assert {"gpu_node", "resource_metric"} <= tables

        # 再跑一次仍是幂等的（不重复加列）
        ensure_schema(engine)
        with engine.begin() as conn:
            again = {row[1] for row in conn.execute(text("PRAGMA table_info(resource)"))}
        assert again == resource_columns
        engine.dispose()
        if os.path.exists(path):
            os.remove(path)
