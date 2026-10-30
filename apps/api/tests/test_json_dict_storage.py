"""回归：``JsonDict`` 在 PostgreSQL 上必须落成 jsonb **对象**，而不是字符串标量。

缺陷形态（本机真实 MinIO 端到端验证时发现）：``JSONDictType.impl = String`` 且
``process_bind_param`` 对所有方言都返回 ``json.dumps`` 的字符串，PostgreSQL 的 jsonb
列收到字符串后存成「JSON 字符串标量」（``jsonb_typeof`` = ``'string'``）。

为什么既有的全套测试没抓到：ORM 读回时会走 ``json_loads``，它把字符串再解析一次，
于是接口层看到的一直是 dict。只有**真在 SQL 里按元数据过滤**才会暴露——
``metadata_json->>'actor'`` 恒为 NULL，备份审计、看板、导出会静默少数据。
因此这里的断言必须落在 SQL 层（``jsonb_typeof`` / ``->>``），不能只断言 ORM 读回值。
"""

from __future__ import annotations

import json

import pytest
from conftest import is_pg
from rg_contracts.audit.service import AuditService
from rg_contracts.db import session as db_session
from rg_contracts.db.base import Base, JSONDictType
from rg_contracts.db.models import AuditLog
from rg_contracts.db.session import ensure_schema, get_engine
from sqlalchemy import text


def test_migration_covers_every_json_dict_column():
    """迁移清单必须**由模型推导**，不能手写：漏一列的后果是那列的历史行永远留在
    字符串标量形态，而「漏了」不会有任何报错——正是本缺陷当初活下来的方式。

    这里把「手写清单是否覆盖全部 JsonDict 列」变成一条会红的断言：模型新增
    JSON 列却忘了加迁移时，先红再说。
    """
    from_models = {
        (table.name, column.name)
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, JSONDictType)
    }
    assert from_models, "没有从模型里找到任何 JsonDict 列（类型推断失败？）"
    derived = set(db_session._json_dict_columns())
    missing = from_models - derived
    assert not missing, f"迁移清单漏了这些 JsonDict 列：{sorted(missing)}"
    # 反向也要成立：迁移不该去动模型里不存在的列（拼错表名/列名的兜底）
    assert not (derived - from_models), f"迁移清单包含模型里不存在的列：{sorted(derived - from_models)}"


def _record(session, metadata: dict | None = None) -> AuditLog:
    entry = AuditService(session, enabled=True).record(
        action="backup_probe",
        outcome="success",
        metadata=metadata if metadata is not None else {"actor": "system:backup", "tier": "daily"},
    )
    session.commit()
    return entry


def test_metadata_roundtrip_through_orm(session):
    """双方言：写入后重新读取仍是 dict（SQLite 文本 / PG jsonb 都要一致）。"""
    entry = _record(session)
    session.expire_all()
    reloaded = session.get(AuditLog, entry.id)
    assert reloaded.metadata_json == {"actor": "system:backup", "tier": "daily"}


@pytest.mark.skipif(not is_pg(), reason="jsonb 的存储形态只在 PostgreSQL 上存在")
def test_postgres_stores_metadata_as_jsonb_object(session):
    """核心回归：jsonb_typeof 必须是 object，SQL 侧 ->> 必须取得到值。"""
    entry = _record(session, {"actor": "system:backup", "object_key": "pg/daily/x.pgc.enc"})
    row = session.execute(
        text(
            "SELECT jsonb_typeof(metadata_json), metadata_json->>'actor' "
            "FROM audit_log WHERE id = :id"
        ),
        {"id": entry.id},
    ).one()
    assert row[0] == "object", (
        "metadata_json 被存成了 JSON 字符串标量：SQL 侧 metadata_json->>'actor' 会恒为 NULL"
    )
    assert row[1] == "system:backup"


@pytest.mark.skipif(not is_pg(), reason="存量行还原只针对 PostgreSQL 的 jsonb 字符串标量")
def test_legacy_string_scalar_rows_are_normalized(session):
    """存量行一次性还原：旧实现写下的字符串标量，跑一次 ensure_schema 后可被 SQL 过滤。"""
    session.execute(
        text(
            "INSERT INTO audit_log (id, ts, action, outcome, metadata_json) VALUES "
            "( 'aud_legacy_scalar', now(), 'backup_legacy', 'success', "
            "  to_jsonb('{\"actor\": \"system:backup\"}'::text) )"
        )
    )
    session.commit()
    before = session.execute(
        text("SELECT jsonb_typeof(metadata_json) FROM audit_log WHERE id = 'aud_legacy_scalar'")
    ).scalar_one()
    assert before == "string", "构造的存量行不成立（应为字符串标量）"

    # 迁移现在是「按 version 一次性」语义（``schema_migrations`` 注册表）：本次
    # 测试会话建库时这条迁移已登记过，不复位版本记录就不会重跑它。真实升级路径
    # 正是「老库没有 ``schema_version`` / 没有这条版本行」，所以这里显式删掉该行，
    # 模拟「还没跑过这条修复」的存量库。迁移本身幂等，删除版本行后重跑是安全的。
    session.execute(text("DELETE FROM schema_version WHERE version = CAST(:v AS INTEGER)"), {"v": 3})
    session.commit()

    ensure_schema(get_engine())

    after = session.execute(
        text(
            "SELECT jsonb_typeof(metadata_json), metadata_json->>'actor' "
            "FROM audit_log WHERE id = 'aud_legacy_scalar'"
        )
    ).one()
    assert after[0] == "object"
    assert after[1] == "system:backup"


@pytest.mark.skipif(is_pg(), reason="文本形式只用于 SQLite 方言垫片")
def test_sqlite_keeps_serialized_text(session):
    """SQLite 分支保持原样：存 JSON 文本，由 ORM 反序列化（降级路径不能改）。"""
    entry = _record(session)
    raw = session.execute(
        text("SELECT metadata_json FROM audit_log WHERE id = :id"), {"id": entry.id}
    ).scalar_one()
    assert isinstance(raw, str), "SQLite 应存文本"
    assert json.loads(raw)["actor"] == "system:backup"
