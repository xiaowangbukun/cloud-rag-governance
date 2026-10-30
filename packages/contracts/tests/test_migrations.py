"""存量库补列迁移单测（P1）。

被测对象：``rg_contracts.db.session._migrate_knowledge_columns``，经由公开入口
``ensure_schema`` 调用（同时验证接线正确）。

为什么必须测：项目没有 alembic，``create_all`` 只建缺失的表、**不会给已存在的表加列**。
按 runbook 从旧版本升级上来的库，一旦缺这 7 列，任何读知识库的请求都会
``no such column``。这条迁移是升链路能否走通的关键路径。

SQLite 无法直接「删除列」（3.35 之前），所以旧表结构用「模型列减去新增列」现场
推导 —— 这样即使将来模型又加列，夹具也不会与真实模型脱节。
"""

from __future__ import annotations

from sqlalchemy import Column, MetaData, Table, create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument
from rg_contracts.db.session import _migrate_knowledge_columns, ensure_schema

#: P1 新增的列（与 models.py、_KNOWLEDGE_COLUMN_UPGRADES 保持一致）
NEW_DOCUMENT_COLUMNS = ("source_type", "source_path", "page_count")
NEW_CHUNK_COLUMNS = ("section_path", "page_no", "char_start", "char_end")


def _legacy_create_sql(model: type, drop_columns: tuple[str, ...], engine: Engine) -> str:
    """生成「去掉指定列」的建表 SQL，用于模拟升级前的存量库。"""
    table = model.__table__  # type: ignore[attr-defined]
    legacy_meta = MetaData()
    legacy_table = Table(table.name, legacy_meta)
    for column in table.columns:
        if column.name in drop_columns:
            continue
        legacy_table.append_column(
            Column(
                column.name,
                column.type,
                primary_key=column.primary_key,
                nullable=column.nullable,
            )
        )
    return str(CreateTable(legacy_table).compile(dialect=engine.dialect))


def _make_legacy_engine() -> Engine:
    """构造「P1 之前」的 SQLite 库：两张知识表只有旧列，并各含一行存量数据。"""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text(_legacy_create_sql(KnowledgeDocument, NEW_DOCUMENT_COLUMNS, engine)))
        conn.execute(text(_legacy_create_sql(KnowledgeChunk, NEW_CHUNK_COLUMNS, engine)))
        conn.execute(
            text(
                "INSERT INTO knowledge_document "
                "(id, title, doc_type, classification, content, sanitized, metadata_json,"
                " created_at, updated_at) VALUES "
                "('kd_legacy', '旧文档', 'rule', 'L2_INTERNAL', '旧正文', 1, '{}',"
                " '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO knowledge_chunk "
                "(id, document_id, ordinal, classification, embedding_text, display_text,"
                " token_count, embedding_model, metadata_json, created_at) VALUES "
                "('kc_legacy', 'kd_legacy', 0, 'L2_INTERNAL', '旧分片', '旧分片', 3,"
                " 'offline', '{}', '2026-01-01T00:00:00+00:00')"
            )
        )
    return engine


def _column_names(engine: Engine, table: str) -> set[str]:
    return {column["name"] for column in inspect(engine).get_columns(table)}


def test_legacy_schema_is_upgraded_and_data_preserved() -> None:
    """① 旧表结构跑一次 ensure_schema → 新列齐全，存量行与既有列不变。"""
    engine = _make_legacy_engine()
    assert "source_type" not in _column_names(engine, "knowledge_document")

    ensure_schema(engine)

    document_columns = _column_names(engine, "knowledge_document")
    chunk_columns = _column_names(engine, "knowledge_chunk")
    assert set(NEW_DOCUMENT_COLUMNS) <= document_columns
    assert set(NEW_CHUNK_COLUMNS) <= chunk_columns

    with engine.connect() as conn:
        document = conn.execute(
            text(
                "SELECT id, title, content, source_type, source_path, page_count "
                "FROM knowledge_document"
            )
        ).one()
        chunk = conn.execute(
            text(
                "SELECT id, document_id, embedding_text, section_path, page_no, "
                "char_start, char_end FROM knowledge_chunk"
            )
        ).one()

    # 存量数据原样保留，新列按默认值回填
    assert document[0] == "kd_legacy"
    assert document[1] == "旧文档"
    assert document[2] == "旧正文"
    assert document[3] == "text"
    assert document[4] is None
    assert document[5] == 0
    # 出处列对存量分片为 NULL（不编造章节/页码）
    assert chunk[0] == "kc_legacy"
    assert chunk[1] == "kd_legacy"
    assert chunk[2] == "旧分片"
    assert chunk[3] is None and chunk[4] is None
    assert chunk[5] is None and chunk[6] is None


def test_upgraded_schema_is_usable_through_orm() -> None:
    """迁移后 ORM 能正常读旧行，也能写入带出处的新行。"""
    engine = _make_legacy_engine()
    ensure_schema(engine)

    with Session(engine) as session:
        document = session.get(KnowledgeDocument, "kd_legacy")
        assert document is not None
        assert document.source_type == "text"
        assert document.page_count == 0
        assert document.source_path is None

        chunk = session.get(KnowledgeChunk, "kc_legacy")
        assert chunk is not None
        assert chunk.section_path is None

        fresh = KnowledgeChunk(
            id="kc_new",
            document_id="kd_legacy",
            ordinal=1,
            embedding_text="新分片",
            display_text="新分片",
            embedding_model="offline",
            section_path="3 部署 > 3.2 数据库",
            page_no=7,
            char_start=120,
            char_end=380,
            created_at=document.created_at,
        )
        session.add(fresh)
        session.commit()

    with Session(engine) as session:
        stored = session.get(KnowledgeChunk, "kc_new")
        assert stored is not None
        assert stored.section_path == "3 部署 > 3.2 数据库"
        assert stored.page_no == 7
        assert (stored.char_start, stored.char_end) == (120, 380)


def test_migration_is_idempotent() -> None:
    """② 连跑两次（两次 ensure_schema + 两次直接调用）不报错、列集合不变。"""
    engine = _make_legacy_engine()

    ensure_schema(engine)
    first_document = _column_names(engine, "knowledge_document")
    first_chunk = _column_names(engine, "knowledge_chunk")

    ensure_schema(engine)
    _migrate_knowledge_columns(engine)
    _migrate_knowledge_columns(engine)

    assert _column_names(engine, "knowledge_document") == first_document
    assert _column_names(engine, "knowledge_chunk") == first_chunk
    with engine.connect() as conn:
        # 重复迁移不得插行、不得清数据
        assert conn.execute(text("SELECT count(*) FROM knowledge_document")).scalar_one() == 1
        assert conn.execute(text("SELECT count(*) FROM knowledge_chunk")).scalar_one() == 1


def test_fresh_schema_migration_is_noop() -> None:
    """③ 新库路径（create_all 已建全列）跑迁移是空操作，不报错。"""
    engine = create_engine("sqlite:///:memory:")
    ensure_schema(engine)
    before_document = _column_names(engine, "knowledge_document")
    before_chunk = _column_names(engine, "knowledge_chunk")
    assert set(NEW_DOCUMENT_COLUMNS) <= before_document
    assert set(NEW_CHUNK_COLUMNS) <= before_chunk

    _migrate_knowledge_columns(engine)

    assert _column_names(engine, "knowledge_document") == before_document
    assert _column_names(engine, "knowledge_chunk") == before_chunk


def test_migration_ignores_absent_tables() -> None:
    """表不存在时整体跳过（只建了别的表的库/半初始化状态不应炸启动）。"""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"))

    _migrate_knowledge_columns(engine)

    tables = set(inspect(engine).get_table_names())
    assert "knowledge_document" not in tables
    assert "knowledge_chunk" not in tables
