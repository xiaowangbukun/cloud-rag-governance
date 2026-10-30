"""D1 回归：``section_path`` 只有一个真值源——``knowledge_chunk.section_path`` 列。

历史包袱：摄取曾把章节路径写进 ``metadata_json["section_path"]``，而模型列
才是出处引用的正主。两个真值源不能长期并存，所以：

* **写入**：统一写模型列，``metadata_json`` 不再承载该字段；
* **读取**：``_source_of`` 只读列，**不留读取回退**（回退一留就再没人删，
  还会持续掩盖数据不一致）；
* **迁移**：历史数据由 ``startup.backfill_chunk_section_path`` 一次性幂等回填。

本文件把这三条各钉一条用例，并额外验证回填可重放（跑第二次返回 0）。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.retrieval import SecureRetriever
from rg_contracts.config import get_settings
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument, new_id, ts
from sqlalchemy import select

from rg_api.startup import backfill_chunk_section_path

MARKDOWN_DOC = "# 部署\n\n## 数据库\n\n先核对配额与事件，再看节点资源是否充足。\n"
LEGACY_SECTION_PATH = "历史章节 > 旧格式"


@pytest.fixture
def legacy_chunk(session):
    """造一条**旧格式**分片：章节路径只在 metadata_json 里，列为空。"""
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="D1 历史文档",
        doc_type="rule",
        project_id=None,
        content="占位内容",
        sanitized=True,
    )
    session.add(doc)
    session.flush()
    embedder = get_embedding_service(get_settings())
    chunk = KnowledgeChunk(
        document_id=doc.id,
        ordinal=0,
        project_id="proj_d1",
        platform=None,
        classification="L2_INTERNAL",
        embedding_text="历史分片正文：核对配额与事件。",
        display_text="历史分片正文：核对配额与事件。",
        token_count=18,
        embedding_model=embedder.model,
        embedding=embedder.embed("历史分片正文：核对配额与事件。"),
        section_path=None,
        metadata_json={"sanitized": True, "section_path": LEGACY_SECTION_PATH},
        created_at=ts(),
    )
    session.add(chunk)
    session.commit()
    ids = {"doc": doc.id, "chunk": chunk.id}

    yield ids

    session.delete(session.get(KnowledgeChunk, chunk.id))
    session.delete(session.get(KnowledgeDocument, doc.id))
    session.commit()


def test_ingest_writes_section_path_column_only(client, session, admin_headers):
    """新摄取：章节路径写进模型列，metadata_json 里不再出现该字段。"""
    resp = client.post(
        "/api/v1/knowledge/documents",
        json={"title": "D1 新文档", "content": MARKDOWN_DOC, "classification": "L2_INTERNAL"},
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text
    document_id = resp.json()["id"]
    try:
        session.expire_all()
        chunks = (
            session.execute(
                select(KnowledgeChunk)
                .where(KnowledgeChunk.document_id == document_id)
                .order_by(KnowledgeChunk.ordinal)
            )
            .scalars()
            .all()
        )
        assert chunks, "前置：应产出分片"
        assert any(chunk.section_path == "部署 > 数据库" for chunk in chunks), (
            "模型列未写入 section_path"
        )
        for chunk in chunks:
            assert "section_path" not in (chunk.metadata_json or {}), (
                "metadata_json 仍在写 section_path（双真值源）"
            )
    finally:
        for chunk in session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all():
            session.delete(chunk)
        document = session.get(KnowledgeDocument, document_id)
        if document is not None:
            session.delete(document)
        session.commit()


def test_legacy_metadata_is_not_read_back(session, legacy_chunk):
    """读取侧没有回退：旧格式分片在回填前，出处章节路径就是 None。

    这条是"回退已删除"的哨兵——如果有人把回退加回来，它会转红。
    """
    retriever = SecureRetriever(session)
    hits, _meta = retriever.search_with_metadata(
        query="历史分片正文：核对配额与事件。",
        subject=make_subject("governance", "L2_INTERNAL", project_ids=("proj_d1",)),
        allowed_project_ids=["proj_d1"],
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        top_k=5,
        unrestricted=False,
    )
    target = next(hit for hit in hits if hit.chunk_id == legacy_chunk["chunk"])
    assert target.source["section_path"] is None


def test_backfill_migrates_legacy_metadata_to_column(session, legacy_chunk):
    """迁移：一次性回填把旧格式值搬进列，之后出处即可溯源。"""
    migrated = backfill_chunk_section_path(session)
    assert migrated >= 1, "回填未处理历史行"

    session.expire_all()
    retriever = SecureRetriever(session)
    hits, _meta = retriever.search_with_metadata(
        query="历史分片正文：核对配额与事件。",
        subject=make_subject("governance", "L2_INTERNAL", project_ids=("proj_d1",)),
        allowed_project_ids=["proj_d1"],
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        top_k=5,
        unrestricted=False,
    )
    target = next(hit for hit in hits if hit.chunk_id == legacy_chunk["chunk"])
    assert target.source["section_path"] == LEGACY_SECTION_PATH


def test_backfill_is_idempotent(session, legacy_chunk):
    """回填可重放：第二次跑返回 0，不产生重复写入。"""
    assert backfill_chunk_section_path(session) >= 1
    assert backfill_chunk_section_path(session) == 0
