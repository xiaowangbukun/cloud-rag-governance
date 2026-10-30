"""D2 回归：``_apply_diversity`` 的单项目配额溢出项必须**丢弃**，不塞满 top_k。

旧行为：超配额的分片被追加到结果末尾（为了凑满 ``top_k``），导致 top-k 尾部
混入低分片段——调用方会把它们当成与头部同等相关的结果，配额的防护强度也被稀释。

新行为：溢出即丢弃，结果条数可以**少于** ``top_k``。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.retrieval import SecureRetriever
from rg_contracts.config import get_settings, reset_settings_cache
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument, new_id, ts
from sqlalchemy import select

PROJECT_ID = "proj_diversity"
QUERY = "部署章节正文：先核对配额再执行扩容动作。"


@pytest.fixture
def settings_env(monkeypatch):
    def _apply(**env: str) -> None:
        for key, value in env.items():
            monkeypatch.setenv(key, str(value))
        reset_settings_cache()

    yield _apply
    reset_settings_cache()


@pytest.fixture
def many_chunks(session):
    """同一项目下造 5 个分片（都高于阈值，都会被召回）。"""
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="D2 配额测试文档",
        doc_type="rule",
        project_id=None,
        content="占位内容",
        sanitized=True,
    )
    session.add(doc)
    session.flush()
    embedder = get_embedding_service(get_settings())
    now = ts()
    chunks = []
    for ordinal in range(5):
        text = f"部署章节正文第{ordinal}条：先核对配额再执行扩容动作，然后复核健康检查。"
        chunk = KnowledgeChunk(
            document_id=doc.id,
            ordinal=ordinal,
            project_id=PROJECT_ID,
            platform=None,
            classification="L2_INTERNAL",
            embedding_text=text,
            display_text=text,
            token_count=len(text),
            embedding_model=embedder.model,
            embedding=embedder.embed(text),
            created_at=now,
        )
        chunks.append(chunk)
    session.add_all(chunks)
    session.commit()
    ids = [chunk.id for chunk in chunks] + [doc.id]

    yield ids

    for chunk in session.execute(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == doc.id)
    ).scalars().all():
        session.delete(chunk)
    session.delete(session.get(KnowledgeDocument, doc.id))
    session.commit()


def _search(session, top_k: int = 10) -> list:
    retriever = SecureRetriever(session)
    hits, _meta = retriever.search_with_metadata(
        query=QUERY,
        subject=make_subject("governance", "L2_INTERNAL", project_ids=(PROJECT_ID,)),
        allowed_project_ids=[PROJECT_ID],
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        top_k=top_k,
        unrestricted=False,
    )
    return hits


def _from_project(hits: list) -> list:
    """只取目标项目的命中：全局知识（project_id 为 None）有**独立**的配额桶，
    配额是按项目分别计的，断言必须按项目口径做，否则会被种子全局分片带偏。"""
    return [hit for hit in hits if hit.project_id == PROJECT_ID]


def test_overflow_items_are_dropped_not_appended(session, many_chunks, settings_env):
    """核心回归：配额=2、同项目 5 条语料 → 该项目只回 2 条，且是分数最高的 2 条。"""
    settings_env(RAG_MAX_CHUNKS_PER_PROJECT="2", RAG_CANDIDATE_LIMIT="500")
    assert get_settings().RAG_MAX_CHUNKS_PER_PROJECT == 2, "前置：配额未生效"

    hits = _search(session, top_k=10)
    picked = _from_project(hits)
    assert len(picked) == 2, f"溢出项被塞进了结果：该项目回了 {len(picked)} 条（配额 2）"

    # 留下的必须是分数最高的两条（丢弃的是低分，不是随机）
    settings_env(RAG_MAX_CHUNKS_PER_PROJECT="5", RAG_CANDIDATE_LIMIT="500")
    all_picked = _from_project(_search(session, top_k=10))
    assert len(all_picked) >= 3, "前置：放宽配额后该项目应有更多命中"
    assert [hit.score for hit in picked] == [hit.score for hit in all_picked[:2]], (
        "保留的不是最高分的两条：丢弃逻辑破坏了排序"
    )


def test_result_may_be_shorter_than_top_k(session, many_chunks, settings_env):
    """结果条数可以少于 top_k —— 不为了凑数塞低分片段。"""
    settings_env(RAG_MAX_CHUNKS_PER_PROJECT="1", RAG_CANDIDATE_LIMIT="500")
    hits = _search(session, top_k=8)
    assert len(_from_project(hits)) == 1, "配额 1 时该项目应只回 1 条"
