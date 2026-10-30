"""检索响应补全回归（方案 §4.2 第 87 行 / §4.3 第 106 行）。

补全三项，全部**纯新增字段**，既有响应字段名与结构不动（前端仍在消费）：

1. ``retrieval.keyword_scope``：候选集被截短时是 ``"truncated"``，否则
   ``"full"`` —— 没有它，调用方会把「被上限截断」误判成「库里根本没有」。
2. 每个命中的 ``vector_score`` / ``keyword_score`` / ``fused_score``：融合
   关闭时后两者是 ``None``（None = 通道未启用，**不是 0** —— 0 是合法分数）。
3. 每个命中的 ``source``：``{document_title, section_path, page_no, ordinal}``，
   让回答能溯源到文档/章节/页码。

安全约束：新增字段不得成为泄漏通道——document_title 出库前再净化一次，
section_path / page_no 只取分片自身已授权的行内字段。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.retrieval import SecureRetriever
from rg_contracts.config import get_settings, reset_settings_cache
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument, new_id, ts
from sqlalchemy import select

PROJECT_ID = "proj_rmeta"


@pytest.fixture
def settings_env(monkeypatch):
    """切换检索相关配置；用例结束重置缓存，避免污染同进程其他用例。"""

    def _apply(**env: str) -> None:
        for key, value in env.items():
            monkeypatch.setenv(key, str(value))
        reset_settings_cache()

    yield _apply
    reset_settings_cache()


@pytest.fixture
def rmeta_chunks(session):
    """造 3 个 L2 分片：Markdown（章节路径）+ PDF（页码）+ 普通文本。"""
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="响应补全测试文档 联系人 ops@corp.local",
        doc_type="rule",
        project_id=None,
        content="占位内容",
        sanitized=True,
    )
    session.add(doc)
    session.flush()

    embedder = get_embedding_service(get_settings())
    now = ts()
    markdown_text = "部署章节正文：先核对配额再执行扩容动作。"
    pdf_text = "PDF 页内正文：驱动版本与 CUDA 版本必须匹配。"

    def _chunk(text: str, ordinal: int, **extra) -> KnowledgeChunk:
        return KnowledgeChunk(
            document_id=doc.id,
            ordinal=ordinal,
            project_id=PROJECT_ID,
            platform="db",
            classification="L2_INTERNAL",
            embedding_text=text,
            display_text=text,
            token_count=len(text),
            embedding_model=embedder.model,
            embedding=embedder.embed(text),
            created_at=now,
            **extra,
        )

    # D1：新格式分片把章节路径写在模型列上（metadata_json 不再承载该字段）
    markdown = _chunk(
        markdown_text,
        0,
        metadata_json={"sanitized": True},
        section_path="部署 > 数据库",
    )
    pdf = _chunk(pdf_text, 1, page_no=7, section_path="3 部署")
    plain = _chunk("普通文本分片：资源下线前需释放弹性公网地址。", 2)
    session.add_all([markdown, pdf, plain])
    session.commit()
    ids = {"markdown": markdown.id, "pdf": pdf.id, "plain": plain.id, "doc": doc.id}

    yield ids

    for chunk in session.execute(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == doc.id)
    ).scalars().all():
        session.delete(chunk)
    session.delete(session.get(KnowledgeDocument, doc.id))
    session.commit()


def _search_hits(session, query: str, top_k: int = 20) -> list:
    retriever = SecureRetriever(session)
    hits, _meta = retriever.search_with_metadata(
        query=query,
        subject=make_subject("governance", "L2_INTERNAL", project_ids=(PROJECT_ID,)),
        allowed_project_ids=[PROJECT_ID],
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        top_k=top_k,
        unrestricted=False,
    )
    return hits


def _api_search(client, headers, query: str, project_id: str = "prj_core_policy", top_k: int = 8) -> dict:
    resp = client.post(
        "/api/v1/knowledge/search",
        json={"query": query, "project_id": project_id, "top_k": top_k},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_keyword_scope_is_full_when_candidate_set_complete(client, pm_headers, settings_env):
    """①-a 候选集没被截短时 keyword_scope == full。"""
    settings_env(RAG_CANDIDATE_LIMIT="500")
    body = _api_search(client, pm_headers, "资源新增需要核对什么")
    assert body["retrieval"]["keyword_scope"] == "full", "候选集完整却标记为 truncated"


def test_keyword_scope_is_truncated_when_candidate_set_capped(client, pm_headers, settings_env):
    """①-b 候选集被 RAG_CANDIDATE_LIMIT 截短时必须显式标注（防假阴性）。"""
    settings_env(RAG_CANDIDATE_LIMIT="2")
    assert get_settings().RAG_CANDIDATE_LIMIT == 2, "前置：上限未生效"
    body = _api_search(client, pm_headers, "资源新增需要核对什么")
    assert body["retrieval"]["keyword_scope"] == "truncated", (
        "候选集被截短却未标注：调用方会误判成「库里根本没有」"
    )


def test_response_hits_carry_score_breakdown_and_source(client, pm_headers, settings_env):
    """② 命中项带上打分明细与出处；新增键不得动既有键。"""
    settings_env(RAG_CANDIDATE_LIMIT="500")
    body = _api_search(client, pm_headers, "资源新增需要核对什么")
    assert body["security"]["prefiltered"] is True, "既有 security 结构被破坏"
    hits = body["hits"]
    assert hits, "前置：应有命中"
    for hit in hits:
        for key in ("chunk_id", "text", "score", "metadata"):
            assert key in hit, f"既有命中字段缺失：{key}"
        assert "vector_score" in hit and "keyword_score" in hit and "fused_score" in hit
        assert set(hit["source"]) == {"document_title", "section_path", "page_no", "ordinal"}


def test_source_traces_markdown_section_path(session, rmeta_chunks, settings_env):
    """③-a Markdown 来源：section_path 取自分片自身，page_no 为 None。"""
    settings_env(RAG_HYBRID_ENABLED="false", RAG_CANDIDATE_LIMIT="500")
    hits = _search_hits(session, "部署章节正文：先核对配额再执行扩容动作。")
    target = next(hit for hit in hits if hit.chunk_id == rmeta_chunks["markdown"])
    assert target.source["section_path"] == "部署 > 数据库"
    assert target.source["page_no"] is None, "Markdown 没有页码，不得编造"
    assert target.source["ordinal"] == 0
    # 标题出库再净化：入库/种子里可能残留未脱敏内容，出处是新开的出域面
    assert "ops@corp.local" not in (target.source["document_title"] or ""), (
        "出处字段泄漏了未脱敏的文档标题"
    )


def test_source_traces_pdf_page_number(session, rmeta_chunks, settings_env):
    """③-b PDF 来源：page_no 透出页码（当前无 PDF 摄取路由，字段按模型原样给）。"""
    settings_env(RAG_HYBRID_ENABLED="false", RAG_CANDIDATE_LIMIT="500")
    hits = _search_hits(session, "PDF 页内正文：驱动版本与 CUDA 版本必须匹配。")
    target = next(hit for hit in hits if hit.chunk_id == rmeta_chunks["pdf"])
    assert target.source["page_no"] == 7
    assert target.source["section_path"] == "3 部署", "PDF 页内章节应取自模型列"
    assert target.source["ordinal"] == 1


def test_score_breakdown_is_none_when_hybrid_disabled(session, rmeta_chunks, settings_env):
    """④ 融合关闭：keyword_score / fused_score 必须是 None（不是 0）。"""
    settings_env(RAG_HYBRID_ENABLED="false", RAG_CANDIDATE_LIMIT="500")
    hits = _search_hits(session, "部署章节正文：先核对配额再执行扩容动作。")
    target = next(hit for hit in hits if hit.chunk_id == rmeta_chunks["markdown"])
    assert target.keyword_score is None, "融合关闭时关键词通道未运行，应为 None 而非 0"
    assert target.fused_score is None, "融合关闭时融合分未产生，应为 None 而非 0"
    assert target.vector_score == pytest.approx(target.score), (
        "融合关闭时最终分必须等于向量余弦"
    )

    settings_env(RAG_HYBRID_ENABLED="true", RAG_CANDIDATE_LIMIT="500")
    fused_hits = _search_hits(session, "部署章节正文：先核对配额再执行扩容动作。")
    fused_target = next(hit for hit in fused_hits if hit.chunk_id == rmeta_chunks["markdown"])
    assert fused_target.keyword_score is not None, "融合开启后关键词分必须有值"
    assert fused_target.fused_score == pytest.approx(fused_target.score)


def test_source_never_leaks_beyond_authorized_rows(session, rmeta_chunks, settings_env):
    """⑤ 授权语义不变：出处只能来自已授权候选行，越权分片连出处都不出现。"""
    settings_env(RAG_HYBRID_ENABLED="true", RAG_CANDIDATE_LIMIT="500")
    # 只放行不存在的密级集合：候选集为空 → 命中与出处都是零条
    retriever = SecureRetriever(session)
    hits, meta = retriever.search_with_metadata(
        query="部署章节正文",
        subject=make_subject("governance", "L2_INTERNAL", project_ids=(PROJECT_ID,)),
        allowed_project_ids=[PROJECT_ID],
        allowed_levels=[],
        top_k=10,
        unrestricted=False,
    )
    assert hits == []
    assert meta["keyword_scope"] == "full", "候选集为空不算截断"
