"""BM25 + 向量混合检索回归（P2 接入）。

安全前提（本文件每条用例都在守）：BM25 **只能**在 ``_candidate_ids`` 过滤后的
授权候选集内打分，绝不参与候选集生成——否则「关键词命中」就能把越权分片拉进
结果，等于绕过 P0-5。

融合公式：``final = alpha * cosine_norm + (1 - alpha) * bm25_norm``，
``RAG_MIN_SCORE`` 作用于最终融合分（融合关闭时退化为纯余弦）。

数值说明（离线 embedding 是字符 n-gram 哈希投影，余弦整体偏高、区分度低）：
长分片里的精确错误码会被长文本稀释，余弦反而低于同批短分片——这正是 BM25
要补的召回缺口，也是用例 ①②的构造依据（数值以本文件断言为准）。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.ai.embedding import cosine_similarity, get_embedding_service
from rg_contracts.ai.retrieval import SecureRetriever
from rg_contracts.config import get_settings, reset_settings_cache
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument, new_id, ts
from sqlalchemy import select

PROJECT_ID = "proj_hybrid"
QUERY_TOKEN = "E1001"
QUERY = "E1001"

_FILLER = (
    "巡检流程要求每日核对资源水位与成本中心归属，"
    "对异常增长的实例需在两个工作日内给出处置结论并归档到治理看板。"
)
#: 长分片：精确错误码只出现一次，其余为无关正文 → 向量被稀释（余弦偏低）
LONG_TARGET = _FILLER * 12 + "故障码 E1001 表示磁盘 inode 耗尽，需清理日志分区。" + _FILLER * 12
DISTRACTOR_1 = "资源新增需要核对成本中心标签，确保财务归属正确。"
DISTRACTOR_2 = "网络策略变更需过安全评审，审批通过后方可执行。"
#: 高密级分片：含同一个错误码，用来证明「BM25 命中」不能突破密级过滤
L3_TARGET = "故障码 E1001 的处理流程属于高密级运维手册内容，禁止外传。"


@pytest.fixture
def hybrid_env(monkeypatch):
    """切换检索相关配置；用例结束重置 settings 缓存，避免污染同进程其他用例。"""

    def _apply(**env: str) -> None:
        for key, value in env.items():
            monkeypatch.setenv(key, str(value))
        reset_settings_cache()

    yield _apply
    reset_settings_cache()


@pytest.fixture
def seeded(session):
    """造 3 个 L2 分片（长目标 + 2 个干扰）+ 1 个 L3 分片，返回各自 id。"""
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="混合检索测试文档",
        doc_type="rule",
        project_id=None,
        content="占位内容",
        sanitized=True,
    )
    session.add(doc)
    session.flush()

    embedder = get_embedding_service(get_settings())
    now = ts()

    def _chunk(text: str, ordinal: int, classification: str) -> KnowledgeChunk:
        return KnowledgeChunk(
            document_id=doc.id,
            ordinal=ordinal,
            project_id=PROJECT_ID,
            platform="db",
            classification=classification,
            embedding_text=text,
            display_text=text,
            token_count=len(text),
            embedding_model=embedder.model,
            embedding=embedder.embed(text),
            created_at=now,
        )

    long_chunk = _chunk(LONG_TARGET, 0, "L2_INTERNAL")
    d1 = _chunk(DISTRACTOR_1, 1, "L2_INTERNAL")
    d2 = _chunk(DISTRACTOR_2, 2, "L2_INTERNAL")
    l3 = _chunk(L3_TARGET, 3, "L3_CONFIDENTIAL")
    session.add_all([long_chunk, d1, d2, l3])
    session.commit()
    ids = {
        "long": long_chunk.id,
        "d1": d1.id,
        "d2": d2.id,
        "l3": l3.id,
        "doc": doc.id,
    }

    yield ids

    for chunk in session.execute(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == doc.id)
    ).scalars().all():
        session.delete(chunk)
    session.delete(session.get(KnowledgeDocument, doc.id))
    session.commit()


def _search(session, query: str = QUERY, levels=("L1_PUBLIC", "L2_INTERNAL"), top_k: int = 10) -> list:
    retriever = SecureRetriever(session)
    return retriever.search(
        query=query,
        subject=make_subject("governance", "L2_INTERNAL", project_ids=(PROJECT_ID,)),
        allowed_project_ids=[PROJECT_ID],
        allowed_levels=list(levels),
        top_k=top_k,
        unrestricted=False,
    )


def test_hybrid_promotes_keyword_match_to_top(session, seeded, hybrid_env):
    """① 关键词命中项在纯向量下排不到第一，开启融合后排第一。

    长分片里只出现一次的精确错误码被长文本稀释（余弦低于同批短分片），
    这正是 BM25 要补的召回缺口。
    """
    hybrid_env(RAG_HYBRID_ENABLED="false")
    assert get_settings().RAG_HYBRID_ENABLED is False, "前置：融合开关未生效"
    vector_only = _search(session)
    assert vector_only, "前置：纯向量路径应有命中"
    assert vector_only[0].chunk_id != seeded["long"], (
        "前置不成立：纯向量下长分片已排第一，本用例无法区分融合效果"
    )

    hybrid_env(RAG_HYBRID_ENABLED="true")
    assert get_settings().RAG_HYBRID_ENABLED is True
    fused = _search(session)
    assert fused, "融合后无命中"
    assert fused[0].chunk_id == seeded["long"], (
        f"关键词命中项未升到首位：{[(h.chunk_id, round(h.score, 4)) for h in fused]}"
    )


def test_hybrid_recalls_keyword_match_when_vector_below_threshold(session, seeded, hybrid_env):
    """② 收紧阈值模拟「语义通道打不中」：关融合零召回，开融合命中错误码分片。"""
    strict_score = 0.35
    hybrid_env(RAG_HYBRID_ENABLED="false", RAG_MIN_SCORE=str(strict_score))
    assert get_settings().RAG_MIN_SCORE == strict_score, "前置：阈值未生效"
    assert _search(session) == [], "前置不成立：纯向量在此阈值下仍有命中"

    hybrid_env(RAG_HYBRID_ENABLED="true", RAG_MIN_SCORE=str(strict_score))
    hits = _search(session)
    returned = {hit.chunk_id for hit in hits}
    assert seeded["long"] in returned, "关键词命中项未被融合召回（BM25 未接入链路）"
    assert returned == {seeded["long"]}, f"融合后召回了无关分片：{returned}"


def test_hybrid_never_widens_authorized_candidate_set(session, seeded, hybrid_env):
    """③ 越权分片即使关键词命中最强，也绝不被 BM25 拉进结果（P0-5 不破）。"""
    hybrid_env(RAG_HYBRID_ENABLED="true")
    assert get_settings().RAG_HYBRID_ENABLED is True

    hits = _search(session, levels=("L1_PUBLIC", "L2_INTERNAL"))
    returned = {hit.chunk_id for hit in hits}
    assert seeded["l3"] not in returned, "L3 分片被关键词通道拉进结果（授权预过滤被绕过）"

    # 正向对照：放开密级后同一查询必须命中它 —— 证明「查不到」来自授权过滤，
    # 而不是「文本里根本没有这个错误码」这类空断言。
    opened = _search(session, levels=("L1_PUBLIC", "L2_INTERNAL", "L3_CONFIDENTIAL"))
    assert opened and opened[0].chunk_id == seeded["l3"], (
        "正向对照失败：放开密级后 L3 分片应排首位（用例前提不成立）"
    )


def test_candidate_set_is_capped_by_rag_candidate_limit(session, seeded, hybrid_env):
    """⑤ 候选集规模受 RAG_CANDIDATE_LIMIT 硬上限约束（语料超限时恰为上限值）。

    候选集也是 BM25 的全部语料：截断发生在关键词打分之前，超出上限的分片
    本次既不参与排序、也不进 IDF 统计。
    """
    levels = ("L1_PUBLIC", "L2_INTERNAL")

    def _candidate_count() -> int:
        retriever = SecureRetriever(session)
        return len(
            retriever._candidate_ids(
                allowed_project_ids=[PROJECT_ID],
                allowed_levels=list(levels),
                unrestricted=False,
                limit=100,
            )
        )

    hybrid_env(RAG_CANDIDATE_LIMIT="500")
    uncapped = _candidate_count()
    assert uncapped > 2, f"前置：语料应多于 2 个候选，实际 {uncapped}"

    hybrid_env(RAG_CANDIDATE_LIMIT="2")
    assert get_settings().RAG_CANDIDATE_LIMIT == 2, "前置：上限未生效"
    assert _candidate_count() == 2, (
        f"候选集未受上限约束：期望 2，实际 {uncapped}（RAG_CANDIDATE_LIMIT 未接入）"
    )


def test_hybrid_disabled_keeps_pure_cosine_scoring(session, seeded, hybrid_env):
    """④ 开关关闭时打分与融合前逐位一致：score 就是向量余弦、按余弦降序。"""
    hybrid_env(RAG_HYBRID_ENABLED="false")
    embedder = get_embedding_service(get_settings())
    query_vector = embedder.embed(QUERY)

    hits = _search(session)
    assert hits, "前置：应有命中"
    for hit in hits:
        chunk = session.get(KnowledgeChunk, hit.chunk_id)
        expected = cosine_similarity(query_vector, list(chunk.embedding))
        assert hit.score == pytest.approx(expected), (
            f"融合关闭时 score 必须等于纯向量余弦，实际 {hit.score} vs {expected}"
        )
    # 只断言「最高分在首位」：后续顺序由单项目配额 _apply_diversity 决定
    # （配额溢出项会被追加到末尾），本用例不覆盖多样性语义。
    assert hits[0].score >= max(hit.score for hit in hits[1:]), "首位必须是最高分"
