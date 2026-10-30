"""R1（P0-5）回归：unrestricted 不得绕过密级过滤。

缺陷形态：``SecureRetriever._candidate_ids`` 曾把密级过滤写在
``if not unrestricted`` 分支内，导致 unrestricted 令牌（管理员/治理角色）
直接跳过 classification 过滤，高密级分片随全项目范围一起泄漏。

修复后铁律：
- 密级过滤恒生效（与 unrestricted 无关）；
- unrestricted 只放宽项目范围（global 知识可见）；
- allowed_levels 为空 = 无可读密级，直接返回空候选。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.retrieval import RetrievalHit, SecureRetriever
from rg_contracts.config import get_settings
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument, new_id, ts
from rg_contracts.security.policy import Subject
from sqlalchemy import select

QUERY_TEXT = "资源清单与密级治理规则说明"
CHUNK_TEXT = "资源清单与密级治理规则说明"


@pytest.fixture
def seeded_chunks(session):
    """造 3 个分片：proj-a/L2、proj-b/L2、proj-a/L3，返回各 chunk id。"""
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="R1 测试文档",
        doc_type="rule",
        project_id=None,
        content=CHUNK_TEXT,
        sanitized=True,
    )
    session.add(doc)
    session.flush()

    embedder = get_embedding_service(get_settings())
    vector = embedder.embed(CHUNK_TEXT)
    now = ts()

    chunks = [
        KnowledgeChunk(
            document_id=doc.id,
            ordinal=0,
            project_id="proj-a",
            platform="db",
            classification="L2_INTERNAL",
            embedding_text=CHUNK_TEXT,
            display_text=CHUNK_TEXT,
            token_count=len(CHUNK_TEXT),
            embedding_model=embedder.model,
            embedding=vector,
            created_at=now,
        ),
        KnowledgeChunk(
            document_id=doc.id,
            ordinal=1,
            project_id="proj-b",
            platform="db",
            classification="L2_INTERNAL",
            embedding_text=CHUNK_TEXT,
            display_text=CHUNK_TEXT,
            token_count=len(CHUNK_TEXT),
            embedding_model=embedder.model,
            embedding=vector,
            created_at=now,
        ),
        KnowledgeChunk(
            document_id=doc.id,
            ordinal=2,
            project_id="proj-a",
            platform="db",
            classification="L3_CONFIDENTIAL",
            embedding_text=CHUNK_TEXT,
            display_text=CHUNK_TEXT,
            token_count=len(CHUNK_TEXT),
            embedding_model=embedder.model,
            embedding=vector,
            created_at=now,
        ),
    ]
    session.add_all(chunks)
    session.commit()
    ids = {"a_l2": chunks[0].id, "b_l2": chunks[1].id, "a_l3": chunks[2].id}

    yield ids

    # 清理：避免污染同库其他用例
    for chunk in session.execute(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == doc.id)
    ).scalars().all():
        session.delete(chunk)
    session.delete(doc)
    session.commit()


def _subject() -> Subject:
    return make_subject("governance", "L2_INTERNAL", project_ids=("proj-a",))


def _candidates(session, allowed_projects, allowed_levels, unrestricted):
    retriever = SecureRetriever(session)
    return retriever._candidate_ids(
        allowed_project_ids=list(allowed_projects),
        allowed_levels=list(allowed_levels),
        unrestricted=unrestricted,
        limit=100,
    )


def test_candidate_ids_apply_level_filter_even_when_unrestricted(session, seeded_chunks):
    """核心回归：unrestricted=True 时密级过滤仍必须生效（P0-5）。"""
    ids = _candidates(
        session,
        allowed_projects=[],  # 与路由一致：unrestricted 时项目列表传空
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        unrestricted=True,
    )
    assert seeded_chunks["a_l3"] not in ids, "L3 分片绝不允许因 unrestricted 泄漏"
    assert seeded_chunks["a_l2"] in ids
    assert seeded_chunks["b_l2"] in ids, "unrestricted 放宽项目范围：可见全部项目的 L2"


def test_candidate_ids_restricted_scope_keeps_project_and_level_filters(session, seeded_chunks):
    """unrestricted=False 行为不变：项目范围 + 密级双重过滤。"""
    ids = _candidates(
        session,
        allowed_projects=["proj-a"],
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        unrestricted=False,
    )
    assert seeded_chunks["a_l2"] in ids, "授权项目内的 L2 分片必须可见"
    assert seeded_chunks["b_l2"] not in ids, "非授权项目不可见"
    assert seeded_chunks["a_l3"] not in ids, "超出密级上限不可见"


def test_candidate_ids_empty_allowed_levels_returns_empty(session, seeded_chunks):
    """可读密级集合为空 = 直接返回空候选（两种 unrestricted 取值均如此）。"""
    for unrestricted in (True, False):
        ids = _candidates(
            session,
            allowed_projects=["proj-a"],
            allowed_levels=[],
            unrestricted=unrestricted,
        )
        assert ids == [], f"unrestricted={unrestricted} 时 allowed_levels 为空必须返回 []"


def test_search_never_returns_chunk_above_ceiling_when_unrestricted(session, seeded_chunks):
    """端到端：unrestricted 检索结果中不得出现 L3 分片。"""
    retriever = SecureRetriever(session)
    hits = retriever.search(
        query=QUERY_TEXT,
        subject=_subject(),
        allowed_project_ids=[],  # 与路由一致：unrestricted 时传空
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        top_k=10,
        unrestricted=True,
    )
    returned_ids = {hit.chunk_id for hit in hits}
    assert seeded_chunks["a_l3"] not in returned_ids, "unrestricted 检索泄漏了 L3 分片"
    assert all(hit.classification in {"L1_PUBLIC", "L2_INTERNAL"} for hit in hits)


# --------------------------------------------------- 全局知识可达性（基线发现）


@pytest.fixture
def global_and_project_chunks(session):
    """造 3 个全局分片 + 2 个项目内分片，用于验证「无项目授权」与配额口径。"""
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="全局治理规则（可达性测试）",
        doc_type="rule",
        project_id=None,
        content="全局治理规则",
        sanitized=True,
    )
    session.add(doc)
    session.flush()

    embedder = get_embedding_service(get_settings())
    text = "资源清单与密级治理规则说明"
    vector = embedder.embed(text)
    now = ts()
    chunks = [
        KnowledgeChunk(
            document_id=doc.id,
            ordinal=index,
            project_id=None,
            classification="L2_INTERNAL",
            embedding_text=text,
            display_text=text,
            token_count=len(text),
            embedding_model=embedder.model,
            embedding=vector,
            created_at=now,
        )
        for index in range(3)
    ] + [
        KnowledgeChunk(
            document_id=doc.id,
            ordinal=10 + index,
            project_id="proj-a",
            classification="L2_INTERNAL",
            embedding_text=text,
            display_text=text,
            token_count=len(text),
            embedding_model=embedder.model,
            embedding=vector,
            created_at=now,
        )
        for index in range(2)
    ]
    session.add_all(chunks)
    session.commit()

    yield {"global": [c.id for c in chunks[:3]], "project": [c.id for c in chunks[3:]]}

    for chunk in session.execute(
        select(KnowledgeChunk).where(KnowledgeChunk.document_id == doc.id)
    ).scalars().all():
        session.delete(chunk)
    session.delete(doc)
    session.commit()


def test_global_knowledge_is_reachable_without_any_project(session, global_and_project_chunks):
    """没有项目授权的用户（如只读岗）必须能检索到全局知识。

    缺陷形态：``_candidate_ids_with_scope`` 曾在 ``allowed_project_ids`` 为空时
    直接返回空候选，把 ``project_id IS NULL`` 的全局治理规则一并挡掉——而这份
    知识正是无项目授权用户唯一该看到的内容。40 题基线实测该早退让 recall@8
    从 1.0 掉到 0.5（32 道正向题里 16 道 0 命中）。
    """
    retriever = SecureRetriever(session)
    ids = retriever._candidate_ids(
        allowed_project_ids=[],  # 无任何项目授权
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        unrestricted=False,
        limit=100,
    )
    assert set(global_and_project_chunks["global"]).issubset(set(ids))
    assert not set(global_and_project_chunks["project"]) & set(ids), "无项目授权不得看到项目内分片"


def test_global_hits_are_not_capped_by_project_quota(session, global_and_project_chunks):
    """全局知识不受「单项目 2 片」配额约束，项目内仍是每项目 2 片。

    缺陷形态：配额曾把 ``project_id or "global"`` 当成一个项目，导致全局知识的
    结果上限恒为 ``RAG_MAX_CHUNKS_PER_PROJECT``（默认 2），recall@8 实测被压到
    0.9062：3 道题的正确文档全部落在配额之外。
    """
    retriever = SecureRetriever(session)
    hits = retriever.search(
        query="资源清单与密级治理规则说明",
        subject=make_subject("viewer", "L2_INTERNAL"),
        allowed_project_ids=["proj-a"],
        allowed_levels=["L1_PUBLIC", "L2_INTERNAL"],
        top_k=10,
    )
    returned = {hit.chunk_id for hit in hits}
    # 三个全局分片必须全部出现在结果里；旧实现只留 2 条，第三个会被配额丢掉
    assert set(global_and_project_chunks["global"]) <= returned, "全局知识被项目配额压掉了"
    project_hits = [h for h in hits if h.project_id == "proj-a"]
    assert len(project_hits) <= 2, f"项目内配额被突破，实际 {len(project_hits)} 片"


# --------------------------------------------------- 项目保底（拼图覆盖度回归）


def _hit(chunk_id: str, project_id: str | None, score: float) -> RetrievalHit:
    """构造最小命中对象：这里只验证结果集构成，不需要真实向量。"""
    return RetrievalHit(
        chunk_id=chunk_id,
        document_id="kd_test",
        project_id=project_id,
        platform=None,
        classification="L2_INTERNAL",
        score=score,
        display_text="文本",
        metadata={},
    )


def _diverse(hits: list[RetrievalHit], limit: int) -> list[RetrievalHit]:
    """只测结果集构成：绕过 __init__（不打向量模型、不需要数据库会话）。"""
    retriever = SecureRetriever.__new__(SecureRetriever)
    retriever.settings = get_settings()
    return retriever._apply_diversity(hits, limit)


def test_project_hit_survives_when_global_scores_are_higher():
    """全局知识分值全高于项目分片时，项目仍必须保留至少 1 条。

    缺陷形态：放开全局配额后（见上一条用例）出现过反向问题——``top_k`` 较小时
    高分全局分片把项目分片整段挤出结果集，于是「项目内检索拿不到项目自己的
    分片」，拼图防护按项目统计的覆盖率也不再累积。实测于
    ``test_jigsaw::test_repeated_search_eventually_downgrades``（top_k=6 时
    覆盖率始终不上升，``coarsen`` 永不触发）。
    """
    hits = [
        _hit("g1", None, 0.90),
        _hit("g2", None, 0.85),
        _hit("g3", None, 0.80),
        _hit("a1", "proj-a", 0.50),
        _hit("a2", "proj-a", 0.45),
        _hit("b1", "proj-b", 0.40),
    ]
    selected = _diverse(hits, limit=4)
    chunk_ids = [hit.chunk_id for hit in selected]
    assert len(selected) == 4, f"结果条数异常：{chunk_ids}"
    # 保底 1 条（limit // 4 = 1），由分值最高的项目（proj-a）获得
    assert "a1" in chunk_ids, f"全局高分把项目分片挤掉了：{chunk_ids}"
    # 其余预算仍按相关性给全局，不被保底挤占
    assert {"g1", "g2", "g3"} <= set(chunk_ids), chunk_ids
    # 结果按分值降序，保底不等于「插到队头」
    assert [hit.score for hit in selected] == sorted(
        (hit.score for hit in selected), reverse=True
    )


def test_project_reserve_is_capped_and_never_exceeds_limit():
    """保底总数上限 ``limit // 4``：limit=2 时只保 1 个项目，且不超输出上限。"""
    hits = [
        _hit("g1", None, 0.90),
        _hit("a1", "proj-a", 0.50),
        _hit("b1", "proj-b", 0.45),
        _hit("c1", "proj-c", 0.40),
    ]
    selected = _diverse(hits, limit=2)
    chunk_ids = [hit.chunk_id for hit in selected]
    assert len(selected) == 2, chunk_ids
    assert "a1" in chunk_ids, f"limit=2 时仍应保留最高分项目的一条：{chunk_ids}"


def test_no_project_hits_means_globals_fill_the_budget():
    """没有项目命中时保底预算整段让给全局知识，不出现空位。"""
    hits = [_hit(f"g{index}", None, 0.9 - index * 0.05) for index in range(5)]
    selected = _diverse(hits, limit=4)
    assert [hit.chunk_id for hit in selected] == ["g0", "g1", "g2", "g3"]
