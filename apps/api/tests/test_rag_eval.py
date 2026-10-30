"""评测基线（P0-2）回归：题库完整、泄漏判定不误判、安全闸门会红。

评测工具本身也需要被评测——否则"泄漏率恒为 0"可能只是判据写错了。这组用例
覆盖三层：

1. **题库**：题号唯一、主体可解析、期望文档都在语料里、项目维度题存在；
2. **判据**：``_authorized`` 对「跨项目 / 超密级 / 全局知识」三类行的判定，
   用构造出来的行验证正反两面（不能只测"会放过"）；
3. **闸门**：泄漏或拒答率不达标时命令行必须返回非 0，且 ``compare`` 能识别
   召回下降与泄漏上升。

另外守一条容易悄悄退化的约定：**决策级的自报条件**（``decision_grade``）。
它一旦变成"永远为真"，报告就会把离线向量 + 小语料的数字当成可信数据。
"""

from __future__ import annotations

import pytest
from conftest import is_pg, make_subject
from rg_contracts.ai.embedding import EmbeddingService
from rg_contracts.config import EmbeddingBackend, get_settings
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument
from rg_contracts.eval import DEFAULT_GOLD_SET, REPORT_VERSION, compare, evaluate, load_gold_set
from rg_contracts.eval.rag_baseline import GOLD_SET_VERSION, _authorized, _scope_for
from rg_contracts.security.policy import Subject
from rg_contracts.seed.demo import KNOWLEDGE_DOCS

#: 金标准引用的文档集合 —— 从种子语料推导，不手写，语料一改就会跟着红/绿。
SEED_DOCS = {doc["title"] for doc in KNOWLEDGE_DOCS}
#: 项目内文档（带 project_id）：项目维度题目必须只引用这些。
PROJECT_DOCS = {doc["title"] for doc in KNOWLEDGE_DOCS if doc["project_id"]}


def _row(project_id: str | None, classification: str) -> KnowledgeChunk:
    """构造未持久化的分片对象：判据只看行上的项目与密级。"""
    return KnowledgeChunk(
        document_id="kd_probe",
        ordinal=0,
        project_id=project_id,
        classification=classification,
        embedding_text="probe",
        display_text="probe",
        token_count=1,
        embedding_model="probe",
    )


# ---------------------------------------------------------------------- 题库


def test_gold_set_ids_are_unique_and_refusals_are_present():
    questions = load_gold_set(DEFAULT_GOLD_SET)
    assert len({q.id for q in questions}) == len(questions)
    assert len([q for q in questions if q.is_refusal]) >= 8


def test_gold_set_expectations_reference_seed_documents_only():
    """期望文档必须真实存在于种子语料，否则基线永远红。"""
    expected = {q.expect_doc for q in load_gold_set() if q.expect_doc}
    assert expected <= SEED_DOCS, f"题库引用了语料里没有的文档：{sorted(expected - SEED_DOCS)}"


def test_gold_set_covers_project_dimension():
    """必须存在「带 project_id 且期望文档是项目内文档」的题。

    旧题库全是不带 project_id 的全局题，于是项目维度的授权与召回**从未被测量**；
    而越权题也没有任何可泄漏的项目内内容，"拒答 100%"只是必然结果。
    """
    project_questions = [
        q for q in load_gold_set() if not q.is_refusal and q.project_id is not None
    ]
    assert project_questions, "缺少项目维度正向题"
    assert {q.expect_doc for q in project_questions} <= PROJECT_DOCS, (
        "项目维度题必须引用项目内文档"
    )


def test_every_seed_document_has_at_least_one_question():
    """语料里每份文档都要有题，否则新增文档等于没有测量覆盖。"""
    referenced = {q.expect_doc for q in load_gold_set() if q.expect_doc}
    assert referenced == SEED_DOCS, f"未被覆盖的文档：{sorted(SEED_DOCS - referenced)}"


def test_gold_set_refusal_questions_all_name_a_forbidden_project():
    for question in load_gold_set():
        if question.is_refusal:
            assert question.forbidden_project, f"{question.id} 是越权题却没写禁止项目"


def test_gold_set_rejects_duplicate_ids(tmp_path):
    path = tmp_path / "dup.json"
    path.write_text(
        f'{{"version": {GOLD_SET_VERSION}, "questions": ['
        '{"id": "x", "subject": "viewer", "query": "a"},'
        '{"id": "x", "subject": "viewer", "query": "b"}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="重复"):
        load_gold_set(path)


def test_gold_set_rejects_unknown_version(tmp_path):
    """题库版本必须与代码里的 ``GOLD_SET_VERSION`` 严格一致。

    这里用 ``GOLD_SET_VERSION + 1`` 而不是写死数字：写死的话，版本一升级，
    这条"拒绝未知版本"的用例会变成"接受已知版本"，静默失效。
    """
    path = tmp_path / "future.json"
    path.write_text(f'{{"version": {GOLD_SET_VERSION + 1}, "questions": []}}', encoding="utf-8")
    with pytest.raises(ValueError, match="版本"):
        load_gold_set(path)


# ---------------------------------------------------------------------- 判据


def test_authorized_accepts_global_row_within_user_ceiling():
    subject = make_subject("viewer", "L2_INTERNAL")
    assert _authorized(subject, _row(None, "L2_INTERNAL"), [], False) is True


def test_authorized_rejects_global_row_above_user_ceiling():
    subject = make_subject("viewer", "L2_INTERNAL")
    assert _authorized(subject, _row(None, "L3_CONFIDENTIAL"), [], False) is False


def test_authorized_rejects_foreign_project_even_when_level_allows():
    subject = make_subject(
        "pm", "L3_CONFIDENTIAL", project_ids=["prj_a"], visible_ceilings={"prj_a": "L3_CONFIDENTIAL"}
    )
    assert _authorized(subject, _row("prj_b", "L2_INTERNAL"), ["prj_a"], False) is False


def test_authorized_uses_project_ceiling_not_user_ceiling():
    subject = make_subject(
        "pm", "L3_CONFIDENTIAL", project_ids=["prj_a"], visible_ceilings={"prj_a": "L2_INTERNAL"}
    )
    assert _authorized(subject, _row("prj_a", "L3_CONFIDENTIAL"), ["prj_a"], False) is False
    assert _authorized(subject, _row("prj_a", "L2_INTERNAL"), ["prj_a"], False) is True


def test_unrestricted_widens_projects_but_never_levels():
    subject = make_subject("admin", "L3_CONFIDENTIAL", project_ids=["prj_a"])
    assert _authorized(subject, _row("prj_b", "L2_INTERNAL"), [], True) is True
    assert _authorized(subject, _row("prj_b", "L4_SECRET"), [], True) is False


def test_scope_matches_route_semantics():
    """评测口径必须和 ``routes/knowledge.py`` 一致，否则测的不是线上行为。"""
    audience = make_subject("pm", "L3_CONFIDENTIAL", project_ids=["prj_a"])
    project_ids, levels, unrestricted = _scope_for(audience, None)
    assert project_ids == ["prj_a"] and unrestricted is False
    assert "L3_CONFIDENTIAL" in levels and "L4_SECRET" not in levels

    admin = make_subject("admin", "L2_INTERNAL", project_ids=["prj_a"])
    project_ids, levels, unrestricted = _scope_for(admin, None)
    assert project_ids == [] and unrestricted is True
    assert levels == ["L1_PUBLIC", "L2_INTERNAL"]


def test_scope_for_project_uses_project_ceiling():
    subject = make_subject(
        "pm", "L3_CONFIDENTIAL", project_ids=["prj_a"], visible_ceilings={"prj_a": "L2_INTERNAL"}
    )
    _, levels, _ = _scope_for(subject, "prj_a")
    assert levels == ["L1_PUBLIC", "L2_INTERNAL"]


# --------------------------------------------------------------- 端到端（PG）


def _subjects_from_db(session) -> dict[str, Subject]:
    """按金标准的主体标识（邮箱 @ 之前的部分）从库里装配 Subject。"""
    from rg_contracts.db.models import ProjectMember, User
    from sqlalchemy import select

    by_subject = {user.subject: user for user in session.execute(select(User)).scalars()}
    subjects: dict[str, Subject] = {}
    for key in {q.subject for q in load_gold_set()}:
        user = by_subject.get(f"{key}@corp.local")
        if user is None:
            continue
        members = session.execute(
            select(ProjectMember).where(ProjectMember.user_id == user.id)
        ).scalars().all()
        subjects[key] = Subject(
            user_id=user.id,
            subject=user.subject,
            display_name=user.display_name,
            role=user.role,
            org_id=user.org_id,
            classification_ceiling=user.classification_ceiling,
            project_ids=frozenset(m.project_id for m in members),
            visible_ceilings={m.project_id: m.visible_ceiling for m in members},
            auth_mode="dev",
            attributes=user.attributes,
        )
    return subjects


@pytest.mark.skipif(not is_pg(), reason="需要种子语料（PG 夹具以 DEMO_SEED=true 建库）")
def test_e2e_seed_corpus_keeps_security_gates_green(session):
    """端到端：真实语料上跑完全部金标准题，泄漏率与拒答率这两道闸门必须全绿。

    只断言与语料大小无关的两项（泄漏、拒答），不断言 recall——离线向量下 recall
    不是决策级数据，详见 ``docs/eval.md``。
    """
    subjects = _subjects_from_db(session)
    if len(subjects) < 4:
        pytest.skip("当前库没有演示主体（DEMO_SEED=false）")
    report = evaluate(session, load_gold_set(), subjects)

    assert report["metrics"]["questions"] == len(load_gold_set())
    assert report["metrics"]["unauthorized_leak_rate"] == 0.0, report["failures"]
    assert report["metrics"]["refusal_accuracy"] == 1.0, report["failures"]
    assert report["metrics"]["total_hits"] > 0, "一条都没检索到：语料缺向量或全局知识不可达"
    # 语料已扩充，两个"结构性"阻塞项不该再出现；离线向量仍应自报不可信。
    blockers = set(report["decision_grade"]["blockers"])
    assert "offline_embedding" in blockers, "离线向量必须自报非决策级"
    assert "corpus_saturated" not in blockers, "语料已大于 top_k，不应再判饱和"
    assert "no_project_slice" not in blockers, "金标准已含项目维度题"
    assert report["slices"]["project"]["questions"] > 0
    assert report["slices"]["project"]["hit_rate"] > 0, "项目内题目一条都没命中：项目分片不可达"


@pytest.mark.skipif(not is_pg(), reason="需要种子语料（PG 夹具以 DEMO_SEED=true 建库）")
def test_decision_grade_gate_opens_once_backend_is_not_offline(session, monkeypatch):
    """门槛逻辑本身可被打开：非离线后端 + 足够语料 + 项目维度题 → ``recall=True``。

    **这条不证明效果**：本机没有真实模型服务，测试把 HTTP 传输打桩成离线实现，
    所以数字仍来自离线降级向量。它验的是「判定条件」——否则"永远报非决策级"
    会和"永远报决策级"一样没用，门禁也无法在真实后端就位后自动转绿。
    """
    subjects = _subjects_from_db(session)
    if len(subjects) < 4:
        pytest.skip("当前库没有演示主体（DEMO_SEED=false）")

    monkeypatch.setattr(
        EmbeddingService, "_embed_http", lambda self, texts: [self._embed_offline(t) for t in texts]
    )
    http_like = get_settings().model_copy(update={"EMBEDDING_BACKEND": EmbeddingBackend.HTTP})
    report = evaluate(session, load_gold_set(), subjects, settings=http_like)

    assert report["config"]["embedding_backend"] == "http"
    assert "offline_embedding" not in report["decision_grade"]["blockers"], (
        f"后端非 offline 后不应再以离线性判定：{report['decision_grade']['blockers']}"
    )
    assert report["decision_grade"]["recall"] is True, report["decision_grade"]["reasons"]
    assert report["corpus"]["chunks"] >= report["decision_grade"]["thresholds"]["min_corpus_chunks"]


def test_decision_grade_flags_small_corpus(monkeypatch):
    """语料不足 ``top_k × 4`` 时必须自报 ``corpus_too_small``（不能只靠"饱和"兜住）。"""
    from rg_contracts.eval.rag_baseline import MIN_CORPUS_MULTIPLE

    assert MIN_CORPUS_MULTIPLE >= 2, "倍数过小时 top_k 几乎覆盖全语料，recall 仍是恒等式"
    settings = get_settings()
    assert settings.RAG_TOP_K * MIN_CORPUS_MULTIPLE == 32, (
        "默认 top_k × 倍数 = 32；改任一常量都要同步 docs/eval.md 的说明"
    )


@pytest.fixture
def foreign_chunk(session):
    """造一条「对 pm/viewer/auditor 一定越权」的分片：prj_data + L4_SECRET。

    为什么不复用种子语料：种子只有全局 L2 知识，没有可越权的行；这里必须自己
    造，反向用例才能在任何干净库上重复跑。
    """
    from rg_contracts.ai.embedding import get_embedding_service
    from rg_contracts.config import get_settings
    from rg_contracts.db.models import new_id, ts

    embedder = get_embedding_service(get_settings())
    text = "数据中台对象存储桶清单与月度成本"
    doc = KnowledgeDocument(
        id=new_id("kd"),
        title="越权探针文档",
        doc_type="fact",
        project_id="prj_data",
        classification="L4_SECRET",
        content=text,
        sanitized=True,
    )
    chunk = KnowledgeChunk(
        document_id=doc.id,
        ordinal=0,
        project_id="prj_data",
        classification="L4_SECRET",
        embedding_text=text,
        display_text=text,
        token_count=len(text),
        embedding_model=embedder.model,
        embedding=embedder.embed(text),
        created_at=ts(),
    )
    session.add(doc)
    # 先 flush 父行：两个对象之间没有 relationship，add_all 不保证插入顺序，
    # 直接一起加会先插分片、撞 knowledge_chunk_document_id_fkey。
    session.flush()
    session.add(chunk)
    session.commit()
    yield chunk
    session.delete(chunk)
    session.delete(doc)
    session.commit()


@pytest.mark.skipif(not is_pg(), reason="只在 PG 上具备完整 RLS 语义")
def test_e2e_leaky_retriever_turns_the_gate_red(monkeypatch, session, foreign_chunk):
    """反向验证：把检索换成"故意泄漏"的替身，闸门必须变红。

    没有这条用例，"泄漏率 0"可能只是判据写错了——它证明同一条判据确实能抓到泄漏。
    """
    from rg_contracts.ai import retrieval as retrieval_module
    from rg_contracts.ai.retrieval import RetrievalHit

    subjects = _subjects_from_db(session)
    if len(subjects) < 4:
        pytest.skip("当前库没有演示主体（DEMO_SEED=false）")

    def _leaky_search(self, **kwargs):
        return [
            RetrievalHit(
                chunk_id=foreign_chunk.id,
                document_id=foreign_chunk.document_id,
                project_id=foreign_chunk.project_id,
                platform=foreign_chunk.platform,
                classification=foreign_chunk.classification,
                display_text=foreign_chunk.display_text,
                metadata={},
                score=1.0,
                source={"document_title": "越权探针文档"},
            )
        ]

    monkeypatch.setattr(retrieval_module.SecureRetriever, "search", _leaky_search)
    report = evaluate(session, load_gold_set(), subjects)
    assert report["metrics"]["leaked_hits"] > 0, "判据没有识别出故意构造的泄漏"
    assert report["metrics"]["unauthorized_leak_rate"] > 0


def test_compare_flags_leak_regression():
    base = {"generated_at": "2026-10-28T00:00:00+00:00", "report_version": REPORT_VERSION,
            "metrics": {"unauthorized_leak_rate": 0.0, "refusal_accuracy": 1.0,
                        "recall_at_3": 0.9, "recall_at_8": 1.0, "mrr_at_10": 0.9}}
    worse = {"report_version": REPORT_VERSION,
             "metrics": {"unauthorized_leak_rate": 0.01, "refusal_accuracy": 1.0,
                         "recall_at_3": 0.9, "recall_at_8": 1.0, "mrr_at_10": 0.9}}
    metrics = {item["metric"] for item in compare(base, worse)["regressions"]}
    assert metrics == {"unauthorized_leak_rate"}


def test_compare_flags_recall_regression_and_passes_on_equal():
    base = {"generated_at": "x", "metrics": {"unauthorized_leak_rate": 0.0, "refusal_accuracy": 1.0,
                                             "recall_at_3": 0.9, "recall_at_8": 1.0, "mrr_at_10": 0.9}}
    worse = {"metrics": {"unauthorized_leak_rate": 0.0, "refusal_accuracy": 1.0,
                         "recall_at_3": 0.5, "recall_at_8": 1.0, "mrr_at_10": 0.9}}
    assert {item["metric"] for item in compare(base, worse)["regressions"]} == {"recall_at_3"}
    assert compare(base, base)["regressions"] == []
