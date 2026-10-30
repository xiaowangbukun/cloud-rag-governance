"""检索质量与授权泄漏的评测基线（P0-2）。

为什么需要它
------------
``RAG_HYBRID_ENABLED`` 至今默认关闭，注释里的理由是「没有 recall 对照数据」
（``config.py`` L176–183）。同样地，「检索只会返回授权分片」此前只是设计
声明——``ai/retrieval.py`` 的过滤条件写对了，但没有任何测量能证明它写对了。

本模块提供两件可重复的事：

1. **授权泄漏测量**：把检索结果逐条对照「独立算出来的授权边界」复核，
   而不是复用检索自身的 WHERE。检索漏写条件时，这里会红。
2. **召回基线**：固定金标准题库，记录 ``recall@3 / recall@8 / MRR@10``，
   用于「改召回前后有没有变差」的对照，而不是用来宣称效果多好。

口径上的四条自觉
----------------
* **用系统会话跑**（``session_scope``）：RLS 是第二道防线，如果评测也走 RLS
  作用域，泄漏会被数据库提前挡掉、指标恒为 0，等于测不出应用层的疏漏。
  这里刻意只测「应用层过滤」这一层；第二道防线由 ``tests/test_rls.py`` 单独证明。
* **离线向量不算决策级数据**：内置离线降级向量（任意两文本余弦 0.06~0.18）
  排序基本是噪声。报告里带 ``decision_grade.blockers``，不把这种数字当收益证据。
* **饱和的指标不是指标**：语料分片数若不足 ``top_k × MIN_CORPUS_MULTIPLE``，
  ``recall@k`` 就接近恒等式（旧基线 6 分片 vs top_k=8 时任何实现都拿 1.0）。
  这类报告单独标 ``corpus_too_small`` / ``corpus_saturated``。
* **维度必须分开看**：全局题与项目内题分开统计（``slices``）。合并后的单一
  recall 会掩盖「项目维度整体失效」——旧基线全是全局题，项目维度从未被测量。
* **拒答的定义要写清楚**：本系统没有生成环节参与评测，"拒答"指**检索没有
  返回越权对象的事实**——越权问题返回全局规则文档是允许的，返回该项目/该
  密级的实际内容才是失败。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rg_contracts.ai.embedding import EmbeddingService
from rg_contracts.ai.retrieval import SecureRetriever
from rg_contracts.config import EmbeddingBackend, Settings, get_settings
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument
from rg_contracts.enums import classification_rank
from rg_contracts.logging_setup import get_logger
from rg_contracts.security.policy import Subject, levels_at_or_below

logger = get_logger(__name__)

DEFAULT_GOLD_SET = Path(__file__).with_name("gold_set.json")

#: 报告版本：字段增删时递增，便于比对历史基线时识别口径变化。
#: v2 增加 ``slices``（分片指标）与 ``decision_grade.blockers``（机器可读阻塞项），
#: 并把「语料太小」从饱和里拆出来单独判定。
REPORT_VERSION = 2

#: 决策级召回对语料规模的最低要求（相对 ``top_k`` 的倍数）。
#:
#: 为什么是 4：``recall@k`` 只在「正确文档并非必然进入前 k 名」时才有区分度。
#: 语料等于 ``top_k`` 时（旧基线 6 分片 vs top_k=8）任何实现都拿满分，指标是
#: 恒等式而不是测量。取 4 倍是让 ``top_k`` 至多覆盖语料四分之一——仍不算严格，
#: 但足以让"排序有没有变差"这件事可被观测；这不是统计显著性阈值。
MIN_CORPUS_MULTIPLE = 4

#: 金标准题库格式版本。与 ``REPORT_VERSION`` **分开**：题库结构变了要连带重写
#: 报告口径，但两者递增的时机不同（题库增题不必改报告字段），混用一个常量会
#: 让"版本不一致"这件事失去指向性。
GOLD_SET_VERSION = 2


@dataclass(frozen=True)
class GoldQuestion:
    """一道金标准题。

    - 正向题：``expect_doc`` 给出唯一正确的文档标题，命中即算召回；
    - 越权题：``forbidden_project`` 给出不该出现事实的项目，返回该项目内容即失败；
    - 两字段都为空的题按「应当零结果」处理。
    """

    id: str
    subject: str
    query: str
    expect_doc: str | None = None
    forbidden_project: str | None = None
    project_id: str | None = None
    note: str = ""

    @property
    def is_refusal(self) -> bool:
        return self.expect_doc is None


def load_gold_set(path: Path | str | None = None) -> list[GoldQuestion]:
    payload = json.loads(Path(path or DEFAULT_GOLD_SET).read_text(encoding="utf-8"))
    if payload.get("version") != GOLD_SET_VERSION:
        raise ValueError(
            f"金标准版本不支持: {payload.get('version')}（期望 {GOLD_SET_VERSION}）"
        )
    questions = [GoldQuestion(**item) for item in payload["questions"]]
    ids = [q.id for q in questions]
    if len(set(ids)) != len(ids):
        raise ValueError("金标准题号重复，基线不可比对")
    return questions


# ------------------------------------------------------------------ 授权口径


def _scope_for(subject: Subject, project_id: str | None) -> tuple[list[str], list[str], bool]:
    """与 ``routes/knowledge.py`` 的受控检索同口径（项目集合 + 密级集合 + 是否放开项目）。"""
    unrestricted = subject.role in ("admin", "governance")
    project_ids = [] if unrestricted else sorted(subject.project_ids)
    ceiling = subject.ceiling_for(project_id) if project_id else subject.classification_ceiling
    return project_ids, levels_at_or_below(ceiling), unrestricted


def _authorized(subject: Subject, row: KnowledgeChunk, project_ids: Sequence[str], unrestricted: bool) -> bool:
    """复核单条命中是否在授权范围内（独立于检索 SQL 的第二套判断）。

    全局知识（``project_id`` 为空）对所有人可见，但密级仍按用户总体上限判定；
    项目内知识按「用户上限 ∩ 项目上限」判定。
    """
    row_project = row.project_id
    if row_project is None:
        level_ok = classification_rank(row.classification) <= classification_rank(
            subject.classification_ceiling
        )
        return level_ok
    if not unrestricted and row_project not in project_ids:
        return False
    return classification_rank(row.classification) <= classification_rank(subject.ceiling_for(row_project))


# ---------------------------------------------------------------------- 评估


@dataclass
class _QuestionResult:
    id: str
    subject: str
    query: str
    hit_count: int
    expected_rank: int | None = None
    leaked: int = 0
    refusal_ok: bool = True
    forbidden_hits: int = 0
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject": self.subject,
            "query": self.query,
            "hits": self.hit_count,
            "expected_rank": self.expected_rank,
            "leaked": self.leaked,
            "refusal_ok": self.refusal_ok,
            "forbidden_hits": self.forbidden_hits,
        }


def evaluate(
    session: Session,
    questions: Sequence[GoldQuestion],
    subjects: Mapping[str, Subject],
    settings: Settings | None = None,
    hybrid: bool | None = None,
) -> dict[str, Any]:
    """跑一遍金标准，返回可直接落盘/比对的结构化报告。

    Args:
        session: **系统会话**（见模块 docstring，不能是请求作用域会话）。
        questions: 金标准题。
        subjects: ``subject -> Subject``，由调用方从目录数据构造。
        settings: 覆盖配置（评测用独立 Settings 时传入）。
        hybrid: 显式覆盖 ``RAG_HYBRID_ENABLED``，用于「开/关」对照；None 用配置值。
    """
    base = settings or get_settings()
    settings = base.model_copy(update={"RAG_HYBRID_ENABLED": hybrid}) if hybrid is not None else base
    # 刻意**不用** ``get_embedding_service(settings)``：那个单例只认第一次传入的
    # settings，之后传什么都返回同一个实例。评测的 ``settings`` 覆盖正是为了做
    # 「后端/维度」对照，若拿单例，报告里的 ``embedding_backend`` 会与实际算向量的
    # 实现不一致——那是最坏的一种假绿：配置写着 http，向量其实是离线降级。
    retriever = SecureRetriever(session, settings, EmbeddingService(settings))
    top_k = settings.RAG_TOP_K

    rows: list[_QuestionResult] = []
    total_hits = 0
    total_leaked = 0
    started = time.perf_counter()
    for question in questions:
        subject = subjects.get(question.subject)
        if subject is None:
            raise KeyError(f"金标准引用了未知主体: {question.subject}")
        project_ids, allowed_levels, unrestricted = _scope_for(subject, question.project_id)
        hits = retriever.search(
            query=question.query,
            subject=subject,
            allowed_project_ids=project_ids,
            allowed_levels=allowed_levels,
            top_k=top_k,
            unrestricted=unrestricted,
        )
        chunk_ids = [hit.chunk_id for hit in hits]
        chunk_rows = {
            row.id: row
            for row in session.execute(
                select(KnowledgeChunk).where(KnowledgeChunk.id.in_(chunk_ids))
            ).scalars()
        } if chunk_ids else {}

        leaked = sum(
            1
            for hit in hits
            if hit.chunk_id in chunk_rows
            and not _authorized(subject, chunk_rows[hit.chunk_id], project_ids, unrestricted)
        )
        forbidden_hits = sum(
            1 for hit in hits if question.forbidden_project and hit.project_id == question.forbidden_project
        )

        expected_rank = None
        if question.expect_doc:
            for rank, hit in enumerate(hits, start=1):
                if (hit.source or {}).get("document_title") == question.expect_doc:
                    expected_rank = rank
                    break

        if question.is_refusal:
            # 越权题：既不返回越权对象的事实，也不返回任何未授权分片
            refusal_ok = forbidden_hits == 0 and leaked == 0
        else:
            refusal_ok = True

        total_hits += len(hits)
        total_leaked += leaked
        rows.append(
            _QuestionResult(
                id=question.id,
                subject=question.subject,
                query=question.query,
                hit_count=len(hits),
                expected_rank=expected_rank,
                leaked=leaked,
                refusal_ok=refusal_ok,
                forbidden_hits=forbidden_hits,
                note=question.note,
            )
        )

    positive = [r for r, q in zip(rows, questions) if not q.is_refusal]
    refusals = [r for r, q in zip(rows, questions) if q.is_refusal]
    # 分片：全局题（不带 project_id）与项目内题分开统计。合在一起的 recall 会
    # 掩盖「某一维度整体失效」——旧基线全是全局题，项目维度从未被测量过。
    global_positive = [r for r, q in zip(rows, questions) if not q.is_refusal and q.project_id is None]
    project_positive = [r for r, q in zip(rows, questions) if not q.is_refusal and q.project_id]

    def _recall(k: int) -> float:
        if not positive:
            return 0.0
        return round(
            sum(1 for r in positive if r.expected_rank is not None and r.expected_rank <= k) / len(positive),
            4,
        )

    def _slice(results: Sequence[_QuestionResult]) -> dict[str, Any]:
        """单组题目的指标（空组返回 0，不返回 None，避免"未测量"被当成"满分"）。"""
        if not results:
            return {"questions": 0, "recall_at_8": 0.0, "mrr_at_10": 0.0, "hit_rate": 0.0}
        hits = sum(1 for r in results if r.expected_rank is not None)
        return {
            "questions": len(results),
            "recall_at_8": round(
                sum(1 for r in results if r.expected_rank is not None and r.expected_rank <= 8) / len(results),
                4,
            ),
            "mrr_at_10": round(
                sum(1.0 / r.expected_rank for r in results if r.expected_rank) / len(results), 4
            ),
            "hit_rate": round(hits / len(results), 4),
        }

    mrr = _slice(positive)["mrr_at_10"]

    corpus_chunks = int(session.execute(select(func.count()).select_from(KnowledgeChunk)).scalar_one())
    corpus_docs = int(session.execute(select(func.count()).select_from(KnowledgeDocument)).scalar_one())

    saturated = corpus_chunks <= top_k
    min_corpus = top_k * MIN_CORPUS_MULTIPLE
    # 阻塞项用机器可读代码，理由用人话：代码可被门禁判断（``--require-decision-grade``），
    # 理由给人看。两者必须一一对应，不能只在文档里写"不可信"却让报告看着像绿的。
    blockers: list[str] = []
    reasons: list[str] = []
    if settings.EMBEDDING_BACKEND is EmbeddingBackend.OFFLINE:
        blockers.append("offline_embedding")
        reasons.append("embedding 后端为 offline 降级向量（任意两文本余弦 0.06~0.18），排序近似噪声")
    if saturated:
        blockers.append("corpus_saturated")
        reasons.append(f"语料仅 {corpus_chunks} 个分片 ≤ top_k={top_k}，recall@{top_k} 必然饱和")
    elif corpus_chunks < min_corpus:
        blockers.append("corpus_too_small")
        reasons.append(
            f"语料 {corpus_chunks} 个分片不足 top_k×{MIN_CORPUS_MULTIPLE}={min_corpus}，"
            "排序质量与 top_k 覆盖范围不足以区分实现差异"
        )
    if not project_positive:
        blockers.append("no_project_slice")
        reasons.append("金标准没有带 project_id 的正向题，项目维度授权与召回从未被测量")

    return {
        "report_version": REPORT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": {
            "hybrid": settings.RAG_HYBRID_ENABLED,
            "hybrid_alpha": settings.RAG_HYBRID_ALPHA,
            "min_score": settings.RAG_MIN_SCORE,
            "top_k": top_k,
            "embedding_backend": settings.EMBEDDING_BACKEND.value,
            "embedding_model": settings.EMBEDDING_MODEL,
        },
        "corpus": {
            "documents": corpus_docs,
            "chunks": corpus_chunks,
            "saturated": saturated,
            "min_for_decision_grade": min_corpus,
            "project_chunks": int(
                session.execute(
                    select(func.count()).select_from(KnowledgeChunk).where(
                        KnowledgeChunk.project_id.is_not(None)
                    )
                ).scalar_one()
            ),
        },
        "metrics": {
            "questions": len(rows),
            "positive_questions": len(positive),
            "refusal_questions": len(refusals),
            "recall_at_3": _recall(3),
            "recall_at_8": _recall(top_k),
            "mrr_at_10": mrr,
            "total_hits": total_hits,
            "leaked_hits": total_leaked,
            "unauthorized_leak_rate": round(total_leaked / total_hits, 4) if total_hits else 0.0,
            "refusal_accuracy": round(
                sum(1 for r in refusals if r.refusal_ok) / len(refusals), 4
            ) if refusals else 1.0,
        },
        "slices": {
            "global": _slice(global_positive),
            "project": _slice(project_positive),
            "refusal": {
                "questions": len(refusals),
                "refusal_accuracy": round(
                    sum(1 for r in refusals if r.refusal_ok) / len(refusals), 4
                ) if refusals else 1.0,
                "forbidden_hits": sum(r.forbidden_hits for r in refusals),
            },
        },
        "decision_grade": {
            "recall": not blockers,
            "blockers": blockers,
            "reasons": reasons,
            "thresholds": {"top_k": top_k, "min_corpus_chunks": min_corpus},
        },
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "failures": [
            result.as_dict()
            for result, question in zip(rows, questions)
            if (not result.refusal_ok) or (not question.is_refusal and result.expected_rank is None)
        ],
        "results": [r.as_dict() for r in rows],
    }


def compare(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """与历史基线对比；返回回归项清单（空列表表示没有变差）。"""
    regressions: list[dict[str, Any]] = []
    b, c = baseline["metrics"], current["metrics"]
    if c["unauthorized_leak_rate"] > b["unauthorized_leak_rate"]:
        regressions.append(
            {
                "metric": "unauthorized_leak_rate",
                "baseline": b["unauthorized_leak_rate"],
                "current": c["unauthorized_leak_rate"],
            }
        )
    if c["refusal_accuracy"] < b["refusal_accuracy"]:
        regressions.append(
            {
                "metric": "refusal_accuracy",
                "baseline": b["refusal_accuracy"],
                "current": c["refusal_accuracy"],
            }
        )
    for key in ("recall_at_3", "recall_at_8", "mrr_at_10"):
        if c[key] < b[key]:
            regressions.append({"metric": key, "baseline": b[key], "current": c[key]})
    return {"regressions": regressions, "baseline_generated_at": baseline.get("generated_at")}
