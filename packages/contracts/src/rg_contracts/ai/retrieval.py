"""受控检索层。

铁律：先按授权过滤出「候选 ID 集合」，再做向量相似度排序。
绝不先召回全库再在应用层过滤，否则未授权分片的向量信息已被计算并可能被推导。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sqlalchemy import bindparam, func, or_, select, text
from sqlalchemy.orm import Session

from rg_contracts.ai.bm25 import BM25Index, tokenize
from rg_contracts.ai.embedding import EmbeddingService, cosine_similarity, get_embedding_service
from rg_contracts.config import Settings, get_settings
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument
from rg_contracts.db.vector import EMBEDDING_DIM_HINT, Vector
from rg_contracts.security.policy import Subject
from rg_contracts.security.sanitize import Sanitizer


@dataclass
class RetrievalHit:
    chunk_id: str
    document_id: str
    project_id: str | None
    platform: str | None
    classification: str
    score: float
    display_text: str
    metadata: dict
    # ---- 以下为响应补全新增字段（纯增补，既有序字段与语义不动）
    # 各通道打分明细：融合关闭时 keyword_score / fused_score 为 None
    # （None = 该通道未启用；**不用 0 冒充** —— 0 是合法分数，会让人误以为
    # 通道跑了但打了 0 分，排查时会走错方向）。
    vector_score: float | None = None
    keyword_score: float | None = None
    fused_score: float | None = None
    # 出处溯源：{document_title, section_path, page_no, ordinal}
    source: dict | None = None

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "project_id": self.project_id,
            "platform": self.platform,
            "classification": self.classification,
            "score": round(self.score, 4),
            "text": self.display_text,
            "metadata": self.metadata,
            "vector_score": None if self.vector_score is None else round(self.vector_score, 4),
            "keyword_score": None if self.keyword_score is None else round(self.keyword_score, 4),
            "fused_score": None if self.fused_score is None else round(self.fused_score, 4),
            "source": self.source,
        }


class SecureRetriever:
    def __init__(
        self,
        session: Session,
        settings: Settings | None = None,
        embedder: EmbeddingService | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.embedder = embedder or get_embedding_service(self.settings)

    # ------------------------------------------------------------- write path
    def upsert_chunk(self, chunk: KnowledgeChunk, vector: Sequence[float]) -> None:
        chunk.embedding = list(vector)
        chunk.embedding_model = self.embedder.model
        self.session.merge(chunk)

    def delete_document_chunks(self, document_id: str) -> int:
        rows = self.session.execute(
            select(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalars().all()
        for row in rows:
            self.session.delete(row)
        return len(rows)

    # -------------------------------------------------------------- read path
    def search(
        self,
        query: str,
        subject: Subject,
        allowed_project_ids: Sequence[str] | None,
        allowed_levels: Sequence[str] | None,
        top_k: int | None = None,
        unrestricted: bool = False,
    ) -> list[RetrievalHit]:
        """检索入口（只返回命中）。需要响应元数据时用 ``search_with_metadata``。"""
        hits, _meta = self.search_with_metadata(
            query=query,
            subject=subject,
            allowed_project_ids=allowed_project_ids,
            allowed_levels=allowed_levels,
            top_k=top_k,
            unrestricted=unrestricted,
        )
        return hits

    def search_with_metadata(
        self,
        query: str,
        subject: Subject,
        allowed_project_ids: Sequence[str] | None,
        allowed_levels: Sequence[str] | None,
        top_k: int | None = None,
        unrestricted: bool = False,
    ) -> tuple[list[RetrievalHit], dict]:
        """检索入口：授权预过滤 →（可选）BM25 与向量融合排序 → 阈值 → 多样性配额。

        allowed_* 必须由策略层计算后传入。

        **阈值语义**（避免后人误解）：``RAG_MIN_SCORE`` 作用于**最终融合分**，
        不对向量通道单独设阈。融合关闭时融合分退化为向量余弦，语义与历史一致；
        融合开启时向量对融合分的贡献是 ``alpha * cosine``，等价于对余弦设了
        ``RAG_MIN_SCORE / alpha`` 的隐含下限（alpha=0.6 → 0.083）—— 这是刻意
        的单一阈值模型：**改 alpha 会同时改到召回门槛**，调参时必须连
        RAG_MIN_SCORE 一起复核，不要只动一边。

        **授权语义不变**（P0-5）：候选集只由 ``_candidate_ids`` 的密级/项目
        过滤决定；BM25 只在该候选集内部打分，既不扩大也不缩小候选集。

        Returns:
            (命中列表, 响应元数据)。元数据当前只含 ``keyword_scope``：

            * ``"truncated"``：库里匹配的授权分片多于 ``count_taken``，即本次
              **没看全**——关键词通道只在这批候选里排序，语料更多的分片没参与
              本次排序，调用方不得据此判定"库里没有"（防假阴性）。截断来自硬
              上限还是预取量对调用方都一样，都是没看全。
            * ``"full"``：候选集完整。

            三个数量的关系（预取量 / 硬上限 / 实际取用）见
            ``_candidate_ids_with_scope`` 的 docstring。
        """
        limit = top_k or self.settings.RAG_TOP_K
        query_vector = self.embedder.embed(query)

        candidate_ids, truncated = self._candidate_ids_with_scope(
            allowed_project_ids=list(allowed_project_ids or []),
            allowed_levels=list(allowed_levels or []),
            unrestricted=unrestricted,
            # 预取量：候选集还要给 BM25 当语料、给多样性配额留余量，
            # 故按 top_k 放大；真正的硬上限在 _candidate_ids_with_scope 里
            # 由 RAG_CANDIDATE_LIMIT 兜住（两者取小）。
            limit=max(limit * 20, 200),
            query=query,
            query_vector=query_vector,
        )
        metadata = {"keyword_scope": "truncated" if truncated else "full"}
        if not candidate_ids:
            return [], metadata

        rows = self._ranked_rows(candidate_ids, query_vector, fetch=max(limit * 20, 200))
        # BM25 的语料就是「已授权候选集」本身：IDF 只在候选集内统计，全库 IDF
        # 会把未授权分片的词频信息带进打分（等于绕过授权预过滤）。
        keyword_scores = self._bm25_scores(query, rows)
        titles = self._document_titles({row.document_id for row in rows})
        hybrid = self.settings.RAG_HYBRID_ENABLED
        hits: list[RetrievalHit] = []
        for row in rows:
            vector = row.embedding
            if not vector:
                continue
            vector_score = cosine_similarity(query_vector, list(vector))
            score = self._fused_score(vector_score, keyword_scores.get(row.id, 0.0))
            if score < self.settings.RAG_MIN_SCORE:
                continue
            hits.append(
                RetrievalHit(
                    chunk_id=row.id,
                    document_id=row.document_id,
                    project_id=row.project_id,
                    platform=row.platform,
                    classification=row.classification,
                    score=score,
                    display_text=row.display_text,
                    metadata=row.metadata_json,
                    vector_score=vector_score,
                    # 融合关闭时关键词/融合通道未运行 → None（不是 0）
                    keyword_score=keyword_scores.get(row.id) if hybrid else None,
                    fused_score=score if hybrid else None,
                    source=self._source_of(row, titles),
                )
            )

        hits.sort(key=lambda h: h.score, reverse=True)
        return self._apply_diversity(hits, limit), metadata

    # ---------------------------------------------------------------- helpers
    def _document_titles(self, document_ids: set[str]) -> dict[str, str]:
        """取命中分片的文档标题（出库前再净化一次）。

        入库时标题已走脱敏（``knowledge.py`` 的 ``safe_title``），这里再净化
        一次是兜住**修复前已落库的历史标题**（与 ``list_documents`` 同一口径）：
        出处字段是新开的出域面，不能成为未脱敏内容的出口。
        """
        if not document_ids:
            return {}
        rows = self.session.execute(
            select(KnowledgeDocument.id, KnowledgeDocument.title).where(
                KnowledgeDocument.id.in_(document_ids)
            )
        ).all()
        sanitizer = Sanitizer(self.settings)
        return {row.id: sanitizer.sanitize_text(row.title or "").text for row in rows}

    def _source_of(self, row: KnowledgeChunk, titles: dict[str, str]) -> dict:
        """出处溯源：{document_title, section_path, page_no, ordinal}。

        * ``section_path``：只读 ``knowledge_chunk.section_path`` **列**（D1 之后
          这是唯一真值源）。历史行若只有 ``metadata_json`` 里的旧值，由
          ``startup.backfill_chunk_section_path`` 一次性回填到列——读取侧不做
          回退，避免两个真值源长期并存。
        * ``page_no``：只有 PDF 摄取才有（Markdown / 文本提交为 None），
          按模型列原样透出，不编造页码。
        """
        return {
            "document_title": titles.get(row.document_id),
            "section_path": row.section_path,
            "page_no": row.page_no,
            "ordinal": row.ordinal,
        }

    def _bm25_scores(self, query: str, rows: Sequence[KnowledgeChunk]) -> dict[str, float]:
        """对已授权候选集算 BM25 并归一化到 [0,1]（除以候选集内最高分）。

        输入 ``rows`` 必须是 ``_candidate_ids`` 过滤后的分片：本方法只打分，
        不参与候选集生成——关键词命中不能让越权分片进入结果。

        Returns:
            {chunk_id: 归一化分数}；融合关闭或无候选时返回空 dict（调用方按 0 分处理）。
        """
        if not self.settings.RAG_HYBRID_ENABLED or not rows:
            return {}
        raw_scores = BM25Index([row.embedding_text or "" for row in rows]).score(query)
        if not raw_scores:
            return {}
        peak = max(raw_scores)
        if peak <= 0.0:
            # 关键词通道整体没命中：全 0 而不是除零；融合分此时只剩向量分量
            return {row.id: 0.0 for row in rows}
        return {row.id: value / peak for row, value in zip(rows, raw_scores)}

    def _fused_score(self, vector_score: float, keyword_score: float) -> float:
        """把向量余弦与归一化 BM25 合成最终分（阈值作用在返回值上）。

        融合关闭时原样返回向量余弦，保证与历史行为逐位一致。
        """
        if not self.settings.RAG_HYBRID_ENABLED:
            return vector_score
        alpha = self.settings.RAG_HYBRID_ALPHA
        # 余弦理论上落在 [-1,1]，离线/线上模型都可能给出负值；归一化前夹到
        # [0,1]，否则负分会把融合分整体拉低、让阈值语义失真。
        clamped = min(1.0, max(0.0, vector_score))
        return alpha * clamped + (1.0 - alpha) * keyword_score

    def _candidate_ids(
        self,
        allowed_project_ids: list[str],
        allowed_levels: list[str],
        unrestricted: bool,
        limit: int,
    ) -> list[str]:
        """授权预过滤下推到 SQL：只回传允许访问的分片 ID（不含截断标记）。"""
        ids, _truncated = self._candidate_ids_with_scope(
            allowed_project_ids=allowed_project_ids,
            allowed_levels=allowed_levels,
            unrestricted=unrestricted,
            limit=limit,
        )
        return ids

    def _candidate_ids_with_scope(
        self,
        allowed_project_ids: list[str],
        allowed_levels: list[str],
        unrestricted: bool,
        limit: int,
        query: str | None = None,
        query_vector: Sequence[float] | None = None,
    ) -> tuple[list[str], bool]:
        """授权预过滤下推到 SQL：只回传允许访问的分片 ID，并报告是否被截断。

        密级过滤（classification）恒生效，与 unrestricted 无关：
        unrestricted 只放宽项目范围（global 知识也可见），
        绝不等于放开密级上限——否则高密级分片会随
        ``unrestricted`` 令牌一起泄漏（P0-5）。

        **三个数量别搞混**（改名/调参前先看这里）：

        * ``count_prefetched`` = 本方法的 ``limit`` 入参，即调用方想预取多少
          （``search`` 里是 ``max(top_k * 20, 200)``：候选集还要给 BM25 当语料、
          给多样性配额留余量）。它是**意愿**，不是结果。
        * ``RAG_CANDIDATE_LIMIT`` = 配置的**硬上限**，与调用方意愿无关，
          语料再大也不许超过它（否则单次检索的排序成本与 BM25 建索引成本失控）。
        * ``count_taken`` = ``min(count_prefetched, RAG_CANDIDATE_LIMIT)``，
          本次真正取用、并交给 BM25 与排序的候选条数。

        **截断必须按相关性截断**（否则召回会静默塌陷）：候选集一旦被硬上限
        截断，若取的是库内任意（如插入顺序）若干行，查询的**最佳匹配**可能
        整段落在窗口之外，而调用方只会看到"相关度低"，不会知道是没看全。
        因此本方法按方言选择排序：

        * PostgreSQL：``ORDER BY embedding <=> query`` 下推到 hnsw 索引
          （谓词与授权过滤同一条 SQL，授权预过滤仍在排序之前生效）；
        * 其它方言（SQLite 等，无向量算子）：**关键词命中优先**后补足其余
          授权分片，保证含查询词的精确匹配一定进入候选窗口。

        ``count_taken`` 小于库里匹配数时返回 ``truncated``，最终经
        ``search_with_metadata`` 以 ``keyword_scope="truncated"`` 暴露给调用方
        ——防止把"没看全"误判成"库里没有"。

        Returns:
            (候选 ID 列表, 是否被截断)。
        """
        stmt = select(KnowledgeChunk.id)
        if not allowed_levels:
            # 允许的密级集合为空 = 密级上限下没有任何分片可读
            return [], False
        stmt = stmt.where(KnowledgeChunk.classification.in_(allowed_levels))
        if not unrestricted:
            # 项目内知识 + 全局知识（``project_id`` 为空）都在授权范围内。
            # 注意：``allowed_project_ids`` 为空时**不能**直接返回空候选——那会把
            # 全局知识（公司级治理规则）一起挡掉，而这正是没有项目授权的只读用户
            # 唯一该看到的内容。40 题基线实测过这条早退的代价：recall@8 从 1.0
            # 掉到 0.5（32 道正向题里 16 道 0 命中，只有带项目授权的提问还能检索）。
            # 空的项目集合只应意味着"只看得见全局知识"，与 RLS 策略对
            # ``project_id IS NULL`` 的放行保持一致。
            stmt = stmt.where(
                or_(
                    KnowledgeChunk.project_id.in_(allowed_project_ids),
                    KnowledgeChunk.project_id.is_(None),
                )
            )
        # count_taken = min(预取量 limit, 硬上限 RAG_CANDIDATE_LIMIT)；见 docstring
        count_taken = min(limit, self.settings.RAG_CANDIDATE_LIMIT)

        # 多取 1 条即可判断「窗口之外是否还有授权分片」，
        # 不需要再对同一过滤条件跑一次 COUNT（大语料上那是每次检索一次全扫）。
        ids = self._select_candidate_ids(
            stmt, count_taken + 1, query, query_vector
        )
        return ids[:count_taken], len(ids) > count_taken

    def _select_candidate_ids(
        self,
        stmt,
        take: int,
        query: str | None,
        query_vector: Sequence[float] | None,
    ) -> list[str]:
        """在授权 WHERE 之内取至多 ``take`` 个 ID，按相关性优先。"""
        if self._is_pg() and query_vector is not None:
            ranked = (
                stmt.order_by(
                    KnowledgeChunk.embedding.op("<=>")(
                        bindparam("candidate_query_vector", type_=Vector, value=list(query_vector))
                    )
                )
                .limit(take)
            )
            return list(self.session.execute(ranked).scalars().all())

        selected: list[str] = []
        terms = _distinct_terms(query)
        if terms:
            matched = stmt.where(
                or_(
                    *[
                        func.lower(KnowledgeChunk.embedding_text).contains(term, autoescape=True)
                        for term in terms
                    ]
                )
            ).limit(take)
            selected = list(self.session.execute(matched).scalars().all())
        if len(selected) < take:
            # 关键字没铺满窗口时用其余授权分片补足（保持确定性顺序）
            filler = stmt.order_by(KnowledgeChunk.id).limit(take + len(selected))
            seen = set(selected)
            for chunk_id in self.session.execute(filler).scalars().all():
                if chunk_id in seen:
                    continue
                selected.append(chunk_id)
                if len(selected) >= take:
                    break
        return selected

    def _is_pg(self) -> bool:
        bind = self.session.get_bind()
        return bind is not None and bind.dialect.name == "postgresql"

    def _ranked_rows(
        self,
        candidate_ids: Sequence[str],
        query_vector: Sequence[float],
        fetch: int,
    ) -> list[KnowledgeChunk]:
        """按候选 ID 集合取行；PG 上把向量排序下推给 hnsw 索引。

        铁律不变：先在 SQL 内完成授权预过滤得到 candidate_ids，
        再仅对该 ID 集合按 ``embedding <=> query`` 排序取前 fetch 行，
        绝不在全库范围内做向量召回。最终 score 仍由应用层
        cosine_similarity 精确计算（与 SQLite 路径完全一致）。
        """
        stmt = select(KnowledgeChunk).where(KnowledgeChunk.id.in_(candidate_ids))
        if self._is_pg():
            # <=> 为 pgvector 余弦距离算子（升序即最相似在前）；
            # Vector 类型的 bind 处理器会把 list[float] 序列化为 vector
            # 字面量（psycopg 以 unknown 类型发送，由 PG 按算子上下文
            # 推断为 vector）
            stmt = stmt.order_by(
                KnowledgeChunk.embedding.op("<=>")(
                    bindparam("query_vector", type_=Vector, value=list(query_vector))
                )
            ).limit(fetch)
            return list(self.session.execute(stmt).scalars().all())
        return list(self.session.execute(stmt).scalars().all())

    def _apply_diversity(self, hits: list[RetrievalHit], limit: int) -> list[RetrievalHit]:
        """结果集构成：项目分片按配额，全局知识不占项目配额，但项目必须保底。

        三条规则（顺序即优先级）：

        1. **单项目配额**：同一项目最多 ``RAG_MAX_CHUNKS_PER_PROJECT`` 条，防止
           靠一次大 top_k 把某个项目拼出全貌。**溢出项直接丢弃**，不再追加到
           结果末尾凑满 ``top_k``（D2）：``top_k`` 的语义是「最相关的 k 条」，
           为凑数把被配额挡下的低分片段塞到尾部，会让调用方误判其相关性，
           配额本身的防护强度也被稀释。结果条数因此可能**少于** ``top_k``。
        2. **全局知识不占项目配额**：它与任何项目无关，配额要防的
           「拼出某个项目全貌」在这里没有对象。曾经把 ``project_id or "global"``
           当成一个项目、上限 2 条，导致全局治理规则最多只能出 2 条——评测基线
           实测 ``recall@8`` 因此掉到 0.9062。
        3. **项目保底**：放开全局后出现过一次反向问题（实测于
           ``test_jigsaw::test_repeated_search_eventually_downgrades``）：``top_k``
           较小时全局高分分片把项目分片整段挤出结果集，于是「项目内检索拿不到
           项目自己的分片」，拼图防护的覆盖度累积也随之失效（覆盖率按项目统计，
           项目分片没进结果就等于没看见）。因此对**每个有命中的项目**保底 1 条，
           保底总数上限 ``limit // 4``（至少 1），把主导权留给相关性。
        """
        max_per_project = max(1, self.settings.RAG_MAX_CHUNKS_PER_PROJECT)

        global_hits = [hit for hit in hits if hit.project_id is None]
        per_project: dict[str, list[RetrievalHit]] = {}
        for hit in hits:
            if hit.project_id is not None:
                per_project.setdefault(hit.project_id, []).append(hit)

        # ① 每个项目取前 max_per_project 条（hits 已按分值降序，组内顺序即相关度）
        project_selected: list[RetrievalHit] = []
        for project_id in sorted(
            per_project, key=lambda pid: per_project[pid][0].score, reverse=True
        ):
            project_selected.extend(per_project[project_id][:max_per_project])

        # ② 保底：高分项目优先，每个项目至少 1 条，总数不超过 limit // 4
        reserve = min(len(per_project), max(1, limit // 4))
        reserved = project_selected[:reserve]
        remaining = project_selected[reserve:]

        budget = limit - len(reserved)
        selected = list(reserved)
        if budget > 0:
            take_global = min(budget, len(global_hits))
            selected.extend(global_hits[:take_global])
            budget -= take_global
        if budget > 0:
            selected.extend(remaining[:budget])

        selected.sort(key=lambda hit: hit.score, reverse=True)
        return selected[:limit]


def _distinct_terms(query: str | None, max_terms: int = 12) -> list[str]:
    """查询词项（去重保序、限条数），用于候选窗口的关键词优先排序。

    复用 BM25 的 ``tokenize``（ASCII 词 + 中文 bigram + 单字），保证「候选
    选择」与「关键词打分」对同一个词项集合达成共识，不会出现选出来的
    候选在 BM25 眼里一个词都没命中。限条数是为了控制 OR-LIKE 的 SQL 规模。
    """
    if not query:
        return []
    terms = [term for term in dict.fromkeys(tokenize(query)) if term.strip()]
    return terms[:max_terms]


def ensure_pgvector_index(session: Session, dim: int = EMBEDDING_DIM_HINT) -> None:
    """生产环境建议的 HNSW 索引；本地 SQLite 自动跳过。

    错误处理约定：本函数不吞异常。索引 DDL 失败（权限不足、
    maintenance_work_mem 不够、列类型不符等）会让事务进入 aborted 状态，
    调用方必须显式 ``session.rollback()`` 后再决定是降级继续还是中止 ——
    静默吞掉异常会把 aborted 事务留给后续操作，引发
    ``InFailedSqlTransaction`` 连环失败（P0-1 事故的放大机制）。
    向量检索在无索引时结果仍正确（退化为顺序扫描），仅性能下降，
    因此 startup 选择 rollback 后降级继续。
    """
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_knowledge_chunk_embedding "
            "ON knowledge_chunk USING hnsw (embedding vector_cosine_ops)"
        )
    )
    session.commit()


__all__ = ["RetrievalHit", "SecureRetriever", "ensure_pgvector_index", "Vector"]
