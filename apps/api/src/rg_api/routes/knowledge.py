"""知识库：写入前强制净化，检索走受控 RAG，杜绝未脱敏内容进入向量库。"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Sequence

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from pydantic import BaseModel, Field, field_validator
from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.retrieval import RetrievalHit, SecureRetriever
from rg_contracts.config import Settings, get_settings
from rg_contracts.db.base import TimestampCodec
from rg_contracts.db.models import KnowledgeChunk, KnowledgeDocument, new_id, ts
from rg_contracts.db.session import db_session
from rg_contracts.enums import (
    CLASSIFICATION_ORDER,
    Classification,
    is_valid_classification,
    level_allows,
)
from rg_contracts.errors import PermissionDeniedError, PromptInjectionError, ValidationError
from rg_contracts.knowledge.chunking import ChunkDraft, PageText, chunk_markdown, chunk_pdf
from rg_contracts.knowledge.pdf import read_pdf_pages
from rg_contracts.security.budget import get_budget
from rg_contracts.security.detectors import detect_enumeration_intent, detect_injection
from rg_contracts.security.jigsaw import JigsawGuard, sanitize_before_chunking
from rg_contracts.security.policy import Subject, default_engine, levels_at_or_below
from rg_contracts.security.sanitize import SanitizeOptions, Sanitizer
from sqlalchemy import and_, or_, select, true
from sqlalchemy.orm import Session

from rg_api.routes.auth import current_subject
from rg_api.services.access import assert_capability, scoped_project_ids
from rg_api.services.audit import audit_action, audit_security
from rg_api.startup import get_canary_registry

router = APIRouter(prefix="/knowledge", tags=["knowledge"])
_engine = default_engine()

#: PDF 上传可接受的内容类型。octet-stream 要放行：部分客户端（含 curl -F
#: 未显式指定类型、某些浏览器旧版本）会把 PDF 报成通用二进制流，按扩展名
#: 拒绝会让正常上传失败；真正的类型校验由 read_pdf_pages 的解析兜住。
_PDF_CONTENT_TYPES = frozenset({"application/pdf", "application/octet-stream"})


class DocumentIn(BaseModel):
    title: str = Field(min_length=1, max_length=190)
    content: str = Field(min_length=1, max_length=20000)
    doc_type: str = "rule"
    project_id: str | None = None
    classification: str = Classification.L2_INTERNAL.value
    source_ref: str | None = None

    @field_validator("classification")
    @classmethod
    def _valid_classification(cls, value: str) -> str:
        """密级必须是枚举字面量：脏值（尾空格/错分隔符）不允许进入存储。

        旧实现接受任意字符串，非法值在 SQL 过滤里不可见、在 ``classification_rank``
        里却被当公开（fail-open），同一份数据两条路径两种结论。
        """
        if not is_valid_classification(value):
            raise ValueError(f"非法密级：{value!r}，允许 {sorted(CLASSIFICATION_ORDER)}")
        return value


class SearchIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    project_id: str | None = None
    top_k: int = Field(default=6, ge=1, le=20)


def _raw_drafts(
    full_text: str,
    pages: Sequence[PageText] | None,
    params: dict[str, int],
) -> list[ChunkDraft]:
    """按来源切出**未净化**的分片，只用于切片规避检测。

    检测必须与入库分片同一套切块器，否则「检测的」和「入库的」不是同一批切片，
    检测形同虚设。
    """
    if pages is not None:
        return chunk_pdf(pages, **params)
    return chunk_markdown(full_text, **params)


def _sanitized_drafts(
    full_text: str,
    pages: Sequence[PageText] | None,
    params: dict[str, int],
    settings: Settings,
    ingest_opts: SanitizeOptions,
) -> list[ChunkDraft]:
    """先净化再切块：入库分片一律来自净化后的文本（旧顺序是切完再逐片净化）。

    PDF **按页**净化：页是硬边界，``chunk_pdf`` 绝不跨页拼接（跨页会把页眉页脚
    混进正文，也会让 ``page_no`` 失去意义），所以净化必须在页面粒度上做，
    之后再按页切块，页码才能保住。``max_text_len`` 用全文长度，任何一页都不会
    被静默截断。
    """
    if pages is not None:
        sanitized_pages = [
            PageText(
                page_no=page.page_no,
                text=sanitize_before_chunking(page.text, settings, ingest_opts)[0],
            )
            for page in pages
        ]
        return chunk_pdf(sanitized_pages, **params)
    sanitized_full, _removed = sanitize_before_chunking(full_text, settings, ingest_opts)
    # 净化会改变文本长度与字符偏移：切片必须在净化后的全文上重做一遍。
    # 因此 ChunkDraft 的 char_start/char_end 是「净化后全文」的偏移，与原文
    # 不可映射，这里只消费 text / section_path / page_no，不把偏移写进库。
    return chunk_markdown(sanitized_full, **params)


def _ingest_document(
    *,
    request: Request,
    session: Session,
    subject: Subject,
    settings: Settings,
    title: str,
    full_text: str,
    pages: Sequence[PageText] | None,
    doc_type: str,
    classification: str,
    project_id: str | None,
    source_type: str,
    source_path: str | None,
    source_ref: str | None,
    page_count: int,
) -> dict:
    """文本 / PDF 摄取的**唯一**实现（两个 HTTP 入口共用）。

    铁律：任何新摄取入口都必须走这里，不允许复制一份平行实现 —— 同一套安全
    校验在两个入口里各写一份，必然出现「改一边漏另一边」（本项目已反复踩过：
    两套网关序列化、三套切块器都是这么来的）。

    安全顺序（不可调换）：
    1) 能力校验 → 2) 标题净化 → 3) 注入检测 → 4) 项目 / 密级授权
    → 5) 密级闸门（L4 仅登记不切片）→ 6) 先净化全文再切块
    → 7) 切片规避检测（与入库分片同源）→ 8) 逐片幂等净化 + 金丝雀
    → 9) 落库 + 审计
    """
    assert_capability(subject, "knowledge:write", request=request, session=session)
    # 兜底：任何新入口都必须过密级白名单（入口已各自校验，这里防止新增入口漏掉）
    if not is_valid_classification(classification):
        raise ValidationError(
            f"非法密级：{classification!r}", allowed=sorted(CLASSIFICATION_ORDER)
        )
    sanitizer = Sanitizer(settings)

    # P1-15：title 与 content 同属出域面（会进审计日志、安全事件、文档列表），
    # 必须在入库前净化；content 走 sanitize_before_chunking，title 不能例外。
    safe_title = sanitizer.sanitize_text(title).text

    injections = detect_injection(full_text)
    if injections:
        # 紧接着就抛异常 → 业务会话必回滚；安全事件必须走独立事务才留得下来
        audit_security(
            session, subject, "prompt_injection_blocked",
            "知识文档写入命中提示词注入特征", severity="high",
            metadata={"title": safe_title},
            project_id=project_id,
            independent=True,
        )
        audit_action(
            request, session, subject, "knowledge:write", "denied",
            project_id, "prompt_injection",
        )
        raise PromptInjectionError("文档内容包含疑似提示词注入，已拒绝写入")

    if project_id:
        if not _engine.check_project(subject, project_id).allowed:
            audit_action(
                request,
                session,
                subject,
                "knowledge:write",
                "denied",
                project_id,
                "project_out_of_scope",
            )
            raise PermissionDeniedError("无该项目访问权限")
        if not _engine.check_level(subject, project_id, classification).allowed:
            audit_action(request, session, subject, "knowledge:write", "denied", project_id, "level_exceeded")
            raise PermissionDeniedError("密级超出授权上限")

    # L4 原始事实禁止向量化，仅登记不切片。唯一合法闸门是密级：
    # 金丝雀开关不参与本判断（其入库侧职责是 assert_clean，disabled 时为 no-op）。
    from rg_contracts.enums import VECTORIZABLE_MAX_LEVEL, classification_rank

    can_vectorize = classification_rank(classification) <= classification_rank(VECTORIZABLE_MAX_LEVEL.value)

    document = KnowledgeDocument(
        id=new_id("kd"),
        title=safe_title,
        doc_type=doc_type,
        project_id=project_id,
        platform=None,
        classification=classification,
        source_ref=source_ref,
        content=full_text,
        sanitized=True,
        source_type=source_type,
        source_path=source_path,
        page_count=page_count,
        metadata_json={"vectorizable": can_vectorize},
    )
    session.add(document)
    session.flush()

    embedder = get_embedding_service(settings)
    retriever = SecureRetriever(session, settings, embedder)
    canary = get_canary_registry()
    chunks = 0
    if can_vectorize:
        # 切块参数取配置（旧的 260 字是「按分号硬切后的产物长度」而非语义目标，
        # 标题感知切块按句末聚包，目标长度应能放下一整段处置步骤）。
        chunk_params = {
            "target_chars": settings.CHUNK_TARGET_CHARS,
            "overlap_chars": settings.CHUNK_OVERLAP_CHARS,
            "max_chars": settings.CHUNK_MAX_CHARS,
        }
        scan = JigsawGuard(session, settings).scan_ingest(
            full_text, [draft.text for draft in _raw_drafts(full_text, pages, chunk_params)]
        )
        if scan.risky:
            audit_security(
                session, subject, "jigsaw_slicing_evasion",
                "知识文档存在切片规避特征：敏感值被分片切断或需跨分片重组",
                severity="high",
                metadata={"title": safe_title, "scan": scan.as_dict()},
            )
        # max_text_len 必须覆盖全文：默认 1200 字截断会把长文档后半段静默丢弃
        ingest_opts = SanitizeOptions(
            mask_entities=settings.SECURITY_MASK_ENTITIES,
            coarse_buckets=settings.SECURITY_COARSE_BUCKETS,
            redact_owner=settings.SECURITY_REDACT_OWNER,
            max_text_len=len(full_text) + 16,
        )
        drafts = _sanitized_drafts(full_text, pages, chunk_params, settings, ingest_opts)
        for ordinal, draft in enumerate(drafts):
            # 净化后的分片再跑一次（幂等），作为入库前的兜底校验
            result = sanitizer.sanitize_text(draft.text, ingest_opts)
            canary.assert_clean(result.text, "knowledge_ingest")
            vector = embedder.embed(result.text)
            chunk = KnowledgeChunk(
                id=new_id("kc"),
                document_id=document.id,
                ordinal=ordinal,
                project_id=project_id,
                platform=None,
                classification=classification,
                embedding_text=result.text,
                display_text=result.text,
                token_count=len(result.text),
                embedding_model=embedder.model,
                # D1：section_path / page_no 的唯一真值源是模型列，
                # 不再往 metadata_json 里写（旧数据由启动时的一次性回填迁移）。
                section_path=draft.section_path,
                page_no=draft.page_no,
                metadata_json={
                    "sanitized": True,
                    "removed": result.removed,
                    "jigsaw_scan": scan.as_dict() if scan.risky else None,
                },
                created_at=ts(),
            )
            session.add(chunk)
            session.flush()
            retriever.upsert_chunk(chunk, vector)
            chunks += 1

    session.commit()
    audit_action(
        request, session, subject, "knowledge:write", "allowed", project_id, None,
        resource_type="knowledge_document", resource_id=document.id,
        metadata={"chunks": chunks, "vectorizable": can_vectorize, "source_type": source_type},
    )
    return {"id": document.id, "chunks": chunks, "vectorizable": can_vectorize}


@router.post("/documents")
def create_document(
    payload: DocumentIn,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    """写入即净化：原文入库，但向量与模型只用净化后的分片。"""
    return _ingest_document(
        request=request,
        session=session,
        subject=subject,
        settings=get_settings(),
        title=payload.title,
        full_text=payload.content,
        pages=None,
        doc_type=payload.doc_type,
        classification=payload.classification,
        project_id=payload.project_id,
        source_type="text",
        source_path=None,
        source_ref=payload.source_ref,
        page_count=0,
    )


@router.post("/documents/pdf")
def create_pdf_document(
    request: Request,
    file: UploadFile = File(...),
    title: str | None = Form(default=None),
    project_id: str | None = Form(default=None),
    classification: str = Form(default=Classification.L2_INTERNAL.value),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    """PDF 摄取：逐页抽取文本后走**与文本摄取完全相同**的一条链路。

    本路由只负责「字节 → 逐页文本」与入参校验，注入检测、授权密级、净化、
    切块、金丝雀、审计全部由 ``_ingest_document`` 完成，不复制任何一份。

    Raises:
        ValidationError: 非 PDF 内容类型或超过上传上限（沿用 422 错误码体系）。
        ScannedPdfUnsupported / EncryptedPdfError / CorruptPdfError: 由
        ``read_pdf_pages`` 抛出的类型化异常（均映射 422）。
    """
    settings = get_settings()
    # Form 入参不走 pydantic 模型，密级脏值必须在这里拦（与 DocumentIn 同口径）
    if not is_valid_classification(classification):
        raise ValidationError(
            f"非法密级：{classification!r}", allowed=sorted(CLASSIFICATION_ORDER)
        )
    if (file.content_type or "") not in _PDF_CONTENT_TYPES:
        raise ValidationError("仅支持 application/pdf 上传", content_type=file.content_type)
    raw = file.file.read()
    if len(raw) > settings.KNOWLEDGE_UPLOAD_MAX_BYTES:
        raise ValidationError(
            f"文件超过上传上限 {settings.KNOWLEDGE_UPLOAD_MAX_BYTES} 字节",
            size=len(raw),
        )
    pages = read_pdf_pages(io.BytesIO(raw))
    # 只存 basename：落绝对路径会泄露服务器目录结构（最小披露）
    filename = Path(file.filename or "").name or "upload.pdf"
    return _ingest_document(
        request=request,
        session=session,
        subject=subject,
        settings=settings,
        title=title or filename,
        full_text="\n\n".join(page.text for page in pages),
        pages=pages,
        doc_type="pdf",
        classification=classification,
        project_id=project_id,
        source_type="pdf",
        source_path=filename,
        source_ref=f"upload://{filename}",
        page_count=len(pages),
    )


@router.post("/search")
def search(
    payload: SearchIn,
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    """受控检索：授权预过滤 → 向量排序 → 输出 DLP → 审计。"""
    settings = get_settings()
    project_ids = scoped_project_ids(subject, payload.project_id)
    unrestricted = _engine.build_scope(subject).unrestricted

    if detect_enumeration_intent(payload.query):
        # 下面立即抛异常 → 业务会话回滚；独立事务保证这条留痕不丢
        audit_security(
            session, subject, "enumeration_intent_blocked",
            f"检索意图被判定为批量枚举：{payload.query[:80]}", severity="high",
            project_id=payload.project_id, independent=True,
        )
        audit_action(request, session, subject, "knowledge:search", "denied", payload.project_id, "enumeration_intent")
        raise PermissionDeniedError("查询意图被判定为全量枚举，已拒绝")

    try:
        get_budget().enforce_retrieval(subject.user_id, project_ids, unrestricted)
    except PermissionDeniedError as exc:
        audit_action(request, session, subject, "knowledge:search", "denied", payload.project_id, exc.code)
        raise

    allowed_projects = [] if unrestricted else project_ids
    ceiling = subject.ceiling_for(payload.project_id) if payload.project_id else subject.classification_ceiling
    allowed_levels = levels_at_or_below(ceiling)

    embedder = get_embedding_service(settings)
    retriever = SecureRetriever(session, settings, embedder)
    # search_with_metadata 与 search 同一条链路，只是额外回传响应元数据
    # （keyword_scope：候选集是否被截短，避免调用方误判"库里没有"）。
    hits: list[RetrievalHit]
    hits, retrieval_meta = retriever.search_with_metadata(
        query=payload.query,
        subject=subject,
        allowed_project_ids=allowed_projects,
        allowed_levels=allowed_levels,
        top_k=payload.top_k,
        unrestricted=unrestricted,
    )
    canary_hits = get_canary_registry().scan(" ".join(h.display_text for h in hits))
    if canary_hits:
        audit_security(
            session, subject, "canary_leak_blocked", "检索结果命中安全金丝雀",
            severity="critical", metadata={"hits": [h.__dict__ for h in canary_hits]},
        )
        hits = []

    # 拼图防护：跨查询累积视图（覆盖度 + 敏感维度共现）。单次查询都合法，
    # 只有把窗口内所有命中合起来看才能识别 mosaic / salami-slicing 攻击。
    guard = JigsawGuard(session, settings)
    risk = guard.assess(subject.user_id, payload.project_id, hits, payload.query)
    response_hits: list[dict] = [hit.to_dict() for hit in hits]
    downgraded = False
    reason_code = None

    if risk.action == "deny" and risk.triggered:
        audit_security(
            session, subject, "jigsaw_pattern_denied",
            "检索模式判定为拼图攻击，已拒绝返回", severity="high",
            metadata=risk.as_dict(),
        )
        audit_action(
            request, session, subject, "knowledge:search", "denied",
            payload.project_id, "jigsaw_risk",
        )
        hits = []
        response_hits = []
    elif risk.action == "coarsen" and risk.triggered:
        response_hits = guard.coarsen(hits)
        # 降密级返回走 jigsaw 自己的序列化（只覆盖文本），会把 C 批新增的
        # 出处与打分明细丢掉——响应形状随「是否触发降密级」漂移，调用方很难
        # 处理。这里按 chunk_id 把这些字段补回去，保证两种路径同形状。
        by_chunk_id = {hit.chunk_id: hit for hit in hits}
        for item in response_hits:
            hit = by_chunk_id.get(item.get("chunk_id"))
            if hit is None:
                continue
            for field in ("vector_score", "keyword_score", "fused_score", "source"):
                item.setdefault(field, getattr(hit, field))
        downgraded = True
        reason_code = "jigsaw_coarsened"

    guard.record(subject.user_id, hits, payload.query, downgraded=downgraded)

    if risk.triggered:
        # 静默记录：风险只在审计/安全事件留痕，响应体不回显，避免攻击者据此调整策略
        audit_security(
            session, subject, "jigsaw_risk_detected",
            f"检索模式命中拼图风险（{risk.risk}）：" + "; ".join(risk.reasons[:3]),
            severity="high" if risk.risk != "critical" else "critical",
            metadata=risk.as_dict(),
        )
        audit_action(
            request, session, subject, "knowledge:search",
            "downgraded" if downgraded else "allowed",
            payload.project_id, reason_code,
            metadata={"jigsaw": risk.as_dict()},
        )

    audit_action(
        request, session, subject, "knowledge:search", "allowed", payload.project_id, None,
        metadata={"query_len": len(payload.query), "hits": len(response_hits), "levels": allowed_levels},
    )
    session.commit()
    security_payload = {
        "allowed_levels": allowed_levels,
        # 密级过滤恒生效（unrestricted 也不放开密级上限），字段名
        # 保持不变：前端 KnowledgeView.vue 消费 security.prefiltered
        "prefiltered": True,
        "canary_hits": len(canary_hits),
        "budget": get_budget().snapshot(subject.user_id),
    }
    if not settings.SECURITY_JIGSAW_SILENT:
        security_payload["jigsaw"] = risk.as_dict()
    return {
        "query": payload.query,
        "hits": response_hits,
        "security": security_payload,
        # 检索元数据（方案 §4.3）：纯新增顶层键，既有 response 结构不动。
        # keyword_scope=truncated 表示候选集被 RAG_CANDIDATE_LIMIT 或预取量
        # 截短，库里可能还有匹配分片——调用方不得据此判定"库里没有"。
        "retrieval": retrieval_meta,
    }


@router.post("/reindex")
def reindex(
    request: Request,
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> dict:
    assert_capability(subject, "knowledge:reindex", request=request, session=session)
    from rg_api.startup import backfill_embeddings

    count = backfill_embeddings(session, get_settings())
    audit_action(request, session, subject, "knowledge:reindex", "allowed", None, None, metadata={"embedded": count})
    return {"embedded": count}


@router.get("/documents")
def list_documents(
    limit: int = Query(20, ge=1, le=100),
    subject: Subject = Depends(current_subject),
    session: Session = Depends(db_session),
) -> list[dict]:
    """文档列表：**先授权、后截断**，逐项目按 ``ceiling_for(project)`` 过滤。

    P1-14：项目内 visible_ceiling 可能低于用户全局上限，只用全局 ceiling
    会把项目内越限文档列出来；此处与检索路径（search 内 ceiling_for）
    保持同一口径，越密级条目不返回。

    旧实现是「先 ``limit`` 再逐行丢弃」：项目范围与项目级 ceiling 都在
    分页之后才生效，用户看到的结果会被不可见文档挤掉（明明有 20 条可见
    文档，却只返回 3 条），``limit=-1`` 更是让 SQLite 全表返回、PG 直接 500。
    现在范围与密级全部下推到同一条 SQL，``limit`` 只裁可见行。
    """
    scope = _engine.build_scope(subject)
    global_levels = levels_at_or_below(subject.classification_ceiling)
    overrides = dict(subject.visible_ceilings)

    clauses = []
    for pid, ceiling in overrides.items():
        # 项目级上限覆盖全局：该项目只放行到它自己的上限
        clauses.append(
            and_(
                KnowledgeDocument.project_id == pid,
                KnowledgeDocument.classification.in_(levels_at_or_below(ceiling)),
            )
        )
    # 注意 SQL 三值逻辑：``NULL NOT IN (...)`` 结果是 UNKNOWN 而非 TRUE，
    # 直接 ``notin_`` 会把 project_id IS NULL 的全局文档整批排除掉
    # （回归用例 test_document_list_includes_global_documents 已验证：
    #  旧写法下管理员列表里一条全局文档都看不到）。必须显式并入 NULL 分支。
    outside_overrides = (
        or_(
            KnowledgeDocument.project_id.is_(None),
            KnowledgeDocument.project_id.notin_(list(overrides)),
        )
        if overrides
        else true()
    )
    rest = and_(
        KnowledgeDocument.classification.in_(global_levels),
        outside_overrides,
    )
    if not scope.unrestricted:
        # 项目受限用户：只留本项目（overrides 之外的授权项目）+ 全局文档
        rest = and_(
            rest,
            or_(
                KnowledgeDocument.project_id.in_(sorted(scope.project_ids)),
                KnowledgeDocument.project_id.is_(None),
            ),
        )
    stmt = select(KnowledgeDocument).where(or_(rest, *clauses) if clauses else rest)
    rows = session.execute(
        stmt.order_by(KnowledgeDocument.created_at.desc()).limit(limit)
    ).scalars().all()
    sanitizer = Sanitizer(get_settings())
    return [
        {
            "id": row.id,
            # P1-15：出库再净化一次，兜住修复前已落库的历史标题
            "title": sanitizer.sanitize_text(row.title or "").text,
            "doc_type": row.doc_type,
            "project_id": row.project_id,
            "classification": row.classification,
            "sanitized": row.sanitized,
            # 方言无关序列化：SQLite 为 ISO 文本，PG 为 timestamptz（读回 datetime）
            "created_at": TimestampCodec.encode(row.created_at) or "",
        }
        for row in rows
        # 行级兜底：SQL 已按 ceiling_for 收口，这里再校一次避免后续改写漏掉
        if level_allows(subject.ceiling_for(row.project_id or ""), row.classification)
    ]


__all__ = ["router"]
