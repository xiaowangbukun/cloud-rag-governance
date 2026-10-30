"""启动引导：建表、索引、种子数据、金丝雀注册、向量回填。"""

from __future__ import annotations

from rg_contracts.ai.embedding import get_embedding_service
from rg_contracts.ai.retrieval import SecureRetriever, ensure_pgvector_index
from rg_contracts.config import DbDialect, Settings, get_settings
from rg_contracts.db.models import KnowledgeChunk
from rg_contracts.db.session import (
    ensure_schema,
    get_engine,
    get_session_factory,
    session_scope,
    verify_schema,
)
from rg_contracts.logging_setup import get_logger
from rg_contracts.security.canary import build_registry
from rg_contracts.seed.demo import build_canaries, seed_everything
from sqlalchemy import func, select
from sqlalchemy.orm import Session

logger = get_logger(__name__)

_canary_registry = None
_bootstrapped = False


def ensure_bootstrap(settings: Settings | None = None) -> None:
    """幂等引导：本地开发、测试客户端、uvicorn 启动时都会调用，只执行一次。"""
    global _bootstrapped
    if _bootstrapped:
        return
    bootstrap(settings)
    _bootstrapped = True


def get_canary_registry():
    global _canary_registry
    if _canary_registry is None:
        settings = get_settings()
        _canary_registry = build_registry(build_canaries(), enabled=settings.SECURITY_CANARY_ENABLED)
    return _canary_registry


def bootstrap(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    _prepare_schema(settings)
    _check_rls_enforcement(settings)

    with session_scope() as session:
        # W1 CI 前置决策：索引 DDL 失败只降性能、不阻断启动 —— 向量检索无索引时
        # 结果仍正确（退化为顺序扫描）。但失败的 DDL 会把会话事务置于 aborted
        # 状态，必须显式 rollback 后再继续，否则后续 backfill 的 SELECT 会以
        # InFailedSqlTransaction 连环失败，整个 bootstrap 崩掉（P0-1 放大机制）。
        if not settings.DB_MIGRATE_ON_STARTUP:
            # 索引是 DDL，运行角色没有权限；由 schema-init Job 用属主身份建好。
            logger.info(
                "pgvector_index_skipped",
                extra={"extra_fields": {"reason": "DB_MIGRATE_ON_STARTUP=false（索引由迁移 Job 建）"}},
            )
        else:
            try:
                ensure_pgvector_index(session, settings.EMBEDDING_DIM)
            except Exception:  # noqa: BLE001
                session.rollback()
                logger.error(
                    "pgvector_index_failed",
                    extra={
                        "extra_fields": {
                            "dim": settings.EMBEDDING_DIM,
                            "impact": "向量检索退化为顺序扫描，功能可用、性能下降",
                        }
                    },
                )
        if settings.DEMO_SEED:
            result = seed_everything(session, settings)
            logger.info("seed_done", extra={"extra_fields": result})
        embedded = backfill_embeddings(session, settings)
        logger.info("embedding_backfill", extra={"extra_fields": {"embedded": embedded}})


def _prepare_schema(settings: Settings) -> None:
    """按配置决定「初始化」还是「只校验」schema。

    生产用运行角色（只 DML、无 DDL）连接，初始化必须由属主身份的部署 Job 完成；
    应用侧只校验，缺表就 fail-fast，避免把「部署顺序错了」伪装成运行时 500。
    """
    if settings.DB_MIGRATE_ON_STARTUP:
        applied = ensure_schema()
        # ``applied`` 是本次真的执行了的迁移版本；空列表代表 schema 已是最新。
        # 记进启动日志，运维才能回答「这台机器升级到第几个版本了」。
        logger.info(
            "schema_ready",
            extra={"extra_fields": {"dialect": settings.DB_DIALECT.value, "applied": applied}},
        )
        return
    verify_schema()
    logger.info(
        "schema_verified",
        extra={"extra_fields": {"dialect": settings.DB_DIALECT.value, "migrate_on_startup": False}},
    )


def _check_rls_enforcement(settings: Settings) -> None:
    """启动自检：RLS 策略已建，但连接角色若会绕过策略，它就只是装饰品。

    为什么不直接 fail-fast：k8s 已按「属主 / 运行」拆分角色（见
    ``deploy/k8s/12-schema-job.yaml``），但单机部署、docker compose 与 CI 仍用
    ``POSTGRES_USER``（超级用户）连接，硬失败会把它们全部挡在门外。这里选择
    「醒目告警 + 明确整改文本」，运维照 ``docs/rls.md`` 拆完角色后告警自然消失。
    """
    if settings.DB_DIALECT is DbDialect.SQLITE or not settings.DB_RLS_ENABLED:
        return
    from rg_contracts.db.rls import bypassing_role, policy_rows

    try:
        policy_count = len(policy_rows(get_engine()))
    except Exception:  # noqa: BLE001 —— 自检失败不能阻断启动
        logger.warning("rls_self_check_failed", extra={"extra_fields": {"stage": "policy_rows"}})
        return
    bypass = bypassing_role(get_engine())
    if bypass:
        logger.warning(
            "rls_ineffective_superuser_role",
            extra={
                "extra_fields": {
                    "role": bypass["role"],
                    "superuser": bypass["superuser"],
                    "bypassrls": bypass["bypassrls"],
                    "policies": policy_count,
                    "impact": "该角色绕过所有 RLS 策略，第二道防线当前不生效",
                    "fix": "为应用创建 NOSUPERUSER NOBYPASSRLS 角色并以该角色连接（见 docs/rls.md）",
                }
            },
        )
    elif policy_count == 0:
        # 策略数为 0 = 兜底完全没装上：比「角色绕过策略」更早、更该暴露。
        logger.warning(
            "rls_policies_missing",
            extra={
                "extra_fields": {
                    "policies": 0,
                    "impact": "受保护表没有任何 RLS 策略，第二道防线完全缺席",
                    "fix": "以属主身份执行 `python -m rg_contracts.db.migrate`（部署侧为 schema-init Job）",
                }
            },
        )
    else:
        logger.info("rls_enforced", extra={"extra_fields": {"policies": policy_count}})


def backfill_embeddings(session: Session, settings: Settings | None = None, limit: int = 500) -> int:
    """为缺失向量的分片补算 embedding。"""
    settings = settings or get_settings()
    embedder = get_embedding_service(settings)
    # 注意：SQLite 下 JSON/向量列为文本，IS NULL 判定不可靠，这里在应用层过滤
    rows = (
        session.execute(select(KnowledgeChunk).limit(limit)).scalars().all()
    )
    pending = [row for row in rows if not row.embedding]
    if not pending:
        return 0
    vectors = embedder.embed_many([row.embedding_text for row in pending])
    retriever = SecureRetriever(session, settings, embedder)
    for row, vector in zip(pending, vectors):
        # 向量化前最后一道检查：净化文本不得命中金丝雀
        get_canary_registry().assert_clean(row.embedding_text, "embedding")
        retriever.upsert_chunk(row, vector)
    session.commit()
    return len(pending)


def backfill_chunk_section_path(session: Session, limit: int = 2000) -> int:
    """把历史分片 ``metadata_json["section_path"]`` 回填到模型列（幂等）。

    背景（D1）：摄取曾把章节路径写进 ``metadata_json``，而模型列
    ``knowledge_chunk.section_path`` 才是唯一真值源。两个真值源不能长期并存，
    所以选**一次性回填**而不是"读取时回退"：回退逻辑一旦留下就再没人删，
    且会持续掩盖数据不一致；回填是幂等可重放的，跑完即可删掉回退分支。

    Returns:
        本次回填的行数；没有待回填的历史行时返回 0。
    """
    rows = session.execute(select(KnowledgeChunk).limit(limit)).scalars().all()
    pending = [
        row
        for row in rows
        if row.section_path is None and (row.metadata_json or {}).get("section_path")
    ]
    if not pending:
        return 0
    for row in pending:
        row.section_path = row.metadata_json["section_path"]
    session.commit()
    logger.info(
        "section_path_backfill",
        extra={"extra_fields": {"backfilled": len(pending)}},
    )
    return len(pending)


def count_chunks(session: Session) -> int:
    return int(session.execute(select(func.count(KnowledgeChunk.id))).scalar() or 0)


def reset_runtime() -> None:
    global _canary_registry, _bootstrapped
    _canary_registry = None
    _bootstrapped = False
    from rg_contracts.db.session import reset_engine_state

    reset_engine_state()
    get_session_factory()
