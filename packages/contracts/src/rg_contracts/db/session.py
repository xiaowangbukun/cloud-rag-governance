from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from rg_contracts.config import DbDialect, Settings, get_settings
from rg_contracts.db import rls
from rg_contracts.logging_setup import get_logger, log_event

#: 会话级监听在模块导入时注册：任何通过本模块工厂建出来的 Session 都会在
#: 每个事务开始时拿到作用域（未设作用域的走显式 system 通道）。
rls.install_session_listener()

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def build_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    if settings.DB_DIALECT is DbDialect.SQLITE:
        path = settings.sqlite_abs_path
        path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            settings.database_url,
            echo=settings.DB_ECHO,
            connect_args={"check_same_thread": False},
            future=True,
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    engine = create_engine(
        settings.database_url,
        echo=settings.DB_ECHO,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        future=True,
    )
    # 直接走 ``engine.begin()`` 的连接（迁移、一次性脚本）没有 Session 可挂
    # 作用域，统一按 system 通道处理，避免被策略静默拒绝成「更新 0 行」。
    rls.install_engine_listener(engine)
    return engine


def get_engine(settings: Settings | None = None) -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine(settings)
    return _engine


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(settings), autocommit=False, autoflush=False, expire_on_commit=False
        )
    return _session_factory


def ensure_schema(engine: Engine | None = None) -> list[int]:
    """建表 + 执行未登记的迁移 + （PG）建 RLS 策略，返回本次应用的 version 列表。

    执行顺序是固定的，每一步都依赖前一步：
    1. ``CREATE EXTENSION vector``（仅 PG，``knowledge_chunk.embedding`` 依赖它）；
    2. ``create_all``：只建**缺失的表**，顺带把 ``schema_version`` 表建出来，
       因此后面登记版本时不存在「版本表自己也得靠迁移创建」的鸡生蛋问题；
    3. ``schema_migrations.apply_pending``：按注册表顺序执行未登记的迁移并逐条
       登记 —— 「注册即执行」，从结构上消灭「迁移函数定义了但没人调用」；
    4. 建 RLS 策略（仅 PG）：策略引用的列必须已由第 2、3 步补齐。

    迁移不再由本函数逐个点名调用（历史实现是 4 处直接调用）。注册表见
    ``rg_contracts.db.schema_migrations.registry()``；不用 alembic 的理由与
    切换判据写在 ``docs/schema-bootstrap-governance.md`` §3 方案 3。

    Returns:
        本次实际执行的迁移 version（已登记过的不会重跑；重复调用返回空列表）。
    """
    import rg_contracts.db.models  # noqa: F401  (register all models on Base.metadata)
    from rg_contracts.db import schema_migrations
    from rg_contracts.db.base import Base

    target = engine or get_engine()
    if target.dialect.name == "postgresql":
        with target.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(target)
    # 存量库补列/补索引：create_all 只建缺失的表，不会给已存在的表加列或加索引。
    applied = schema_migrations.apply_pending(target)
    if target.dialect.name == "postgresql":
        # 行级安全是「第二道防线」，建表/补列之后才建策略：策略引用的列必须已存在。
        # 开关默认开启；SQLite 没有 RLS 等价物，走应用层过滤（与 P0 方案一致）。
        if get_settings().DB_RLS_ENABLED:
            rls.apply_policies(target)
    return applied


def required_tables() -> tuple[str, ...]:
    """应用运行所需的表清单，**直接取自 ORM 元数据**而不是手写常量。

    手写清单会在新增模型时静默过期：漏一张表，启动校验照样通过，问题推迟到
    第一次查询才以 500 暴露。从 ``Base.metadata`` 推导则天然同步——新增模型
    不跑迁移，应用就会在启动时明确失败（见 ``verify_schema``）。
    """
    import rg_contracts.db.models  # noqa: F401  (register all models on Base.metadata)
    from rg_contracts.db.base import Base

    return tuple(sorted(Base.metadata.tables))


def verify_schema(engine: Engine | None = None) -> None:
    """只校验、不建表：用于 ``DB_MIGRATE_ON_STARTUP=false`` 的生产运行角色。

    为什么要有这一步而不是直接跳过初始化：运行角色没有 DDL 权限，若 schema
    尚未由部署 Job 建好，应用会「启动成功、每个请求 500」，把部署顺序错误伪装
    成运行时故障。这里在启动时一次性列出缺哪些表并给出修复命令，属 fail-fast。

    Raises:
        RuntimeError: 存在缺失的表（消息含表名清单与迁移命令）。
    """
    from sqlalchemy import inspect

    target = engine or get_engine()
    existing = set(inspect(target).get_table_names())
    missing = [name for name in required_tables() if name not in existing]
    if not missing:
        return
    raise RuntimeError(
        f"schema 未就绪：缺少 {len(missing)} 张表（{', '.join(missing[:8])}"
        f"{' 等' if len(missing) > 8 else ''}）。"
        "当前进程以 DB_MIGRATE_ON_STARTUP=false 运行，不会建表；"
        "请先以属主身份执行 `python -m rg_contracts.db.migrate`（部署侧为 schema-init Job）。"
    )


#: 需要「保证存在」的后加列清单：(表名, 列名, 可直接拼进 ALTER TABLE 的列定义)。
#:
#: 为什么写成裸 DDL 而不是从 ORM 元数据渲染：SQLite 的 ``ALTER TABLE ADD COLUMN``
#: 只接受「可空列」或「非空 + 常量默认值」，从 ``Table.columns`` 渲染出来的 DDL 可能
#: 带 SERVER DEFAULT 表达式或方言定制类型，直接执行会在 SQLite 上失败。这里 7 个列
#: 全部满足该限制，且 ``VARCHAR(n)`` / ``INTEGER`` 两种方言都合法 —— 与 SQLAlchemy
#: 为它们生成的建表语句一致，不会出现「新建库与迁移后的老库类型不同」。
_KNOWLEDGE_COLUMN_UPGRADES: tuple[tuple[str, str, str], ...] = (
    # 摄取通道与来源（P1 §3.1）：默认 'text' 让存量 JSON 文本接口写入的行保持自洽
    ("knowledge_document", "source_type", "VARCHAR(16) NOT NULL DEFAULT 'text'"),
    # 原始文件名（仅 basename）：出处展示需要，绝对路径会泄露目录结构
    ("knowledge_document", "source_path", "VARCHAR(255)"),
    # PDF 页数；非 PDF 恒为 0（不用 NULL，前端可直接展示）
    ("knowledge_document", "page_count", "INTEGER NOT NULL DEFAULT 0"),
    # 出处三件套：章节 / 页码 / 字符偏移（前端高亮定位）
    ("knowledge_chunk", "section_path", "VARCHAR(512)"),
    ("knowledge_chunk", "page_no", "INTEGER"),
    ("knowledge_chunk", "char_start", "INTEGER"),
    ("knowledge_chunk", "char_end", "INTEGER"),
)

#: 已实现补列逻辑的方言。其他方言不猜 DDL，只告警跳过 —— 启动流程不因此失败。
_SUPPORTED_MIGRATION_DIALECTS = frozenset({"postgresql", "sqlite"})

#: 资源治理扩展（P0）需要「保证存在」的后加列，格式同 ``_KNOWLEDGE_COLUMN_UPGRADES``。
#: 新表（``gpu_node`` / ``resource_metric``）由 ``create_all`` 自动建，不在此列。
_EXPANSION_COLUMN_UPGRADES: tuple[tuple[str, str, str], ...] = (
    # D3 成本归属与按团队下钻的高频聚合列（架构 §1.1）
    ("resource", "owner_team", "VARCHAR(64)"),
    # CMDB 资产编号：物理机与云主机的关联键
    ("resource", "asset_tag", "VARCHAR(64)"),
    # 判定规则标识，便于规则级回归与看板分组
    ("resource_diff", "rule_code", "VARCHAR(64)"),
    # 安全事件的项目归属（读取侧按项目授权收口）；存量库必须补列，
    # 否则 security_events 查询会因缺列直接 500。ALTER 不带外键约束，
    # 与 create_all 新建表的差异仅限约束层（可接受，见本模块迁移约定）。
    ("security_event", "project_id", "VARCHAR(64)"),
)

#: 扩展新增的索引（存量库同样需要，``create_all`` 不会给已存在的表加索引）。
#: 全部用 ``CREATE INDEX IF NOT EXISTS``，双方言幂等。
_EXPANSION_INDEX_UPGRADES: tuple[tuple[str, str, str], ...] = (
    ("ix_resource_project_kind", "resource", "project_id, kind"),
    ("ix_resource_project_level", "resource", "project_id, classification"),
    ("ix_diff_project_status_detected", "resource_diff", "project_id, status, detected_at"),
    # 安全事件按项目 + 时间倒序列表（audit 路由的唯一查询形态）
    ("ix_security_event_project_ts", "security_event", "project_id, ts"),
)

#: 历史版本的 ``JSONDictType.process_bind_param`` 对所有方言都返回 ``json.dumps``
#: 的字符串，PostgreSQL 于是把 jsonb 列存成「JSON 字符串标量」（``jsonb_typeof`` =
#: ``'string'``）。后果不是读不出来——ORM 的 ``json_loads`` 会再解析一次——而是
#: **SQL 侧按元数据过滤恒为空**：``metadata_json->>'actor'`` 返回 NULL，备份审计/
#: 看板/导出这类真去 SQL 里查的场景会静默少数据。写入路径已修，存量行由
#: ``_migrate_json_string_scalars`` 一次性还原。列清单见 ``_json_dict_columns()``。


def _json_dict_columns() -> tuple[tuple[str, str], ...]:
    """**从模型推导**所有 ``JsonDict`` 列，而不是手写清单。

    手写清单漏一列不会有任何报错：那一列的历史行永远留在字符串标量形态，直到将来
    有人第一次在 SQL 里按它过滤——这正是本缺陷当初活下来的方式（首版只列了 4 列，
    模型里实际有 13 列）。因此这里改成运行时枚举，并有一条测试断言覆盖完整。
    """
    from rg_contracts.db import models  # noqa: F401  确保模型已注册到 metadata
    from rg_contracts.db.base import Base, JSONDictType

    return tuple(
        (table.name, column.name)
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, JSONDictType)
    )


def _migrate_knowledge_columns(engine: Engine) -> None:
    """P1 数据迁移：给存量库补齐知识库出处列（幂等，可反复执行）。

    背景：``create_all`` 只建缺失的表，不会修改已存在的表。P1 给
    ``knowledge_document`` 增加 ``source_type`` / ``source_path`` / ``page_count``，
    给 ``knowledge_chunk`` 增加 ``section_path`` / ``page_no`` / ``char_start`` /
    ``char_end``；新库由 ``create_all`` 一次建全，**存量库必须显式 ADD COLUMN**，
    否则按 ``rule`` 步骤升级上去的实例一读知识库就报「no such column」。

    幂等与安全约定：
    - 逐列判断（PG 查 ``information_schema.columns``，SQLite 查 ``PRAGMA table_info``），
      缺哪列补哪列，已存在即跳过；
    - 表不存在时整体跳过（新库路径下所有列都已存在，本函数天然是空操作）；
    - 新增列全部「可空」或「非空 + 常量默认」，存量行按默认值回填，
      不重写、不删除任何既有列与既有数据；
    - 不支持的方言不猜 DDL，记一条告警后返回；
    - 所有 ALTER 在同一个事务内提交：中途失败整体回滚，不留半套结构。

    参数化说明：表名/列名/类型全部来自本模块常量（不含外部输入），
    因此 DDL 用字面量拼接；值一律走绑定参数。
    """
    dialect = engine.dialect.name
    logger = get_logger(__name__)
    if dialect not in _SUPPORTED_MIGRATION_DIALECTS:
        log_event(
            logger,
            logging.WARNING,
            "knowledge column migration skipped: unsupported dialect",
            dialect=dialect,
        )
        return

    added: list[str] = []
    with engine.begin() as conn:
        # 每张表只查一次列清单，避免逐列重复 introspection
        columns_by_table: dict[str, set[str] | None] = {}
        for table, column, column_ddl in _KNOWLEDGE_COLUMN_UPGRADES:
            if table not in columns_by_table:
                columns_by_table[table] = _existing_columns(conn, dialect, table)
            existing = columns_by_table[table]
            if existing is None or column in existing:
                continue
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {column_ddl}"))
            existing.add(column)
            added.append(f"{table}.{column}")

    if added:
        log_event(
            logger,
            logging.INFO,
            "knowledge columns added to existing schema",
            columns=",".join(added),
        )


def _migrate_expansion_columns(engine: Engine) -> None:
    """P0 资源治理扩展迁移：给存量库补列 + 补索引（幂等，可反复执行）。

    与 ``_migrate_knowledge_columns`` 同一套约定：逐列 introspection、缺哪补哪、
    表不存在即跳过、不支持的方言告警跳过、所有 DDL 在同一事务内提交。

    **新表不在这里处理**：``gpu_node`` / ``resource_metric`` 已注册进
    ``Base.metadata``，由 ``ensure_schema`` 的 ``create_all`` 自动建，
    这也是方案 A′（锚点唯一 + 属性分表）"迁移代码量为 0"的由来。

    易替换性：架构师正在评估 ``ensure_schema`` / ``create_all`` 的治理方案，
    若结论要求改走别的迁移方式，替换本函数与上面两个常量即可，模型定义不受影响。
    """
    dialect = engine.dialect.name
    logger = get_logger(__name__)
    if dialect not in _SUPPORTED_MIGRATION_DIALECTS:
        log_event(
            logger,
            logging.WARNING,
            "expansion migration skipped: unsupported dialect",
            dialect=dialect,
        )
        return

    added: list[str] = []
    with engine.begin() as conn:
        columns_by_table: dict[str, set[str] | None] = {}
        for table, column, column_ddl in _EXPANSION_COLUMN_UPGRADES:
            if table not in columns_by_table:
                columns_by_table[table] = _existing_columns(conn, dialect, table)
            existing = columns_by_table[table]
            if existing is None or column in existing:
                continue
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {column_ddl}"))
            existing.add(column)
            added.append(f"{table}.{column}")
        # 索引：create_all 只给「新建的表」建索引，存量表的新索引要显式补
        for index_name, table, columns in _EXPANSION_INDEX_UPGRADES:
            if table not in columns_by_table:
                columns_by_table[table] = _existing_columns(conn, dialect, table)
            if columns_by_table[table] is None:
                continue  # 表不存在（新库路径下 create_all 已建全）
            conn.execute(
                text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({columns})")
            )
            added.append(f"index:{index_name}")

    if added:
        log_event(
            logger,
            logging.INFO,
            "expansion columns/indexes added to existing schema",
            objects=",".join(added),
        )


def _migrate_json_string_scalars(engine: Engine) -> None:
    """把存量「JSON 字符串标量」还原成真正的 jsonb 对象（幂等，仅 PG）。

    旧实现把 dict 先 ``json.dumps`` 再写进 jsonb 列，PG 存下的是一个**字符串标量**，
    于是 ``metadata_json->>'actor'`` 恒为 NULL。这里用 ``#>> '{}'`` 取出字符串标量的
    内层文本再 ``::jsonb`` 解析回来；内层文本必然本身是合法 JSON——它当初能写进 jsonb
    列，说明已通过 jsonb 解析。

    只处理内层文本以 ``{`` 开头的行：``JsonDict`` 语义是 dict，其余形态（数字/布尔/
    数组）不是本列能产生的值，不去猜。``WHERE jsonb_typeof(...) = 'string'`` 让迁移
    对已修好的行是空操作，可反复执行。
    """
    logger = get_logger(__name__)
    if engine.dialect.name != "postgresql":
        return  # SQLite 的 JsonDict 本来就是文本列，不需要也不应该改
    targets = _json_dict_columns()
    if not targets:
        logger.warning("json_dict_columns_not_found")  # 模型未注册：不该发生，但别静默
        return
    converted = 0
    with engine.begin() as conn:
        for table, column in targets:
            if _existing_columns(conn, "postgresql", table) is None:
                continue
            # 表名/列名一律加双引号：``user`` 是 PostgreSQL 保留字，不加引号直接语法错误。
            # 名字来自模型元数据（可信），不是外部输入，因此可以安全拼接。
            result = conn.execute(
                text(
                    f'UPDATE "{table}" SET "{column}" = ("{column}" #>> \'{{}}\')::jsonb '
                    f'WHERE jsonb_typeof("{column}") = \'string\' '
                    f'AND left(ltrim("{column}" #>> \'{{}}\'), 1) = \'{{\''
                )
            )
            converted += result.rowcount or 0
    if converted:
        log_event(
            logger,
            logging.INFO,
            "json string scalars normalized to jsonb objects",
            rows=converted,
            columns=",".join(f"{t}.{c}" for t, c in targets),
        )


def _existing_columns(conn: Connection, dialect: str, table: str) -> set[str] | None:
    """读取表的现有列名；表不存在（或方言无法判定）时返回 None。"""
    if dialect == "postgresql":
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = :table"
            ),
            {"table": table},
        ).scalars().all()
        return set(rows) if rows else None
    # SQLite：PRAGMA 不支持绑定参数，表名来自本模块常量，可安全拼接
    rows = conn.execute(text(f"PRAGMA table_info({table})")).all()
    if not rows:
        return None
    # PRAGMA table_info 的列序：cid, name, type, notnull, dflt_value, pk
    return {str(row[1]) for row in rows}


def _migrate_legacy_vector_columns(engine: Engine) -> None:
    """P0-1 数据迁移：把历史 bytea 向量列改写为 pgvector ``vector(dim)``。

    背景：P0-1 修复前，PG 方言下 ``Vector`` 列被 ``load_dialect_impl`` 建成
    ``bytea``（见 ``rg_contracts.db.vector`` 的修复记录），而
    ``create_all`` 不会修改已存在的列，存量库需要显式 ALTER 才能用上
    pgvector 的向量算子与 HNSW 索引。

    幂等性与生产安全：
    - 列已是 ``vector`` 或列/表不存在时为空操作，可反复执行；
    - bytea -> vector 不存在隐式转换，必须显式 USING。旧代码在 PG 上从未
      成功写入过向量列（bind 阶段即 ``TypeError``），存量数据必然为 NULL；
      USING 子句对 NULL 原样透传，对理论上的存量 bytea 文本字面量按
      UTF-8 解码后转 vector；
    - 如 bytea 中是无法解析的内容（二进制格式等），转换失败并抛出明确
      错误，由运维显式决策，本函数不静默丢弃数据。
    """
    from rg_contracts.db.vector import EMBEDDING_DIM_HINT

    with engine.begin() as conn:
        udt_name = conn.execute(
            text(
                "SELECT udt_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'knowledge_chunk' AND column_name = 'embedding'"
            )
        ).scalar_one_or_none()
        if udt_name != "bytea":
            # 已是 vector / 列不存在（建表即新 schema）/ 其他未知类型均不处理
            return
        conn.execute(
            text(
                f"ALTER TABLE knowledge_chunk ALTER COLUMN embedding "
                f"TYPE vector({EMBEDDING_DIM_HINT}) "
                f"USING CASE WHEN embedding IS NULL THEN NULL::vector({EMBEDDING_DIM_HINT}) "
                f"ELSE convert_from(embedding, 'UTF8')::vector({EMBEDDING_DIM_HINT}) END"
            )
        )


def reset_engine_state() -> None:
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def db_session() -> Iterator[Session]:
    """FastAPI dependency：请求会话。

    与 ``session_scope`` 的差别只有一处、但很关键：请求会话**先登记一个
    「无授权」作用域**（``REQUEST_SCOPE``），认证成功后由 ``current_subject``
    升级为真实作用域。于是「新接口忘了依赖认证」读受保护表只会得到空结果，
    而不是系统通道的全量数据——后者是 RLS 最容易被悄悄绕开的方式。
    """
    with session_scope() as session:
        session.info[rls.RLS_INFO_KEY] = rls.REQUEST_SCOPE
        yield session
