"""PostgreSQL 行级安全（RLS）：应用层授权之外的第二道防线。

为什么需要第二道防线
--------------------
本项目的数据边界完全由应用层拼进 ``WHERE``（``ai/retrieval.py`` 的项目/密级
预过滤、``routes/*`` 的 ``scoped_project_ids``）。这在「每条查询都写对了」时是
够的，但任何一个新接口漏写一个 ``where``、任何一个 ``select count(*)`` 聚合，
都会直接越权，而且**测试与代码评审都很难发现**——漏的是条件，不是分支。

RLS 把同一条边界再表达一次在数据库里：即使应用层漏写条件，会话级 GUC
（``app.rls_*``）仍会让数据库只返回授权范围内的行。两道防线**同时存在**，
RLS 不替换应用层过滤。

核心约定
--------
1. **会话作用域由 GUC 携带**（``SET LOCAL`` 语义，事务结束自动失效）：
   ``app.rls_mode`` / ``app.rls_projects`` / ``app.rls_unrestricted`` /
   ``app.rls_levels`` / ``app.rls_anchor_ids``。取值由 :class:`RlsScope` 生成，
   只来自已认证的 ``Subject`` 与已授权锚点，不接受客户端输入。
2. **``app.rls_mode = 'system'`` 是显式的系统通道**：迁移、种子、保留策略、
   备份、测试夹具走这条路。它不是「忘了设上下文」，而是有意的旁路，用于
   与用户请求区分开。
3. **未设上下文 = 拒绝**：如果某个会话既没设作用域、也没设 system 模式，
   策略表达式里的 ``current_setting(..., true)`` 返回 NULL，整条策略为
   NULL（数据库按拒绝处理）。这是 fail-closed：宁可查不到，不可多查。
4. **粗化是有意的**：RLS 用「用户总体上限 ∩ 项目上限」逐项目表达密级，
   与 ``Subject.ceiling_for`` 一致；但角色能力（谁能读审计、谁能导出）
   仍只由应用层判断——RLS 管「行」，不管「操作」。

前置条件（重要）
----------------
``SUPERUSER`` 与带 ``BYPASSRLS`` 属性的角色会**绕过所有策略**，此时 RLS 是
装饰品。部署时应用连接必须使用普通角色；:func:`bypassing_role` 用于启动时
探测并告警，不静默放过。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from rg_contracts.enums import CLASSIFICATION_ORDER, classification_rank
from rg_contracts.logging_setup import get_logger, log_event

logger = get_logger(__name__)

#: ``Session.info`` 里存放当前作用域的键。为什么放在 session 而不是
#: ``ContextVar``：FastAPI 的同步依赖与同步端点可能跑在不同的工作线程上，
#: 线程间不共享 ContextVar 的写入；而同一个请求共享同一个 Session 实例，
#: 挂在 session 上既准确又不会跨请求泄漏。
RLS_INFO_KEY = "rls_scope"

_GUC_MODE = "app.rls_mode"
_GUC_PROJECTS = "app.rls_projects"
_GUC_UNRESTRICTED = "app.rls_unrestricted"
_GUC_LEVELS = "app.rls_levels"
_GUC_ANCHORS = "app.rls_anchor_ids"

_SET_SCOPE_SQL = (
    "SELECT set_config(:mode_key, :mode, true), "
    "set_config(:projects_key, :projects, true), "
    "set_config(:unrestricted_key, :unrestricted, true), "
    "set_config(:levels_key, :levels, true), "
    "set_config(:anchors_key, :anchors, true)"
)


@dataclass(frozen=True)
class RlsScope:
    """一次会话的行级可见范围。``mode='system'`` 表示有意的系统旁路。"""

    mode: str = "system"
    subject_id: str | None = None
    projects: frozenset[str] = frozenset()
    #: 项目 → 该项目内可见的最高密级（已按 ``min(用户上限, 项目上限)`` 收紧）
    ceilings: dict[str, str] = field(default_factory=dict)
    #: 用户总体密级上限，用于 ``project_id IS NULL`` 的全局知识与未知项目
    ceiling: str | None = None
    #: 管理员/治理岗：项目维度不设限（密级仍受限）
    unrestricted: bool = False
    #: 已授权锚点（``resource.id``）集合，只给「没有项目列」的属性表用。
    #: 空集合 = 一行业务属性都读不到（fail-closed）。它由
    #: :func:`scope_anchor_ids` 从已受策略约束的 ``resource`` 查询结果授予，
    #: 因此不会比 ``projects`` / ``ceilings`` 更宽。
    anchor_ids: frozenset[str] = frozenset()

    @classmethod
    def from_subject(cls, subject: Any) -> "RlsScope":
        """从已认证的 ``Subject`` 构造作用域。

        这里只读 ``Subject``（服务端解析结果），不读任何请求参数——客户端
        传入的项目 ID 只能收紧范围（由路由先校验），不能扩大。
        """
        from rg_contracts.security.policy import default_engine

        unrestricted = default_engine().build_scope(subject).unrestricted
        projects = frozenset(subject.project_ids)
        return cls(
            mode="scoped",
            subject_id=subject.user_id,
            projects=projects,
            ceilings={pid: subject.ceiling_for(pid) for pid in projects},
            ceiling=subject.classification_ceiling,
            unrestricted=unrestricted,
        )

    def level_ranks(self) -> dict[str, int]:
        """密级上限的数值映射，供策略里的 ``CASE`` 比较使用。

        ``"*"`` 是全局知识（``project_id IS NULL``）与「不在映射里的项目」的
        回退值，与 ``Subject.ceiling_for`` 对未知项目的回退语义一致（都取用户
        总体上限）。

        两种「没有上限」要分开处理（实测踩过）：``ceiling`` 为空表示**没有拿到
        授权信息**，必须给 -1 → 一行都读不到；``ceiling`` 非空但不合法（拼写
        错误、尾随空格）才走 ``classification_rank`` 的 L4 回退，与应用层
        ``levels_at_or_below`` 的口径一致。若把两者都当 L4，"漏设作用域"就会
        变成"看得见 L4"，这正是 RLS 要防的那种事故。
        """
        ranks: dict[str, int] = {"*": self._rank_or_deny(self.ceiling)}
        for pid, ceiling in self.ceilings.items():
            ranks[pid] = self._rank_or_deny(ceiling)
        return ranks

    @staticmethod
    def _rank_or_deny(ceiling: str | None) -> int:
        return -1 if not ceiling else classification_rank(ceiling)


SYSTEM_SCOPE = RlsScope()

#: 请求会话的**初始**作用域：什么都没授权，所以什么都读不到。
#: ``db_session`` 用它顶上，只有 ``current_subject`` 解析成功后才会被替换成
#: 真实作用域。这样「新接口忘了声明认证依赖」会得到空结果，而不是系统通道的全量。
#: 后台任务（保留策略、种子、备份、审计写入）走 ``session_scope()``，默认是
#: :data:`SYSTEM_SCOPE`，两条路径在构造处就分开了，不靠调用方自觉。
REQUEST_SCOPE = RlsScope(mode="request")


@dataclass(frozen=True)
class RlsTable:
    """受策略保护的表。

    两种形态：
    - **项目列形态**（默认）：列名固定为 ``project_id``（可选再加 ``classification``）；
    - **锚点形态**（``anchor_only=True``）：表上**没有** ``project_id`` /
      ``classification``（属性、指标分表刻意不冗余这两列，见 ``models.py``
      与 ``docs/impl-plan-expansion-p0.md`` S4），只能以
      ``resource_id = ANY(app.rls_anchor_ids)`` 判定——无子查询、无第二连接，
      没授予锚点就一行都读不到。
    """

    name: str
    has_classification: bool = True
    #: 是否允许 ``project_id IS NULL`` 的行（全局知识）
    global_rows: bool = False
    #: 是否用锚点集合（而非项目 + 密级）判定
    anchor_only: bool = False


#: 受保护的表。为什么是这几张：它们承载「谁的事实/知识/归因」，是越权的直接
#: 目标；``audit_log`` / ``security_event`` 不在本批（读取侧已按项目过滤，
#: 且写入路径多来自系统通道，强行加策略的风险大于收益，见 docs/rls.md）。
RLS_TABLES: tuple[RlsTable, ...] = (
    RlsTable("resource"),
    RlsTable("resource_diff"),
    RlsTable("snapshot_state", has_classification=False),
    RlsTable("knowledge_document", global_rows=True),
    RlsTable("knowledge_chunk", global_rows=True),
    RlsTable("attribution", has_classification=False),
    # 属性/指标分表：密级只在锚点行上，这里只校验锚点集合
    RlsTable("resource_metric", has_classification=False, anchor_only=True),
    RlsTable("gpu_node", has_classification=False, anchor_only=True),
)

_LEVEL_RANK_CASE = (
    'CASE "classification" '
    + " ".join(f"WHEN '{level}' THEN {rank}" for level, rank in CLASSIFICATION_ORDER.items())
    + " ELSE 99 END"
)


def _policy_expression(table: RlsTable) -> str:
    """生成 ``USING`` / ``WITH CHECK`` 共用的布尔表达式。

    结构：``system 通道 OR (项目条件 AND 密级条件)``；锚点形态的表把「项目条件」
    换成「锚点集合条件」。表达式里没有任何子查询，只读当前会话的 GUC 与行上的
    列——这是策略在每行上求值时的性能前提。

    ``NULLIF(current_setting(...), '')`` 是必要的：``string_to_array('', ',')``
    会返回含一个空串的数组而不是 NULL，去掉它才能让「空锚点集合」稳定地
    落到 ``NULL``（数据库按拒绝处理），而不是靠"resource_id 恰好不为空串"。
    """
    if table.anchor_only:
        project = (
            f'"resource_id" = ANY (string_to_array('
            f"NULLIF(current_setting('{_GUC_ANCHORS}', true), ''), ','))"
        )
    else:
        project = (
            f"current_setting('{_GUC_UNRESTRICTED}', true) = 'on' "
            f'OR "project_id" = ANY (string_to_array(current_setting(\'{_GUC_PROJECTS}\', true), \',\'))'
        )
        if table.global_rows:
            project = f"({project}) OR \"project_id\" IS NULL"

    if not table.has_classification:
        level = "true"
    else:
        key = 'COALESCE("project_id", \'*\')' if table.global_rows else '"project_id"'
        level = (
            f"{_LEVEL_RANK_CASE} <= CAST(COALESCE("
            f"current_setting('{_GUC_LEVELS}', true)::jsonb ->> {key}, "
            f"current_setting('{_GUC_LEVELS}', true)::jsonb ->> '*', '-1') AS integer)"
        )

    return (
        f"(current_setting('{_GUC_MODE}', true) = 'system') "
        f"OR (({project}) AND ({level}))"
    )


def apply_to_connection(conn: Connection, scope: RlsScope) -> None:
    """把作用域写进当前事务的会话变量（``set_config(..., is_local=true)``）。

    事务一结束 GUC 自动失效，下一个事务由 ``after_begin`` 重新写入——因此
    「一次请求里多次 commit」不会留下上一次的作用域，也不会丢掉当前作用域。
    """
    if conn.dialect.name != "postgresql":
        return
    conn.execute(
        text(_SET_SCOPE_SQL),
        {
            "mode_key": _GUC_MODE,
            "mode": scope.mode,
            "projects_key": _GUC_PROJECTS,
            "projects": ",".join(sorted(scope.projects)),
            "unrestricted_key": _GUC_UNRESTRICTED,
            "unrestricted": "on" if scope.unrestricted else "off",
            "levels_key": _GUC_LEVELS,
            "levels": json.dumps(scope.level_ranks(), ensure_ascii=False),
            "anchors_key": _GUC_ANCHORS,
            # 排序保证同一集合写出的 GUC 值稳定（测试与日志可比对）
            "anchors": ",".join(sorted(scope.anchor_ids)),
        },
    )


def scope_anchor_ids(session: Session, anchor_ids: Any) -> RlsScope:
    """把「已授权锚点集合」写进当前作用域，并立即应用到当前事务。

    调用方必须是**先查过 ``resource``** 的代码：锚点集合只能来自已受策略与
    应用层双重过滤的资源行（``resource_metric`` / ``gpu_node`` 没有项目列，
    这是唯一的判定依据）。每次调用都**整体替换**而不是累加，避免上一次请求
    或同请求内上一个项目的锚点残留成额外可见范围。

    没有锚点时传空集合：属性表随即变成 0 行（fail-closed），而不是"沿用上一次"。
    """
    # 默认基线必须是 SYSTEM_SCOPE：后台任务/脚本的会话本来就没登记作用域，
    # ``after_begin`` 也是按系统通道处理的。若这里默认成 REQUEST_SCOPE，
    # 一次普通读就会把后台会话从 system 悄悄降成「未授权」（返回 0 行）。
    current = session.info.get(RLS_INFO_KEY, SYSTEM_SCOPE)
    scope = replace(current, anchor_ids=frozenset(anchor_ids))
    session.info[RLS_INFO_KEY] = scope
    conn = session.connection()
    apply_to_connection(conn, scope)
    return scope


def scope_session(session: Session, scope: RlsScope) -> None:
    """给请求会话打上作用域，并立即应用到当前事务。

    立即应用是必要的：认证查询已经开过事务，仅靠 ``after_begin`` 要等到下一次
    事务才会生效，而路由的第一次查询通常就在当前事务里。
    """
    session.info[RLS_INFO_KEY] = scope
    conn = session.connection()
    apply_to_connection(conn, scope)


def scope_session_for_subject(session: Session, subject: Any) -> RlsScope:
    scope = RlsScope.from_subject(subject)
    scope_session(session, scope)
    return scope


def _on_session_after_begin(session: Session, _transaction: Any, conn: Connection) -> None:
    """每个新事务开始时重新写入作用域。

    Session 上没有登记作用域时按 :data:`SYSTEM_SCOPE` 处理——这是**后台任务**
    的通道（``session_scope()``）。HTTP 请求的会话由 ``db_session`` 提前登记
    :data:`REQUEST_SCOPE`，所以「请求忘记认证」不会落到系统通道上。
    """
    if conn.dialect.name != "postgresql":
        return
    apply_to_connection(conn, session.info.get(RLS_INFO_KEY, SYSTEM_SCOPE))


def _on_engine_begin(conn: Connection) -> None:
    """``engine.begin()`` / ``engine.connect()`` 直接使用时走 system 通道。

    迁移、保留策略、备份校验这类系统动作不经过 Session，如果不写 GUC，
    策略会把它们当成「未认证会话」全部拒绝——那会让迁移静默地更新 0 行。
    """
    if conn.dialect.name != "postgresql":
        return
    apply_to_connection(conn, SYSTEM_SCOPE)


_INSTALLED = False


def install_session_listener() -> None:
    """注册 Session 级监听（进程内只需一次，重复调用无副作用）。"""
    global _INSTALLED
    if _INSTALLED:
        return
    event.listen(Session, "after_begin", _on_session_after_begin)
    _INSTALLED = True


def install_engine_listener(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return
    if event.contains(engine, "begin", _on_engine_begin):
        return
    event.listen(engine, "begin", _on_engine_begin)


def _table_exists(conn: Connection, table: str) -> bool:
    found = conn.execute(
        text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = :table"
        ),
        {"table": table},
    ).scalar_one_or_none()
    return found is not None


def apply_policies(engine: Engine) -> list[str]:
    """幂等地创建/刷新策略（仅 PG；表不存在时跳过）。

    每张表固定三步：``ENABLE`` + ``FORCE`` + 重建策略。
    - ``FORCE`` 让**表属主**也受策略约束——测试库与单机部署里，应用用户常常
      就是建表用户，只 ``ENABLE`` 的话策略对属主形同虚设；
    - ``DROP POLICY IF EXISTS`` 再 ``CREATE`` 是为了让「改策略表达式」这件事
      在升级时自动生效，不依赖运维手工执行 DDL。
    """
    applied: list[str] = []
    with engine.begin() as conn:
        apply_to_connection(conn, SYSTEM_SCOPE)
        for table in RLS_TABLES:
            if not _table_exists(conn, table.name):
                continue
            policy = f"rls_{table.name}"
            expression = _policy_expression(table)
            conn.execute(text(f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY'))
            conn.execute(text(f'ALTER TABLE "{table.name}" FORCE ROW LEVEL SECURITY'))
            conn.execute(text(f'DROP POLICY IF EXISTS "{policy}" ON "{table.name}"'))
            conn.execute(
                text(
                    f'CREATE POLICY "{policy}" ON "{table.name}" FOR ALL TO PUBLIC '
                    f"USING ({expression}) WITH CHECK ({expression})"
                )
            )
            applied.append(table.name)
    if applied:
        log_event(logger, 20, "rls_policies_applied", tables=",".join(applied))
    return applied


def bypassing_role(engine: Engine) -> dict[str, Any] | None:
    """探测当前连接角色是否会绕过 RLS；返回 ``None`` 表示策略会真正生效。

    这是启动自检的数据来源：``SUPERUSER`` / ``BYPASSRLS`` 角色不受策略约束。
    """
    if engine.dialect.name != "postgresql":
        return None
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT current_user AS role, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one_or_none()
        conn.rollback()
    if row is None:
        return None
    if not (row.rolsuper or row.rolbypassrls):
        return None
    return {"role": row.role, "superuser": bool(row.rolsuper), "bypassrls": bool(row.rolbypassrls)}


def policy_rows(engine: Engine) -> list[dict[str, Any]]:
    """读取当前库上已存在的策略（供自检与测试断言）。"""
    if engine.dialect.name != "postgresql":
        return []
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT tablename AS table, policyname AS policy, cmd "
                "FROM pg_policies WHERE schemaname = current_schema() "
                "ORDER BY tablename"
            )
        ).all()
        conn.rollback()
    return [dict(row._mapping) for row in rows]


__all__ = [
    "RLS_INFO_KEY",
    "RLS_TABLES",
    "REQUEST_SCOPE",
    "RlsScope",
    "RlsTable",
    "SYSTEM_SCOPE",
    "apply_policies",
    "apply_to_connection",
    "bypassing_role",
    "install_engine_listener",
    "install_session_listener",
    "policy_rows",
    "scope_anchor_ids",
    "scope_session",
    "scope_session_for_subject",
]
