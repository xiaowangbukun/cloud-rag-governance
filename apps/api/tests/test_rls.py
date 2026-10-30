"""行级安全（RLS）回归：策略存在、无上下文 fail-closed、作用域与策略同构。

这些断言对应 P0-1 的验收口径，而不是实现细节：

- 受保护表上确实有策略，且策略表达式里**没有子查询**（每行求值，不能被
  数据量放大成 N+1 次扫描）；
- 会话没有作用域时，数据库**返回 0 行**而不是全部——fail-closed；
- 带作用域时，**不带任何 WHERE 的查询**（模拟"应用层漏写条件"）返回的行，
  与「显式按项目 + 密级过滤」的行完全一致；
- 系统通道（迁移/种子/保留）看得到全部行，否则迁移会静默更新 0 行。

PostgreSQL 专属：SQLite 没有 RLS 等价物，相关用例 skip。
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from conftest import is_pg, make_subject
from rg_contracts.db import rls
from rg_contracts.db.models import GpuNode, Resource, ResourceMetric, new_id, ts
from rg_contracts.db.session import get_engine
from rg_contracts.errors import PermissionDeniedError
from rg_contracts.security.policy import default_engine
from sqlalchemy import event, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from rg_api.services import objects

#: 只有「策略真的在拦数据」这组断言依赖 PG；作用域构造与表达式形状在 SQLite
#: 回路里同样要跑（SQLite 上没有 RLS，这两组是唯一能覆盖到的部分）。
requires_pg = pytest.mark.skipif(not is_pg(), reason="RLS 只在 PostgreSQL 上有意义")


# ------------------------------------------------------------------ 作用域构造


def test_scope_from_subject_takes_min_of_user_and_project_ceiling():
    subject = make_subject(
        "gov",  # 伪造角色：能力表里没有它，unrestricted 必须为 False
        "L4_SECRET",
        project_ids=["prj_a", "prj_b"],
        visible_ceilings={"prj_a": "L2_INTERNAL", "prj_b": "L4_SECRET"},
    )
    scope = rls.RlsScope.from_subject(subject)

    assert scope.mode == "scoped"
    assert scope.projects == frozenset({"prj_a", "prj_b"})
    # 项目 a 被项目内上限收紧到 L2，项目 b 保持用户上限 L4
    assert scope.level_ranks() == {"*": 4, "prj_a": 2, "prj_b": 4}
    assert scope.unrestricted is False


def test_scope_marks_admin_and_governance_unrestricted_but_keeps_levels():
    for role in ("admin", "governance"):
        subject = make_subject(role, "L3_CONFIDENTIAL", project_ids=["prj_a"])
        scope = rls.RlsScope.from_subject(subject)
        assert scope.unrestricted is True, f"{role} 应放开项目维度"
        assert scope.level_ranks()["prj_a"] == 3, f"{role} 不得放开密级"
        assert default_engine().build_scope(subject).unrestricted is True


def test_scope_falls_back_to_user_ceiling_for_unknown_project():
    subject = make_subject("viewer", "L2_INTERNAL", project_ids=["prj_a"])
    scope = rls.RlsScope.from_subject(subject)
    # prj_a 没有 visible_ceilings 记录 → ceiling_for 回落用户上限 L2
    assert scope.level_ranks() == {"*": 2, "prj_a": 2}
    assert subject.ceiling_for("prj_unknown") == "L2_INTERNAL"


def test_scope_without_ceiling_denies_everything():
    """没拿到密级上限 = 没有授权信息：不能退回 L4，否则漏设作用域就变成看全 L4。"""
    assert rls.RlsScope(mode="scoped").level_ranks() == {"*": -1}


def test_unknown_ceiling_is_treated_as_highest_level_not_lowest():
    """脏密级（拼写错误/尾部空格）在 RLS 里必须按 L4 处理，不能降密。"""
    subject = make_subject("viewer", "L3-CONFIDENTIAL", project_ids=["prj_a"])
    assert rls.RlsScope.from_subject(subject).level_ranks() == {"*": 4, "prj_a": 4}


def test_system_scope_is_an_explicit_mode_not_an_absent_scope():
    assert rls.SYSTEM_SCOPE.mode == "system"
    assert rls.SYSTEM_SCOPE.projects == frozenset()
    assert rls.RlsScope().mode == "system"


# -------------------------------------------------------------- 策略表达式形状


def test_policy_expression_has_no_subquery():
    for table in rls.RLS_TABLES:
        expression = rls._policy_expression(table)
        assert "select" not in expression.lower(), f"{table.name} 的策略含子查询"
        assert "current_setting" in expression


def test_policy_expression_references_every_guc():
    expression = rls._policy_expression(rls.RLS_TABLES[0])
    for guc in ("app.rls_mode", "app.rls_projects", "app.rls_unrestricted", "app.rls_levels"):
        assert guc in expression, f"策略漏了 {guc}"


def test_knowledge_tables_allow_global_rows_and_resource_does_not():
    knowledge = rls._policy_expression(rls.RlsTable("knowledge_chunk", global_rows=True))
    project_only = rls._policy_expression(rls.RlsTable("resource"))
    assert '"project_id" IS NULL' in knowledge
    assert '"project_id" IS NULL' not in project_only


def test_tables_without_classification_skip_level_check():
    expression = rls._policy_expression(rls.RlsTable("attribution", has_classification=False))
    assert "classification" not in expression
    assert "app.rls_levels" in expression or "app.rls_mode" in expression


def test_session_listener_installed_once():
    import rg_contracts.db.session  # noqa: F401  (触发模块级安装)

    rls.install_session_listener()
    assert event.contains(Session, "after_begin", rls._on_session_after_begin)


# ------------------------------------------------------------------- PG 生效性


@pytest.fixture(scope="module")
def policies_ready() -> list[str]:
    applied = rls.apply_policies(get_engine())
    assert applied, "ensure_schema 之后受保护表应全部拿到策略"
    return applied


@requires_pg
def test_every_protected_table_has_a_policy(policies_ready):
    rows = rls.policy_rows(get_engine())
    found = {row["table"] for row in rows}
    for table in rls.RLS_TABLES:
        assert table.name in found, f"{table.name} 缺少策略"


@requires_pg
def test_policy_applies_to_all_commands(policies_ready):
    """读写都要拦：只拦 SELECT 会让写入口成为绕过点。"""
    rows = {row["table"]: row for row in rls.policy_rows(get_engine())}
    for table in rls.RLS_TABLES:
        assert rows[table.name]["policy"] == f"rls_{table.name}"
        assert rows[table.name]["cmd"] == "ALL"


@requires_pg
def test_bypassing_role_probe_matches_catalog():
    """自检必须如实反映「当前角色会不会绕过策略」，否则启动告警是假的。"""
    engine = get_engine()
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).scalar_one()
        conn.rollback()
    assert (rls.bypassing_role(engine) is not None) is bool(row)


# ------------------------------------------------------- 非超级用户下的真实拦截

APP_ROLE = "rgtest_rls_app"
_PROTECTED = ", ".join(f'"{t.name}"' for t in rls.RLS_TABLES)


def _drop_app_role(conn) -> None:
    """先撤授权再删角色；角色不存在时是空操作。

    为什么不能直接 ``DROP ROLE IF EXISTS``：只要还有任何授权挂在该角色上，
    PG 会报 ``DependentObjectsStillExist`` 而不是「忽略不存在」。上一轮测试
    异常退出留下的角色会让下一轮在 fixture **setup** 阶段就失败。
    """
    exists = conn.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": APP_ROLE}
    ).scalar_one_or_none()
    if exists is None:
        return
    conn.execute(text(f"REVOKE ALL ON {_PROTECTED} FROM {APP_ROLE}"))
    conn.execute(text(f"REVOKE ALL ON SCHEMA public FROM {APP_ROLE}"))
    conn.execute(text(f"DROP ROLE {APP_ROLE}"))


@pytest.fixture(scope="module")
def app_role_ready(policies_ready):
    """建一个 NOSUPERUSER NOBYPASSRLS 角色：超级用户会绕过策略，测不出真假。"""
    engine = get_engine()
    with engine.begin() as conn:
        _drop_app_role(conn)
        conn.execute(text(f"CREATE ROLE {APP_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))
        conn.execute(text(f"GRANT SELECT ON {_PROTECTED} TO {APP_ROLE}"))
        # 属性/指标分表的写入侧也必须覆盖：运行角色的真实权限是 DML（见
        # docs/rls.md），只给 SELECT 就只测到 USING 那一半，WITH CHECK 无人验证。
        conn.execute(
            text(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON "
                + ", ".join(f'"{name}"' for name in _ANCHOR_TABLES)
                + f" TO {APP_ROLE}"
            )
        )
    try:
        yield APP_ROLE
    finally:
        with engine.begin() as conn:
            _drop_app_role(conn)


@contextmanager
def _as_app_role(scope):
    """以非超级用户身份执行并带上作用域；退出时 ``RESET ROLE`` 归还连接池。"""
    engine = get_engine()
    conn = engine.connect()
    try:
        conn.execute(text(f"SET ROLE {APP_ROLE}"))
        rls.apply_to_connection(conn, scope)
        yield conn
    finally:
        conn.rollback()
        conn.execute(text("RESET ROLE"))
        conn.rollback()
        conn.close()


def _count(conn, table: str, where: str = "", params: dict | None = None) -> int:
    sql = f'SELECT count(*) FROM "{table}"' + (f" WHERE {where}" if where else "")
    return int(conn.execute(text(sql), params or {}).scalar_one())


def _system_counts() -> dict[str, int]:
    engine = get_engine()
    with engine.connect() as conn:
        counts = {table.name: _count(conn, table.name) for table in rls.RLS_TABLES}
        conn.rollback()
    return counts


@requires_pg
def test_raw_connection_is_an_explicit_system_channel(app_role_ready):
    """裸连接（迁移/一次性脚本）显式落到 system 通道，而不是"未授权"。

    这条断言是设计的一部分：如果裸连接被当作未授权，迁移会静默更新 0 行。
    真正要防的「请求忘记认证」由下一条用例覆盖。
    """
    engine = get_engine()
    with engine.connect() as conn:
        mode = conn.execute(text("SELECT current_setting('app.rls_mode', true)")).scalar_one()
        conn.rollback()
    assert mode == "system"


@requires_pg
def test_request_session_without_auth_is_denied(app_role_ready):
    """模拟「新接口忘了依赖 current_subject」：请求会话读受保护表必须为空。"""
    engine = get_engine()
    conn = engine.connect()
    try:
        conn.execute(text(f"SET ROLE {APP_ROLE}"))
        session = Session(bind=conn)
        session.info[rls.RLS_INFO_KEY] = rls.REQUEST_SCOPE
        for table in rls.RLS_TABLES:
            assert _count(session, table.name) == 0, f"{table.name} 对未认证请求可见"
        session.rollback()
    finally:
        conn.rollback()
        conn.execute(text("RESET ROLE"))
        conn.rollback()
        conn.close()


@requires_pg
def test_scope_without_authorization_sees_nothing(app_role_ready):
    """作用域设了但没带密级上限（解析失败/字段缺失）同样必须读不到。"""
    with _as_app_role(rls.RlsScope(mode="scoped")) as conn:
        for table in rls.RLS_TABLES:
            assert _count(conn, table.name) == 0, f"{table.name} 在无授权信息时泄漏了行"


@requires_pg
def test_system_scope_still_sees_everything(app_role_ready):
    """系统通道必须看全，否则迁移/保留/备份会静默更新 0 行。"""
    total = _system_counts()
    with _as_app_role(rls.SYSTEM_SCOPE) as conn:
        for table in rls.RLS_TABLES:
            assert _count(conn, table.name) == total[table.name]


@requires_pg
def test_leaky_query_without_where_is_contained(app_role_ready):
    """模拟「新接口漏写 WHERE」：不带任何条件的全表查询仍被策略限制。"""
    subject = make_subject(
        "pm", "L3_CONFIDENTIAL", project_ids=["prj_core_policy"],
        visible_ceilings={"prj_core_policy": "L3_CONFIDENTIAL"},
    )
    scope = rls.RlsScope.from_subject(subject)
    engine = get_engine()
    with _as_app_role(scope) as conn:
        leaky = _count(conn, "resource")
    with engine.connect() as conn:
        expected = _count(
            conn, "resource", "project_id = :pid AND classification = ANY(:levels)",
            {"pid": "prj_core_policy", "levels": ["L1_PUBLIC", "L2_INTERNAL", "L3_CONFIDENTIAL"]},
        )
        conn.rollback()
    assert leaky == expected, "不带 WHERE 的查询必须和显式授权过滤得到同样的行"
    assert 0 < leaky < _system_counts()["resource"]


@requires_pg
def test_scoped_subject_cannot_read_foreign_project(app_role_ready):
    subject = make_subject(
        "pm", "L3_CONFIDENTIAL", project_ids=["prj_core_policy"],
        visible_ceilings={"prj_core_policy": "L3_CONFIDENTIAL"},
    )
    with _as_app_role(rls.RlsScope.from_subject(subject)) as conn:
        foreign = _count(conn, "resource", "project_id = :pid", {"pid": "prj_data"})
    assert foreign == 0, "跨项目读取没有被挡住"


@requires_pg
def test_project_ceiling_is_enforced_below_user_ceiling(app_role_ready):
    """用户上限 L3、项目上限 L2：项目内的 L3 行不得可见（min 语义）。"""
    subject = make_subject(
        "pm", "L3_CONFIDENTIAL", project_ids=["prj_agent"],
        visible_ceilings={"prj_agent": "L2_INTERNAL"},
    )
    with _as_app_role(rls.RlsScope.from_subject(subject)) as conn:
        visible = _count(conn, "resource", "project_id = :pid", {"pid": "prj_agent"})
        l3 = _count(
            conn, "resource", "project_id = :pid AND classification = 'L3_CONFIDENTIAL'",
            {"pid": "prj_agent"},
        )
    assert l3 == 0
    # 种子数据里 prj_agent 的资源全是 L2，因此「可见 = 项目全部」正是期望值
    assert visible == _count_rows("prj_agent")


def _count_rows(project_id: str) -> int:
    engine = get_engine()
    with engine.connect() as conn:
        value = _count(conn, "resource", "project_id = :pid", {"pid": project_id})
        conn.rollback()
    return value


@requires_pg
def test_global_knowledge_uses_user_ceiling(app_role_ready):
    """project_id 为 NULL 的全局知识按用户上限判定，不能被一并挡掉。"""
    subject = make_subject("viewer", "L2_INTERNAL")  # 无项目成员身份
    with _as_app_role(rls.RlsScope.from_subject(subject)) as conn:
        global_chunks = _count(conn, "knowledge_chunk", "project_id IS NULL")
        project_chunks = _count(conn, "knowledge_chunk", "project_id IS NOT NULL")
    assert global_chunks > 0, "全局知识对无项目的读者应当可见"
    assert project_chunks == 0, "无项目成员身份不得看到项目内知识"


@requires_pg
def test_unrestricted_admin_sees_all_projects_but_not_higher_levels(app_role_ready):
    """管理员放开项目维度，仍受密级约束（与 diff_scope_clause 同构）。"""
    subject = make_subject("admin", "L3_CONFIDENTIAL", project_ids=["prj_agent"])
    scope = rls.RlsScope.from_subject(subject)
    assert scope.unrestricted
    with _as_app_role(scope) as conn:
        l4 = _count(conn, "resource", "classification = 'L4_SECRET'")
        all_visible = _count(conn, "resource")
    assert l4 == 0, "管理员不得越过用户密级上限读 L4"
    assert all_visible > 0


@requires_pg
def test_app_role_cannot_run_ddl(app_role_ready):
    """运行角色只拿 DML：DDL 必须留给属主身份的迁移 Job。

    能改表的角色可以自己 ``DROP POLICY``，兜底就形同虚设；因此这条断言与
    「策略真的在拦数据」同等重要——它守的是权限边界，不是功能。
    """
    engine = get_engine()
    conn = engine.connect()
    try:
        conn.execute(text(f"SET ROLE {APP_ROLE}"))
        with pytest.raises(ProgrammingError):
            conn.execute(text("CREATE TABLE rls_probe_should_fail (id integer)"))
        conn.rollback()
    finally:
        conn.execute(text("RESET ROLE"))
        conn.rollback()
        conn.close()


# ------------------------------------------- 属性/指标分表：锚点集合授权

_ANCHOR_PROJECT = "prj_core_policy"  # 种子：L3_CONFIDENTIAL
_FOREIGN_PROJECT = "prj_data"  # 种子：L4_SECRET
_ANCHOR_TABLES = ("resource_metric", "gpu_node")


def _make_anchor(
    project_id: str, classification: str, tag: str, *, with_attributes: bool = True
) -> str:
    """用系统通道造一条锚点（可选带指标 + GPU 属性；夹具不该被策略挡住）。"""
    engine = get_engine()
    resource_id = new_id("res")
    with Session(engine) as session:
        session.add(
            Resource(
                id=resource_id,
                platform="bluking",
                account_id="acc_bk",
                project_id=project_id,
                native_id=f"node-rls-anchor-{tag}-{resource_id}",
                name=f"rls-anchor-{tag}",
                kind="gpu_node",
                classification=classification,
            )
        )
        if not with_attributes:
            session.commit()
            return resource_id
        session.flush()
        session.add(
            ResourceMetric(
                id=new_id("rm"),
                resource_id=resource_id,
                metric_name="gpu_utilization",
                value=5.0,
                unit="%",
                ts=ts(),
            )
        )
        session.add(
            GpuNode(
                resource_id=resource_id,
                gpu_model="A100",
                total_gpus=8,
                allocated_gpus=4,
                updated_at=ts(),
            )
        )
        session.commit()
    return resource_id


def _drop_anchor(resource_id: str) -> None:
    engine = get_engine()
    with engine.begin() as conn:
        for table in _ANCHOR_TABLES:
            conn.execute(
                text(f'DELETE FROM "{table}" WHERE "resource_id" = :rid'), {"rid": resource_id}
            )
        conn.execute(text('DELETE FROM "resource" WHERE "id" = :rid'), {"rid": resource_id})


@pytest.fixture(scope="module")
def anchor_rows(app_role_ready):
    """三条锚点：可见项目（带属性）、别人的 L4 项目（带属性）、可见项目（空表）。"""
    visible = _make_anchor(_ANCHOR_PROJECT, "L2_INTERNAL", "visible")
    foreign = _make_anchor(_FOREIGN_PROJECT, "L4_SECRET", "foreign")
    # 空表锚点专供写入用例：可见的两条已有指标/属性行，直接 INSERT 会撞主键，
    # 那样测到的就不是策略，而是唯一约束。
    clean = _make_anchor(_ANCHOR_PROJECT, "L2_INTERNAL", "clean", with_attributes=False)
    try:
        yield {"visible": visible, "foreign": foreign, "clean": clean}
    finally:
        for resource_id in (visible, foreign, clean):
            _drop_anchor(resource_id)


def _anchor_scope():
    subject = make_subject(
        "pm",
        "L3_CONFIDENTIAL",
        project_ids=[_ANCHOR_PROJECT],
        visible_ceilings={_ANCHOR_PROJECT: "L3_CONFIDENTIAL"},
    )
    return subject, rls.RlsScope.from_subject(subject)


@requires_pg
def test_attribute_tables_are_contained_by_the_anchor_guc(anchor_rows, app_role_ready):
    """未授予锚点时属性表是 0 行；授予一条也只看到那一条（裸查也一样）。"""
    _subject, scope = _anchor_scope()
    visible_id = anchor_rows["visible"]
    foreign_id = anchor_rows["foreign"]
    with _as_app_role(scope) as conn:
        for table in _ANCHOR_TABLES:
            assert _count(conn, table) == 0, f"{table} 在未授予锚点时泄漏了行"
        conn.execute(
            text("SELECT set_config('app.rls_anchor_ids', :ids, true)"), {"ids": visible_id}
        )
        for table in _ANCHOR_TABLES:
            # 「漏写 WHERE」的全表查询也只能看到被授予的那一条
            assert _count(conn, table) == 1, f"{table} 的全表查询超出了锚点范围"
            assert _count(conn, table, "resource_id = :rid", {"rid": foreign_id}) == 0
            assert _count(conn, table, "resource_id = :rid", {"rid": visible_id}) == 1


#: 两张属性表的写入探针（参数化用；``:id`` 只出现在需要显式主键的表上）
_WRITE_PROBES = (
    (
        "resource_metric",
        'INSERT INTO "resource_metric" (id, resource_id, metric_name, value, unit, ts) '
        "VALUES (:id, :rid, 'write_probe_metric', 5.0, '%', '2026-10-30T00:00:00+00:00')",
    ),
    (
        "gpu_node",
        # mig_enabled 是 NOT NULL 且无库级默认：不显式给值会先撞非空约束，
        # 那样测到的不是策略而是列约束
        'INSERT INTO "gpu_node" (resource_id, gpu_model, total_gpus, mig_enabled, updated_at) '
        "VALUES (:rid, 'write_probe_gpu', 8, false, '2026-10-30T00:00:00+00:00')",
    ),
)


def _insert_params(sql: str, resource_id: str) -> dict[str, str]:
    params = {"rid": resource_id}
    if ":id" in sql:
        params["id"] = new_id("rm")
    return params


@requires_pg
@pytest.mark.parametrize("table,insert_sql", _WRITE_PROBES, ids=[probe[0] for probe in _WRITE_PROBES])
def test_attribute_write_requires_the_same_anchor_grant(
    anchor_rows, app_role_ready, table, insert_sql
):
    """写入侧同一条边界：没授予锚点就写不进属性行（``WITH CHECK`` 那一半）。

    只测 USING（读）会漏掉写入绕过点：能往别人的锚点下写指标或 GPU 属性，
    等于投毒——对方看到的是「自己资源」的伪造读数。两张表都测，是因为策略
    形态相同但列不同（``resource_metric`` 有显式主键，``gpu_node`` 主键即锚点）。
    """
    _subject, scope = _anchor_scope()
    foreign_id = anchor_rows["foreign"]
    clean_id = anchor_rows["clean"]
    with _as_app_role(scope) as conn:
        with pytest.raises(ProgrammingError) as excinfo:
            conn.execute(text(insert_sql), _insert_params(insert_sql, foreign_id))
        # 必须是被策略拒绝，而不是唯一约束/权限之类的别的错误
        assert "row-level security" in str(excinfo.value), str(excinfo.value)
        # 报错后事务已中止，GUC 也随之失效：先重建作用域再测「已授权可写」
        conn.rollback()
        rls.apply_to_connection(conn, scope)
        conn.execute(
            text("SELECT set_config('app.rls_anchor_ids', :ids, true)"), {"ids": clean_id}
        )
        conn.execute(text(insert_sql), _insert_params(insert_sql, clean_id))
        # 写完之后用同一个锚点读回来，顺带验证 USING 与 WITH CHECK 用的是同一条边界
        assert _count(conn, table, "resource_id = :rid", {"rid": clean_id}) == 1


@requires_pg
def test_object_service_never_grants_foreign_anchors(anchor_rows, app_role_ready):
    """服务层只把「resource 查询里看得到的」锚点授予属性表，别人的行永远不进来。"""
    subject, scope = _anchor_scope()
    with _as_app_role(scope) as conn:
        session = Session(bind=conn)
        try:
            rls.scope_session(session, scope)
            metrics = objects.load_metrics(session, project_id=_ANCHOR_PROJECT, subject=subject)
            nodes = objects.load_gpu_nodes(session, project_id=_ANCHOR_PROJECT, subject=subject)
            with pytest.raises(PermissionDeniedError):
                objects.load_metrics(session, project_id=_FOREIGN_PROJECT, subject=subject)
            session.rollback()
        finally:
            session.close()
    assert anchor_rows["visible"] in metrics, "可见项目的锚点被一并挡掉了"
    assert anchor_rows["visible"] in nodes
    assert anchor_rows["foreign"] not in metrics, "别人的指标被锚点授权带进来了"
    assert anchor_rows["foreign"] not in nodes
