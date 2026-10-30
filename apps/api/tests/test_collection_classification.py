"""P0-2 验收测试：采集数据密级必须继承项目目录密级。

对应 docs/fix-plan.md §2.2 验收标准：
- QA 测试 1：L4 项目采集后的资源对 L3 治理岗不可见（resources 列表为空）
- QA 测试 2：L4 项目采集后的差异与看板对 L3 治理岗不可见
- QA 测试 4：DB 直查采集资源密级 == 项目密级（L4_SECRET）
- 补充 ⑤：项目密级 L3→L4 提升后再次采集，既有资源密级同步刷新
- 补充 ⑥：未知 project_id 采集失败关闭并留审计

双方言可跑（SQLite 本地 / PG CI）：不依赖演示种子，自建最小实体。
"""
from __future__ import annotations

import pytest
from rg_contracts.db.models import (
    AuditLog,
    CloudAccount,
    Organization,
    Project,
    ProjectMember,
    Resource,
    ResourceDiff,
    Snapshot,
    User,
    new_id,
    ts,
)
from rg_contracts.db.session import get_session_factory
from rg_contracts.enums import Classification, Platform, Role
from sqlalchemy import select

P_L3 = "prj_w1_l3"
P_L4 = "prj_w1_l4"
P_RAISE = "prj_w1_raise"
ACCOUNT = "acc_w1"

GOV_USER = "gov-w1@corp.local"
GOV_PWD = "GovW1@2026"
ADMIN_USER = "admin-w1@corp.local"
ADMIN_PWD = "AdminW1@2026"


def _login(client, username: str, password: str) -> dict[str, str]:
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _run_collection(client, headers: dict, account_id: str | None = None) -> dict:
    body = {"note": "w1 acceptance"}
    if account_id:
        body["account_id"] = account_id
    resp = client.post("/api/v1/collection/run", json=body, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture(scope="session")
def w1(client):
    """自建验收实体 + 两轮采集（基线 12 条 → 增量 15 条，每项目恰好 1 条新增差异）。"""
    from rg_contracts.auth.sessions import hash_password

    factory = get_session_factory()
    with factory() as s:
        exists = s.execute(select(Project.id).where(Project.id == P_L4)).first()
        if exists is None:
            s.add(Organization(id="org_w1", name="W1 验收组织", code="W1-ACC"))
            projects = [(P_L3, Classification.L3_CONFIDENTIAL.value),
                        (P_L4, Classification.L4_SECRET.value),
                        (P_RAISE, Classification.L3_CONFIDENTIAL.value)]
            for pid, level in projects:
                s.add(Project(id=pid, code=pid.upper(), name=pid, org_id="org_w1",
                              classification=level, business_criticality=3))
            s.flush()
            users = [
                ("usr_w1_gov", GOV_USER, Role.GOVERNANCE.value, Classification.L3_CONFIDENTIAL.value, GOV_PWD),
                ("usr_w1_admin", ADMIN_USER, Role.ADMIN.value, Classification.L4_SECRET.value, ADMIN_PWD),
            ]
            for uid, subj, role, ceiling, pwd in users:
                s.add(User(id=uid, subject=subj, display_name=uid, email=subj, role=role,
                           org_id="org_w1", classification_ceiling=ceiling, is_active=True,
                           password_hash=hash_password(pwd), attributes={"w1": True}))
            s.flush()
            # 项目内可见密级上限 = min(用户上限, 项目密级)，与 Subject.ceiling_for 语义一致
            for uid, pid, vis in [
                ("usr_w1_gov", P_L3, "L3_CONFIDENTIAL"),
                ("usr_w1_gov", P_L4, "L3_CONFIDENTIAL"),
                ("usr_w1_gov", P_RAISE, "L3_CONFIDENTIAL"),
                ("usr_w1_admin", P_L3, "L3_CONFIDENTIAL"),
                ("usr_w1_admin", P_L4, "L4_SECRET"),
                ("usr_w1_admin", P_RAISE, "L3_CONFIDENTIAL"),
            ]:
                s.add(ProjectMember(id=new_id("pm"), user_id=uid, project_id=pid,
                                    visible_ceiling=vis, created_at=ts()))
            s.add(CloudAccount(id=ACCOUNT, platform=Platform.QINGCLOUD.value, name="W1 验收账号",
                               endpoint="", region="cn-north-1", credential_ref="QY_CREDENTIALS",
                               enabled=True,
                               options={"project_ids": [P_L3, P_L4, P_RAISE], "resource_count": 12}))
            s.commit()

    gov_headers = _login(client, GOV_USER, GOV_PWD)
    admin_headers = _login(client, ADMIN_USER, ADMIN_PWD)

    r1 = _run_collection(client, gov_headers, account_id=ACCOUNT)
    assert r1["resources"] == 12, r1
    assert r1["diffs"] == 0, r1  # 首轮仅建基线

    # resource_count 12→15：模拟器确定性生成，恰好每项目新增 1 条资源 → 3 条 added 差异
    with factory() as s:
        acc = s.get(CloudAccount, ACCOUNT)
        opts = dict(acc.options or {})
        opts["resource_count"] = 15
        acc.options = opts
        s.commit()

    r2 = _run_collection(client, gov_headers, account_id=ACCOUNT)
    assert r2["resources"] == 15, r2
    assert r2["diffs"] == 3, r2  # 每项目 1 条新增差异（含 L4 项目）

    return {"gov": gov_headers, "admin": admin_headers}


# ---------------------------------------------------------------- QA 测试 1
def test_collected_l4_project_resources_hidden_from_governance(client, w1):
    """QA-1：L4 项目采集后的资源，L3 治理岗读不到（修复前硬编码 L3 导致可读）。"""
    r = client.get("/api/v1/resources", params={"project_id": P_L4}, headers=w1["gov"])
    assert r.status_code == 200
    assert r.json() == [], "L4 项目采集资源对 L3 治理岗必须不可见"

    # 正向对照：L4 管理员能读到，证明数据确实存在、过滤是按密级而非数据缺失
    r = client.get("/api/v1/resources", params={"project_id": P_L4}, headers=w1["admin"])
    assert r.status_code == 200
    assert len(r.json()) >= 1
    assert all(item["classification"] == "L4_SECRET" for item in r.json())


# ---------------------------------------------------------------- QA 测试 2
def test_collected_l4_project_diffs_and_board_hidden_from_governance(client, w1):
    """QA-2：L4 项目采集后的差异与治理看板，L3 治理岗不可见。"""
    r = client.get("/api/v1/resources/diffs", params={"project_id": P_L4}, headers=w1["gov"])
    assert r.status_code == 200
    assert r.json() == []

    r = client.get("/api/v1/governance/board", params={"project_id": P_L4}, headers=w1["gov"])
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["items"] == []

    # 不看板过滤时：L4 项目不出现在任何条目中；L3 项目差异正常可见
    r = client.get("/api/v1/governance/board", headers=w1["gov"])
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(item["project_id"] != P_L4 for item in items)

    r = client.get("/api/v1/governance/board", params={"project_id": P_L3}, headers=w1["gov"])
    assert r.json()["total"] >= 1


# ---------------------------------------------------------------- QA 测试 4
def test_collected_resource_classification_matches_project(w1, session):
    """QA-4：DB 直查——所有采集资源/差异的密级严格等于所属项目密级。"""
    # 只校验本用例自建账号/项目，避免演示种子数据干扰（PG 作业无种子，SQLite 有）
    mismatched_resources = session.execute(
        select(Resource.id, Resource.classification, Project.classification)
        .join(Project, Project.id == Resource.project_id)
        .where(Resource.account_id == ACCOUNT)
        .where(Resource.classification != Project.classification)
    ).all()
    assert mismatched_resources == [], f"存在密级与项目不一致的采集资源: {mismatched_resources[:5]}"

    mismatched_diffs = session.execute(
        select(ResourceDiff.id, ResourceDiff.classification, Project.classification)
        .join(Project, Project.id == ResourceDiff.project_id)
        .where(ResourceDiff.project_id.in_([P_L3, P_L4, P_RAISE]))
        .where(ResourceDiff.classification != Project.classification)
    ).all()
    assert mismatched_diffs == [], f"存在密级与项目不一致的采集差异: {mismatched_diffs[:5]}"

    l4_rows = session.execute(
        select(Resource.classification).where(Resource.project_id == P_L4)
    ).scalars().all()
    assert l4_rows, "L4 项目应有采集资源"
    assert set(l4_rows) == {"L4_SECRET"}


# ---------------------------------------------------------------- 补充 ⑤
def test_project_level_raise_refreshes_resource_classification(client, w1, session):
    """项目密级 L3→L4 后再次采集：既有资源密级同步刷新，治理岗随即不可见。"""
    # 前置确认：提升前 L3 治理岗能看到 prj_w1_raise 的资源
    r = client.get("/api/v1/resources", params={"project_id": P_RAISE}, headers=w1["gov"])
    assert r.status_code == 200 and len(r.json()) >= 1

    with get_session_factory()() as s:
        project = s.get(Project, P_RAISE)
        project.classification = Classification.L4_SECRET.value
        s.commit()

    _run_collection(client, w1["gov"], account_id=ACCOUNT)

    levels = session.execute(
        select(Resource.classification).where(Resource.project_id == P_RAISE)
    ).scalars().all()
    assert levels and set(levels) == {"L4_SECRET"}, "项目升密级后既有资源必须刷新"

    r = client.get("/api/v1/resources", params={"project_id": P_RAISE}, headers=w1["gov"])
    assert r.status_code == 200 and r.json() == [], "项目升密级后治理岗必须不可见"


# ---------------------------------------------------------------- 补充 ⑥
def test_unknown_project_collection_fails_closed_and_audited(client, w1, session):
    """未知 project_id：整账号本次采集失败关闭（不默认 L3 重开缺口）并留审计。"""
    ghost_account = "acc_w1_ghost"
    with get_session_factory()() as s:
        if s.get(CloudAccount, ghost_account) is None:
            s.add(CloudAccount(id=ghost_account, platform=Platform.QINGCLOUD.value,
                               name="W1 幽灵账号", endpoint="", region="cn-north-1",
                               credential_ref="QY_CREDENTIALS", enabled=True,
                               options={"project_ids": [P_L3, "prj_w1_ghost"], "resource_count": 4}))
            s.commit()

    body = _run_collection(client, w1["gov"], account_id=ghost_account)
    assert body["resources"] == 0
    assert body["diffs"] == 0

    snapshot = session.execute(
        select(Snapshot).where(Snapshot.account_id == ghost_account)
    ).scalars().one()
    assert snapshot.status == "failed"
    assert "project_not_in_directory" in (snapshot.error_message or "")

    leaked = session.execute(
        select(Resource.id).where(Resource.account_id == ghost_account)
    ).scalars().all()
    assert leaked == [], "失败关闭路径不得落任何资源"

    audits = session.execute(
        select(AuditLog).where(
            AuditLog.action == "collection:run",
            AuditLog.outcome == "failed",
            AuditLog.reason_code == "project_not_in_directory",
            AuditLog.resource_id == ghost_account,
        )
    ).scalars().all()
    assert audits, "未知项目失败关闭必须留审计"
