"""P1-12 / P1-13 回归：归因出域面必须过密级边界与管理员鉴权。

P1-12：``/attribution/diff/{diff_id}`` 曾只校验项目可见性就直接返回归因结论
（cause / explanation / recommended_action 均从事实域推导，属高敏内容）。
项目内可见 ≠ 密级可读：项目 visible_ceiling 可能低于用户全局上限，
越限 diff 的归因结论一律不返回。

P1-13：``/attribution/gateways`` 曾无任何鉴权，任意登录用户可读网关
base_url / api_key_ref。路由保留（前端 ModelGatewayView 在用），
权限口径与 ``/admin/gateways`` 一致（admin:config）。
"""

from __future__ import annotations

import pytest
from conftest import login
from rg_contracts.db.models import Attribution, ProjectMember, ResourceDiff, new_id, ts
from sqlalchemy import select

# prj_claim 是 L3 项目；auditor 全局上限 L3、仅授权 prj_claim
PROJECT_ID = "prj_claim"
AUDITOR_ID = "usr_auditor"
SENSITIVE_CAUSE = "R12_SENSITIVE_CAUSE"
SENSITIVE_EXPLANATION = "R12_SENSITIVE_EXPLANATION"


def _set_visible_ceiling(session, user_id: str, project_id: str, ceiling: str) -> str:
    """把项目内可见上限改成指定值，返回原值（便于恢复）。"""
    member = session.execute(
        select(ProjectMember).where(
            ProjectMember.user_id == user_id,
            ProjectMember.project_id == project_id,
        )
    ).scalar_one()
    original = member.visible_ceiling
    member.visible_ceiling = ceiling
    session.commit()
    return original


@pytest.fixture
def auditor_headers(client):
    """auditor 登录头（不在 conftest 中定义，避免与并行改动冲突）。"""
    return login(client, "auditor@corp.local", "Audit@2026")


@pytest.fixture
def diff_with_attribution(session):
    """在 prj_claim 造一条 L3 差异 + 一条归因结论（结论文本可识别）。"""
    diff = ResourceDiff(
        id=new_id("diff"),
        project_id=PROJECT_ID,
        platform="aliyun",
        native_id=f"r12-{new_id('x')[-8:]}",
        resource_name="r12-resource",
        kind="vm",
        diff_kind="cost_increase",
        detected_at=ts(),
        cost_delta_cny=128.0,
        classification="L3_CONFIDENTIAL",
        rule_hint="r12-rule-hint",
        summary="r12-summary",
        payload={},
        status="open",
    )
    session.add(diff)
    session.flush()
    attribution = Attribution(
        id=new_id("attr"),
        diff_id=diff.id,
        project_id=PROJECT_ID,
        task_id="task_r12_regression",
        cause=SENSITIVE_CAUSE,
        confidence=0.93,
        explanation=SENSITIVE_EXPLANATION,
        recommended_action="R12_SENSITIVE_ACTION",
        evidence_level="rule",
        provider="internal",
        model_name=None,
        created_at=ts(),
    )
    session.add(attribution)
    session.commit()

    yield {"diff_id": diff.id}

    session.delete(attribution)
    session.delete(diff)
    session.commit()


@pytest.fixture
def lowered_ceiling(session, diff_with_attribution):
    """把 auditor 在 prj_claim 内的上限压到 L2：全局 L3 > 项目内 L2 的越权态。"""
    original = _set_visible_ceiling(session, AUDITOR_ID, PROJECT_ID, "L2_INTERNAL")
    yield
    _set_visible_ceiling(session, AUDITOR_ID, PROJECT_ID, original)


def test_diff_attribution_list_hides_entries_above_project_ceiling(
    client, auditor_headers, session, diff_with_attribution, lowered_ceiling
):
    """核心回归（P1-12）：项目内上限 L2 时，L3 差异的归因结论零返回。

    项目可见（auditor 授权 prj_claim）但密级越限，必须拒绝而不是返回条目。
    """
    resp = client.get(f"/api/v1/attribution/diff/{diff_with_attribution['diff_id']}", headers=auditor_headers)
    assert resp.status_code == 403, resp.text
    body = resp.text
    assert SENSITIVE_CAUSE not in body, "越限归因结论泄漏到响应体"
    assert SENSITIVE_EXPLANATION not in body, "越限归因解释泄漏到响应体"
    assert "R12_SENSITIVE_ACTION" not in body


def test_diff_attribution_list_allows_entries_within_project_ceiling(
    client, auditor_headers, session, diff_with_attribution
):
    """控制组：上限未被压低（L3）时同一差异的归因结论正常返回，防止过度拦截。"""
    resp = client.get(f"/api/v1/attribution/diff/{diff_with_attribution['diff_id']}", headers=auditor_headers)
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["cause"] == SENSITIVE_CAUSE
    assert rows[0]["created_at"], "created_at 不得为方言垫片空串"


def test_attribution_gateways_requires_admin(client, viewer_headers, gov_headers, admin_headers):
    """核心回归（P1-13）：viewer / governance 403，admin 200。"""
    for headers in (viewer_headers, gov_headers):
        resp = client.get("/api/v1/attribution/gateways", headers=headers)
        assert resp.status_code == 403, f"非管理员不得读取网关清单：{resp.status_code}"

    ok = client.get("/api/v1/attribution/gateways", headers=admin_headers)
    assert ok.status_code == 200, ok.text
    assert isinstance(ok.json(), list)


def test_attribution_gateways_requires_authentication(client):
    """未登录同样拒绝。"""
    assert client.get("/api/v1/attribution/gateways").status_code in (401, 403)