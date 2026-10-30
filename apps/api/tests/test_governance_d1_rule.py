"""D1 利用率/浪费判定：规则纯函数 + 采集端到端闭环。

对应 ``docs/impl-plan-expansion-p0.md`` S5 的验收口径：
- ``allocated_gpus=4`` 且 ``gpu_utilization=5.0`` → 产出 1 条 ``UTILIZATION_WASTE``；
- ``gpu_utilization=85.0`` → 不产出；
- 没有指标 → 不产出（**不把缺失当 0**）；
- 治理项 ``classification`` 取对象有效密级，低密级用户看不到高密级项目的治理项。
"""

from __future__ import annotations

import pytest
from rg_contracts.db.models import CloudAccount, GpuNode, Organization, Project, Resource, ResourceDiff
from rg_contracts.db.session import get_session_factory
from rg_contracts.enums import Platform
from rg_contracts.governance import RULES, RuleAnchor, evaluate
from rg_contracts.governance.rules import D1_GPU_UTILIZATION_WASTE
from sqlalchemy import select

PROJECT_L3 = "prj_gpu_probe_l3"
PROJECT_L4 = "prj_gpu_probe_l4"
ACCOUNT_L3 = "acc_gpu_probe_l3"
ACCOUNT_L4 = "acc_gpu_probe_l4"


def _anchor(**overrides) -> RuleAnchor:
    base = dict(
        resource_id="res_probe",
        native_id="sim-gpu-0001",
        project_id=PROJECT_L3,
        classification="L3_CONFIDENTIAL",
        name="gpu_node-probe",
        kind="gpu_node",
        platform="qingcloud",
        monthly_cost_cny=8000.0,
        metrics={"gpu_utilization": 5.0},
        details={"allocated_gpus": 4},
    )
    base.update(overrides)
    return RuleAnchor(**base)


# --------------------------------------------------------------- 规则层（纯函数）
def test_d1_fires_on_allocated_but_idle_gpu():
    records = evaluate([_anchor()])
    assert len(records) == 1
    record = records[0]
    assert record.diff_kind == "UTILIZATION_WASTE"
    assert record.rule_code == D1_GPU_UTILIZATION_WASTE
    assert record.project_id == PROJECT_L3
    assert record.resource_id == "res_probe"
    assert record.payload["allocated_gpus"] == 4
    assert record.payload["gpu_utilization"] == 5.0


def test_d1_skips_busy_gpu():
    assert evaluate([_anchor(metrics={"gpu_utilization": 85.0})]) == []


def test_d1_skips_missing_metric_instead_of_treating_it_as_zero():
    """缺失 ≠ 0：没有指标时判 unknown，绝不能因为"读到 None"就报浪费。"""
    assert evaluate([_anchor(metrics={})]) == []


def test_d1_skips_when_allocation_unknown_or_zero():
    assert evaluate([_anchor(details={})]) == []
    assert evaluate([_anchor(details={"allocated_gpus": 0})]) == []
    # bool 不是数量：``int(True)`` 会悄悄变成"分配了 1 张卡"
    assert evaluate([_anchor(details={"allocated_gpus": True})]) == []


def test_d1_skips_non_gpu_kinds():
    assert evaluate([_anchor(kind="vm", metrics={"cpu_utilization": 5.0})]) == []


def test_rule_registry_is_non_empty():
    assert {rule.code for rule in RULES} == {D1_GPU_UTILIZATION_WASTE}


# --------------------------------------------------------------- 采集端到端
@pytest.fixture(scope="module")
def gpu_env(client, gov_headers):
    """两个项目（L3/L4）+ 两个只产 GPU 节点的账号，避免污染既有计数断言。"""
    from rg_contracts.auth.sessions import hash_password  # noqa: F401  (保持与其它用例同源)

    factory = get_session_factory()
    with factory() as s:
        if s.get(Project, PROJECT_L3) is None:
            s.add(Organization(id="org_gpu_probe", name="GPU 判定组织", code="GPU-PROBE"))
            s.add(Project(id=PROJECT_L3, code="GPU-L3", name="GPU 判定 L3", org_id="org_gpu_probe",
                          classification="L3_CONFIDENTIAL", business_criticality=3))
            s.add(Project(id=PROJECT_L4, code="GPU-L4", name="GPU 判定 L4", org_id="org_gpu_probe",
                          classification="L4_SECRET", business_criticality=3))
            for account_id, project_id in ((ACCOUNT_L3, PROJECT_L3), (ACCOUNT_L4, PROJECT_L4)):
                s.add(
                    CloudAccount(
                        id=account_id,
                        platform=Platform.QINGCLOUD.value,
                        name=f"GPU 判定账号 {project_id}",
                        endpoint="",
                        region="cn-north-1",
                        enabled=True,
                        options={
                            "project_ids": [project_id],
                            "resource_count": 0,
                            "gpu_nodes": 4,
                        },
                    )
                )
            s.commit()

    first = client.post("/api/v1/collection/run", json={"account_id": ACCOUNT_L3}, headers=gov_headers)
    assert first.status_code == 200, first.text
    return {"l3": first.json(), "headers": gov_headers}


def test_collection_writes_gpu_details_and_d1_items(gpu_env, session):
    body = gpu_env["l3"]
    assert body["resources"] == 4, body
    # 4 个节点里偶数序号（0/2）给 5% 利用率、奇数序号给 60%-99% → 恰好 2 条
    assert body["rule_diffs"] == 2, body
    assert body["diffs"] == 2, body

    rows = session.execute(
        select(ResourceDiff.diff_kind, ResourceDiff.rule_code, ResourceDiff.classification)
        .join(Resource, Resource.id == ResourceDiff.resource_id)
        .where(Resource.account_id == ACCOUNT_L3)
    ).all()
    assert {row.diff_kind for row in rows} == {"UTILIZATION_WASTE"}
    assert {row.rule_code for row in rows} == {D1_GPU_UTILIZATION_WASTE}
    assert {row.classification for row in rows} == {"L3_CONFIDENTIAL"}

    nodes = session.execute(
        select(GpuNode)
        .join(Resource, Resource.id == GpuNode.resource_id)
        .where(Resource.account_id == ACCOUNT_L3)
    ).scalars().all()
    assert len(nodes) == 4
    assert {node.allocated_gpus for node in nodes} == {4}
    assert {node.total_gpus for node in nodes} == {8}

    # 属性分表吸收后，锚点 attributes 不再重复保存 gpu 专属键
    attributes = session.execute(
        select(Resource.attributes).where(Resource.account_id == ACCOUNT_L3)
    ).scalars().all()
    assert attributes
    for item in attributes:
        assert "allocated_gpus" not in item, item
        assert "gpu_model" not in item, item


def test_second_collection_does_not_duplicate_open_items(gpu_env, client):
    """同一条结论只在 open 状态建一次；否则每轮采集都会把看板灌满重复项。"""
    again = client.post(
        "/api/v1/collection/run", json={"account_id": ACCOUNT_L3}, headers=gpu_env["headers"]
    )
    assert again.status_code == 200, again.text
    assert again.json()["rule_diffs"] == 0, again.text


def test_d1_items_visible_on_board(gpu_env, client):
    board = client.get(
        "/api/v1/governance/board", params={"project_id": PROJECT_L3}, headers=gpu_env["headers"]
    )
    assert board.status_code == 200, board.text
    body = board.json()
    codes = {item.get("rule_code") for item in body["items"]}
    assert D1_GPU_UTILIZATION_WASTE in codes, body
    assert "UTILIZATION_WASTE" in body["by_kind"], body


def test_d1_items_follow_project_level_not_caller_ceiling(gpu_env, client, session):
    """L4 项目的治理项：L3 治理岗不可见（密级取对象有效密级，不是调用者上限）。"""
    run = client.post(
        "/api/v1/collection/run", json={"account_id": ACCOUNT_L4}, headers=gpu_env["headers"]
    )
    assert run.status_code == 200, run.text
    assert run.json()["rule_diffs"] == 2, run.text

    rows = session.execute(
        select(ResourceDiff.classification)
        .join(Resource, Resource.id == ResourceDiff.resource_id)
        .where(Resource.account_id == ACCOUNT_L4)
    ).scalars().all()
    assert set(rows) == {"L4_SECRET"}

    diffs = client.get(
        "/api/v1/resources/diffs", params={"project_id": PROJECT_L4}, headers=gpu_env["headers"]
    )
    assert diffs.status_code == 200
    assert diffs.json() == []
