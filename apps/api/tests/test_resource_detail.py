"""单资源详情端点（``GET /resources/{id}``）：先授权、后召回的读取顺序。

分表之后，「资源」被拆成三处：锚点行 ``resource``（带项目与密级）、指标
``resource_metric``、GPU 属性 ``gpu_node``。本文件锁住 S6 要求的那条顺序：

1. 查不到锚点行 → 404；
2. 项目不在作用域 → 403（``project_out_of_scope``）；
3. 锚点密级超上限 → 403（``level_exceeded``）；
4. 只有前面都过了，才按锚点集合读指标与 GPU 属性。

第 4 步的顺序意义在于：越权请求不该在内存里先拿到别人的指标再丢掉。
"""

from __future__ import annotations

import pytest
from rg_contracts.db.models import GpuNode, Resource, ResourceMetric, new_id, ts
from sqlalchemy import delete

#: pm@corp.local 的授权项目（种子数据：ceiling=L3，projects=[prj_core_policy]）
PROJECT_ID = "prj_core_policy"
#: pm 无授权的项目（种子数据：L4_SECRET）
FOREIGN_PROJECT = "prj_data"


def _make_resource(session, *, project_id: str, classification: str, name: str, **extra):
    row = Resource(
        id=new_id("res"),
        platform="bluking",
        account_id="acc_bk",
        project_id=project_id,
        native_id=f"node-detail-{new_id('probe')}",
        name=name,
        kind=extra.pop("kind", "gpu_node"),
        classification=classification,
        **extra,
    )
    session.add(row)
    session.flush()
    return row


@pytest.fixture
def detail_resource(session):
    """pm 能访问的项目里一条带指标与 GPU 属性的资源（提交后供 API 会话读取）。"""
    row = _make_resource(
        session,
        project_id=PROJECT_ID,
        classification="L2_INTERNAL",
        name="detail-probe",
        attributes={"owner": "ops", "tags": {"env": "prod"}},
    )
    session.add(
        ResourceMetric(
            id=new_id("rm"),
            resource_id=row.id,
            metric_name="gpu_utilization",
            value=5.0,
            unit="%",
            ts=ts(),
        )
    )
    session.add(
        GpuNode(
            resource_id=row.id,
            gpu_model="A100",
            total_gpus=8,
            allocated_gpus=4,
            updated_at=ts(),
        )
    )
    session.commit()
    try:
        yield row.id
    finally:
        session.execute(delete(GpuNode).where(GpuNode.resource_id == row.id))
        session.execute(delete(ResourceMetric).where(ResourceMetric.resource_id == row.id))
        session.execute(delete(Resource).where(Resource.id == row.id))
        session.commit()


def test_detail_returns_anchor_projection_metrics_and_gpu(client, pm_headers, detail_resource):
    resp = client.get(f"/api/v1/resources/{detail_resource}", headers=pm_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == detail_resource
    assert body["project_id"] == PROJECT_ID
    assert body["classification"] == "L2_INTERNAL"
    # 锚点行只保留通用属性：GPU 键在采集时已剥离到 gpu_node
    assert body["attributes"] == {"owner": "ops", "tags": {"env": "prod"}}
    # 只有采到的指标：缺的键不补 0（缺指标 = unknown，判定层不能当成浪费）
    assert body["metrics"] == {"gpu_utilization": 5.0}
    assert body["gpu"]["gpu_model"] == "A100"
    assert body["gpu"]["allocated_gpus"] == 4


def test_unknown_resource_returns_404(client, pm_headers):
    resp = client.get("/api/v1/resources/res_does_not_exist", headers=pm_headers)
    assert resp.status_code == 404, resp.text


def test_project_out_of_scope_is_denied(session, client, pm_headers):
    row = _make_resource(
        session, project_id=FOREIGN_PROJECT, classification="L4_SECRET", name="detail-foreign"
    )
    session.commit()
    try:
        resp = client.get(f"/api/v1/resources/{row.id}", headers=pm_headers)
        assert resp.status_code == 403, resp.text
        assert "无该项目访问权限" in resp.text
    finally:
        session.execute(delete(Resource).where(Resource.id == row.id))
        session.commit()


def test_level_exceeded_is_denied_even_inside_own_project(session, client, pm_headers):
    """项目授权过了、密级超了，同样拒绝：两关必须都过。"""
    row = _make_resource(
        session, project_id=PROJECT_ID, classification="L4_SECRET", name="detail-over-level"
    )
    session.commit()
    try:
        resp = client.get(f"/api/v1/resources/{row.id}", headers=pm_headers)
        assert resp.status_code == 403, resp.text
        assert "密级" in resp.text
    finally:
        session.execute(delete(Resource).where(Resource.id == row.id))
        session.commit()
