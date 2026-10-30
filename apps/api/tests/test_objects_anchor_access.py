"""属性/指标分表的锚点访问层（``services/objects.py``）与锚点 RLS 策略形态。

``resource_metric`` / ``gpu_node`` 刻意没有 ``project_id`` / ``classification``
（见 ``db/models.py`` 与 ``docs/impl-plan-expansion-p0.md`` S4），所以「这条指标
谁能读」只能由锚点（``resource``）决定。本文件锁住三件事：

1. 读取入口只返回「本主体有权项目 + 密级不超过上限」的锚点所对应的行；
2. 锚点集以外的资源 ID 即使被显式传入也读不到（应用层条件仍在）；
3. 策略表达式是**锚点形态**：无子查询、不含 ``project_id``、引用
   ``app.rls_anchor_ids``。

双方言都跑：SQLite 没有 RLS，第 3 组只是字符串形状断言，第 1、2 组的两道
``WHERE`` 仍是唯一防线（与改造前一致）。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.db import rls
from rg_contracts.db.models import GpuNode, Resource, ResourceMetric, new_id, ts
from rg_contracts.errors import PermissionDeniedError

from rg_api.services import objects

#: 种子项目：L3_CONFIDENTIAL，测试主体有授权
PROJECT_ID = "prj_core_policy"
#: 种子项目：L4_SECRET，测试主体没有授权
FOREIGN_PROJECT = "prj_data"


@pytest.fixture
def anchors(session):
    """造两条锚点 + 各自指标/GPU 属性：一条在可见项目（L2），一条在别人的 L4 项目。

    指标值与 GPU 属性都是「敏感信号」，正是分表要保护的对象；两条行放在一起，
    才能证明可见范围是按锚点逐条判定的，而不是按表一刀切。
    """
    suffix = new_id("probe")
    own = Resource(
        id=new_id("res"),
        platform="bluking",
        account_id="acc_bk",
        project_id=PROJECT_ID,
        native_id=f"node-anchor-own-{suffix}",
        name="anchor-own",
        kind="gpu_node",
        classification="L2_INTERNAL",
    )
    foreign = Resource(
        id=new_id("res"),
        platform="bluking",
        account_id="acc_bk",
        project_id=FOREIGN_PROJECT,
        native_id=f"node-anchor-foreign-{suffix}",
        name="anchor-foreign",
        kind="gpu_node",
        classification="L4_SECRET",
    )
    session.add_all([own, foreign])
    session.flush()
    session.add_all(
        [
            ResourceMetric(
                id=new_id("rm"),
                resource_id=own.id,
                metric_name="gpu_utilization",
                value=5.0,
                unit="%",
                ts=ts(),
            ),
            ResourceMetric(
                id=new_id("rm"),
                resource_id=foreign.id,
                metric_name="gpu_utilization",
                value=3.0,
                unit="%",
                ts=ts(),
            ),
            GpuNode(resource_id=own.id, gpu_model="A100", total_gpus=8, allocated_gpus=4, updated_at=ts()),
            GpuNode(resource_id=foreign.id, gpu_model="H100", total_gpus=8, allocated_gpus=2, updated_at=ts()),
        ]
    )
    session.flush()
    yield {"own": own.id, "foreign": foreign.id}
    # 全部留在未提交事务里，回滚即清理（不污染其他用例的可见集合）
    session.rollback()


def _pm_subject():
    return make_subject(
        "pm", "L3_CONFIDENTIAL", [PROJECT_ID], visible_ceilings={PROJECT_ID: "L3_CONFIDENTIAL"}
    )


def test_load_metrics_returns_only_authorized_anchors(session, anchors):
    metrics = objects.load_metrics(session, project_id=PROJECT_ID, subject=_pm_subject())
    assert metrics[anchors["own"]]["gpu_utilization"] == pytest.approx(5.0)
    assert anchors["foreign"] not in metrics


def test_load_gpu_nodes_mirrors_the_same_boundary(session, anchors):
    nodes = objects.load_gpu_nodes(session, project_id=PROJECT_ID, subject=_pm_subject())
    assert nodes[anchors["own"]]["gpu_model"] == "A100"
    assert nodes[anchors["own"]]["allocated_gpus"] == 4
    assert anchors["foreign"] not in nodes


def test_foreign_project_is_rejected_before_deriving_anchors(session, anchors):
    """锚点集不允许在无授权项目里构造：否则等于绕开列表接口直接读属性。"""
    with pytest.raises(PermissionDeniedError):
        objects.load_metrics(session, project_id=FOREIGN_PROJECT, subject=_pm_subject())


def test_explicit_foreign_resource_id_is_still_filtered_out(session, anchors):
    """显式传入别人的资源 ID 也只会被项目条件挡掉，不会变成「我授权了它」。"""
    metrics = objects.load_metrics(
        session, project_id=PROJECT_ID, subject=_pm_subject(), resource_ids=[anchors["foreign"]]
    )
    assert metrics == {}


def test_level_ceiling_hides_anchor_of_higher_classification(session, anchors):
    """锚点自身密级超上限时，属性行同样读不到（密级判定留在锚点上）。"""
    subject = make_subject("viewer", "L1_PUBLIC", [PROJECT_ID])
    assert anchors["own"] not in objects.load_metrics(session, project_id=PROJECT_ID, subject=subject)
    assert anchors["own"] not in objects.load_gpu_nodes(session, project_id=PROJECT_ID, subject=subject)


def test_anchor_policy_expression_is_keyed_on_resource_id():
    expression = rls._policy_expression(
        rls.RlsTable("resource_metric", has_classification=False, anchor_only=True)
    )
    assert '"resource_id" = ANY' in expression
    assert "app.rls_anchor_ids" in expression
    # 属性表没有项目列与密级列，表达式里出现它们就说明设计被改回去了
    assert '"project_id"' not in expression
    assert "classification" not in expression
    assert "select" not in expression.lower()


def test_attribute_tables_are_registered_as_anchor_tables():
    tables = {table.name: table for table in rls.RLS_TABLES}
    assert {"resource_metric", "gpu_node"} <= set(tables)
    assert tables["resource_metric"].anchor_only and tables["gpu_node"].anchor_only
    assert tables["resource_metric"].has_classification is False
    assert not tables["resource"].anchor_only


def test_scope_anchor_ids_replaces_instead_of_accumulating(session):
    """授予集合是整体替换：残留锚点会变成额外的可见范围。"""
    rls.scope_anchor_ids(session, ["res_a", "res_b"])
    scope = rls.scope_anchor_ids(session, ["res_c"])
    assert scope.anchor_ids == frozenset({"res_c"})
    assert rls.scope_anchor_ids(session, []).anchor_ids == frozenset()
