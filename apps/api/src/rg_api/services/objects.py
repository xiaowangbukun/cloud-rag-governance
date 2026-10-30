"""受保护属性表（``resource_metric`` / ``gpu_node``）的唯一读取入口。

为什么必须集中在一处
--------------------
这两张表**刻意不持有** ``project_id`` / ``classification``（分表设计见
``db/models.py`` 与 ``docs/impl-plan-expansion-p0.md`` S4）：指标值与 GPU 属性
本身是敏感信号，密级只在锚点行 ``resource`` 上。于是「按项目 + 密级过滤」这件事
只能在锚点上做，读属性表必须先拿到一份**已过滤的锚点集**。

本模块把这条顺序固定下来：

1. 先在 ``resource`` 上按「项目 + 密级上限」查锚点 ID（应用层条件）；
2. 再用 :func:`rg_contracts.db.rls.scope_anchor_ids` 把这批 ID 授予本事务；
3. 最后才读属性表。

第 2 步在 PostgreSQL 上同时是数据库策略
（``"resource_id" = ANY(app.rls_anchor_ids)``）的唯一放行依据：锚点集为空时
属性表是 0 行，所以「调用方漏写 ``WHERE``」只会查不到，不会越权；SQLite 没有
RLS，退化回第 1、3 步的两条 ``WHERE`` 条件（与改造前一致）。

**任何新增的属性/指标表读取都必须走本模块**，不要在路由里直接
``select(ResourceMetric)``——那样读的是没有锚点授权的裸表。
"""

from __future__ import annotations

from typing import Any, Iterable

from rg_contracts.db import rls
from rg_contracts.db.models import GpuNode, Resource, ResourceMetric
from rg_contracts.security.policy import Subject, levels_at_or_below
from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_api.services.access import assert_project_access

#: GPU 属性表对外暴露的字段（不含 ``resource_id``，调用方已经按它作键）
_GPU_FIELDS = (
    "gpu_model",
    "total_gpus",
    "allocated_gpus",
    "driver_version",
    "cuda_version",
    "mig_enabled",
    "asset_tag",
    "updated_at",
)


def visible_anchor_ids(
    session: Session,
    *,
    project_id: str,
    subject: Subject,
    resource_ids: Iterable[str] | None = None,
) -> list[str]:
    """在 ``resource`` 上取「该项目内、密级不超上限」的锚点 ID。

    这里的条件顺序与 ``routes/resources.py::_apply_level_filter`` 一致（项目 →
    密级），保证列表接口与属性表读取看到的是同一批对象。PG 上这层查询还被
    ``resource`` 自身的策略再挡一次，于是锚点集天然不可能越界。

    项目授权先判（与路由同一入口 ``check_project``）：锚点集只允许在本主体有权
    访问的项目内构造，否则「给了项目 ID 就能读别人项目属性」等于绕开列表接口。
    """
    assert_project_access(subject, project_id)
    ceiling = subject.ceiling_for(project_id)
    stmt = select(Resource.id).where(Resource.project_id == project_id)
    stmt = stmt.where(Resource.classification.in_(levels_at_or_below(ceiling)))
    if resource_ids is not None:
        wanted = list(resource_ids)
        if not wanted:
            return []
        stmt = stmt.where(Resource.id.in_(wanted))
    return list(session.execute(stmt.order_by(Resource.id)).scalars().all())


def load_metrics(
    session: Session,
    *,
    project_id: str,
    subject: Subject,
    resource_ids: Iterable[str] | None = None,
) -> dict[str, dict[str, float]]:
    """读取指标最新值：``{resource_id: {metric_name: value}}``。

    返回空字典同时覆盖两种情况：锚点不可见、指标缺失。调用方若要做阈值判定，
    **缺指标必须判 unknown 而不是 0**（见 ``ResourceMetric`` 注释与 PRD §8）。
    """
    anchors = visible_anchor_ids(
        session, project_id=project_id, subject=subject, resource_ids=resource_ids
    )
    # 先授权再读：顺序反过来会在运行角色下被策略拒绝（WITH CHECK 只看锚点集合）
    rls.scope_anchor_ids(session, anchors)
    if not anchors:
        return {}
    rows = session.execute(
        select(ResourceMetric.resource_id, ResourceMetric.metric_name, ResourceMetric.value)
        .where(ResourceMetric.resource_id.in_(anchors))
        .order_by(ResourceMetric.resource_id, ResourceMetric.metric_name)
    ).all()
    out: dict[str, dict[str, float]] = {}
    for resource_id, metric_name, value in rows:
        out.setdefault(str(resource_id), {})[str(metric_name)] = float(value)
    return out


def load_gpu_nodes(
    session: Session,
    *,
    project_id: str,
    subject: Subject,
    resource_ids: Iterable[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """读取 GPU 节点属性：``{resource_id: {gpu_model, total_gpus, ...}}``。

    没有属性行 = 该资源的 GPU 字段未知（采集没给），不要用默认值填补：
    ``allocated_gpus`` 缺失时判定层必须放弃「浪费」结论（见 D1 规则）。
    """
    anchors = visible_anchor_ids(
        session, project_id=project_id, subject=subject, resource_ids=resource_ids
    )
    rls.scope_anchor_ids(session, anchors)
    if not anchors:
        return {}
    rows = session.execute(
        select(GpuNode).where(GpuNode.resource_id.in_(anchors)).order_by(GpuNode.resource_id)
    ).scalars().all()
    return {
        str(row.resource_id): {name: getattr(row, name) for name in _GPU_FIELDS} for row in rows
    }


__all__ = ["load_gpu_nodes", "load_metrics", "visible_anchor_ids"]
