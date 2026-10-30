"""R2（P0-6）回归：/resources/stats 聚合必须与明细列表同口径密级过滤。

缺陷形态：``resource_stats`` 的 by_platform / by_kind 两个聚合曾直接
按 project_id 统计，未套用 ``_apply_level_filter``，导致超出调用者
密级上限的资源仍以计数/成本形式泄漏存在性（聚合即披露）。
"""

from __future__ import annotations

from datetime import date

import pytest
from rg_contracts.db.models import CloudAccount, Resource, new_id
from rg_contracts.security.policy import levels_at_or_below
from sqlalchemy import func, select

PROJECT_ID = "prj_core_policy"  # L3_CONFIDENTIAL，pm@corp.local 有授权且上限 L3


@pytest.fixture
def l4_resource(session):
    """在授权项目内插入一条 L4_SECRET 资源（超出 pm 的密级上限），返回其 ID。"""
    account = session.execute(select(CloudAccount)).scalars().first()
    assert account is not None, "演示种子应至少提供一个云账号"
    resource = Resource(
        id=new_id("res"),
        platform=account.platform,
        account_id=account.id,
        project_id=PROJECT_ID,
        native_id=f"r2-regression-{new_id('x')[-8:]}",
        name="r2-regression-l4-resource",
        kind="vm",
        region=account.region,
        spec="2C4G",
        status="running",
        monthly_cost_cny=1234.56,
        classification="L4_SECRET",
        first_seen_date=date(2026, 1, 1),
        last_seen_date=date(2026, 10, 1),
    )
    session.add(resource)
    session.commit()

    yield resource.id

    session.delete(resource)
    session.commit()


def _db_count(session, classification: str | None) -> int:
    stmt = select(func.count(Resource.id)).where(Resource.project_id == PROJECT_ID)
    if classification is not None:
        stmt = stmt.where(Resource.classification.in_(levels_at_or_below(classification)))
    return int(session.execute(stmt).scalar_one())


def test_stats_aggregations_exclude_resources_above_ceiling(client, pm_headers, session, l4_resource):
    """核心回归：聚合计数不得包含超出密级上限的资源（P0-6）。"""
    resp = client.get(f"/api/v1/resources/stats?project_id={PROJECT_ID}", headers=pm_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    total_by_kind = sum(item["count"] for item in body["by_kind"])
    total_by_platform = sum(item["count"] for item in body["by_platform"])
    allowed = _db_count(session, "L3_CONFIDENTIAL")
    all_rows = _db_count(session, None)

    assert all_rows > allowed, "前置条件：L4 资源已入账且被全量计数覆盖"
    assert total_by_kind == allowed, "by_kind 聚合泄漏了超限分级的资源"
    assert total_by_platform == allowed, "by_platform 聚合泄漏了超限分级的资源"


def test_stats_still_counts_authorized_resources(client, pm_headers, session, l4_resource):
    """控制组：修复后授权范围内的资源统计不丢数（防止过度过滤）。"""
    resp = client.get(f"/api/v1/resources/stats?project_id={PROJECT_ID}", headers=pm_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    allowed = _db_count(session, "L3_CONFIDENTIAL")
    assert allowed > 0, "演示种子应在授权项目内造出 L3 资源"
    assert sum(item["count"] for item in body["by_kind"]) == allowed
    assert body["total_monthly_cost_cny"] > 0


def test_stats_detail_and_aggregation_share_same_level_boundary(client, pm_headers, session, l4_resource):
    """明细列表与聚合口径一致：两者都排除同一条 L4 资源。"""
    stats = client.get(f"/api/v1/resources/stats?project_id={PROJECT_ID}", headers=pm_headers).json()
    detail = client.get(
        f"/api/v1/resources?project_id={PROJECT_ID}&limit=200", headers=pm_headers
    ).json()
    allowed = _db_count(session, "L3_CONFIDENTIAL")
    assert len(detail) == allowed
    assert sum(item["count"] for item in stats["by_kind"]) == len(detail)
    assert all(row["classification"] in levels_at_or_below("L3_CONFIDENTIAL") for row in detail)
