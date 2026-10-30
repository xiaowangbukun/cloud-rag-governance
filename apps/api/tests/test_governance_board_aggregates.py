"""治理看板统计口径回归（第二批）：汇总全量聚合，只有清单受上限约束。

为什么要专门守这一组
--------------------
旧实现先 ``limit(200)`` 取行、再在内存里累加 ``by_status`` / ``by_kind`` /
``cost_impact_cny``：治理项超过 200 时**汇总数字本身就会偏小**，而响应里没有
任何迹象。那比「列表少几行」严重得多——看板是给人做决策的，错数比缺数更难
被发现。这里用「插入前/插入后的增量」断言 CLIFF 两侧的真实差异：

- ``total`` / ``by_status`` / ``by_kind`` / ``cost_impact_cny`` 必须包含**全部**行；
- ``items`` 只返回最新 ``item_cap`` 条，且 ``truncated`` 明确标记。

断言用增量而不是绝对值：演示种子与本文件之外的数据都可能存在，增量口径与
种子规模解耦，失败信息也更直接（差多少就是差多少）。
"""

from __future__ import annotations

import pytest
from conftest import make_subject
from rg_contracts.db.models import ResourceDiff, new_id, ts
from sqlalchemy import delete

from rg_api.routes.governance import _BOARD_ITEM_CAP, board

PROJECT_ID = "prj_core_policy"
BOARD_URL = "/api/v1/governance/board"

#: 插入行数：必须显著大于 ``_BOARD_ITEM_CAP``，否则「汇总不受上限影响」这个
#: 断言就没有区分力（列表是否截断、汇总是否偏小都会看不出差别）。
INSERTED = _BOARD_ITEM_CAP + 10


def _insert_diffs(session, count: int) -> list[str]:
    """按「一半 open / 一半 confirmed」插入差异，成本每条 1 元便于核对总和。"""
    diff_ids: list[str] = []
    for index in range(count):
        diff_id = new_id("diff")
        diff_ids.append(diff_id)
        session.add(
            ResourceDiff(
                id=diff_id,
                project_id=PROJECT_ID,
                platform="aliyun",
                native_id=f"board-probe-{diff_id}",
                resource_name="board-probe-resource",
                kind="vm",
                diff_kind="cost_increase",
                detected_at=ts(),
                cost_delta_cny=1.0,
                classification="L3_CONFIDENTIAL",
                summary="board 口径探针",
                payload={},
                status="open" if index % 2 == 0 else "confirmed",
            )
        )
    session.commit()
    return diff_ids


def _delete_diffs(session, diff_ids: list[str]) -> None:
    session.execute(delete(ResourceDiff).where(ResourceDiff.id.in_(diff_ids)))
    session.commit()


def _get_board(client, headers) -> dict:
    resp = client.get(BOARD_URL, params={"project_id": PROJECT_ID}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_board_totals_cover_all_rows_while_items_are_capped(client, gov_headers, session):
    """核心回归：超过上限后，汇总仍按全量算，清单才截断。"""
    before = _get_board(client, gov_headers)
    diff_ids = _insert_diffs(session, INSERTED)
    try:
        after = _get_board(client, gov_headers)
    finally:
        _delete_diffs(session, diff_ids)

    # 1) 汇总口径：全部插入行都被计入（旧实现会被上限吃掉一部分）
    assert after["total"] == before["total"] + INSERTED, after
    assert after["total"] > _BOARD_ITEM_CAP
    assert sum(after["by_status"].values()) == after["total"]
    assert after["by_status"].get("open", 0) == before["by_status"].get("open", 0) + INSERTED // 2
    assert after["by_status"].get("confirmed", 0) == (
        before["by_status"].get("confirmed", 0) + INSERTED // 2
    )
    assert after["by_kind"].get("cost_increase", 0) == (
        before["by_kind"].get("cost_increase", 0) + INSERTED
    )
    assert after["cost_impact_cny"] == pytest.approx(
        round(before["cost_impact_cny"] + INSERTED * 1.0, 2), abs=0.01
    )

    # 2) 清单口径：只给最新 N 条，且必须自报截断（不能静默）
    assert after["item_cap"] == _BOARD_ITEM_CAP
    assert after["truncated"] is True
    assert len(after["items"]) == _BOARD_ITEM_CAP
    # 新插入的行 detected_at 最新，必然出现在清单里
    assert after["items"][0]["id"] in set(diff_ids)

    # 3) 清理后回到原口径，证明上面的增量断言没有跨用例污染
    restored = _get_board(client, gov_headers)
    assert restored["total"] == before["total"]


def test_small_board_is_not_marked_truncated(client, gov_headers):
    """没有超过上限时 ``truncated`` 必须是 False（避免监控长期误报）。"""
    body = _get_board(client, gov_headers)
    if body["total"] > _BOARD_ITEM_CAP:
        pytest.skip("当前库的治理项已超过上限，本条只验证未截断分支")
    assert body["truncated"] is False
    assert len(body["items"]) == body["total"]


def test_empty_scope_response_keeps_full_contract(session):
    """无可见范围时早返回也必须带全字段：前端/探针不该因 payload 形态不同而报错。"""
    from fastapi import Request

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": BOARD_URL,
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 50001),
        }
    )
    # viewer 无任何项目授权 → diff_scope_clause 返回 None，走早返回分支
    body = board(request, None, make_subject("viewer", "L1_PUBLIC"), session)

    assert body["total"] == 0
    assert body["items"] == []
    assert body["by_status"] == {}
    assert body["by_kind"] == {}
    assert body["cost_impact_cny"] == 0
    assert body["truncated"] is False
    assert body["item_cap"] == _BOARD_ITEM_CAP
