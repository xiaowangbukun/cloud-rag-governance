"""R3（P0-4）回归：denied / failed 审计记录必须独立于业务事务落库。

缺陷形态：``audit_action`` 曾把审计行写进业务会话。拒绝路径上路由
随后直接抛 ``PermissionDeniedError``，业务事务整体回滚，审计行随之
丢失——「谁被拒绝了」在合规视角下不可见。修复后 denied/failed 走
独立会话 + 独立事务提交，业务回滚不再吞掉拒绝留痕。
"""

from __future__ import annotations

from conftest import make_subject
from fastapi import Request
from rg_contracts.db.models import AuditLog, SecurityEvent, User
from sqlalchemy import func, select

from rg_api.services.audit import audit_action

ACTION = "audit:r3-regression"
PROJECT_ID = "prj_core_policy"
DENY_ROUNDS = 5


def _fake_request() -> Request:
    """构造最小 HTTP 请求对象，供 client_meta 提取 IP / UA。"""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/resources",
            "headers": [(b"user-agent", b"pytest-r3")],
            "query_string": b"",
            "client": ("127.0.0.1", 54321),
        }
    )


def _count(session, model, **filters) -> int:
    stmt = select(func.count(model.id))
    for column, value in filters.items():
        stmt = stmt.where(getattr(model, column) == value)
    return int(session.execute(stmt).scalar_one())


def test_denied_audit_survives_business_rollback(session):
    """核心回归：业务会话回滚后，denied 审计行依然在库中。"""
    subject = make_subject("viewer", "L2_INTERNAL")
    request = _fake_request()

    audit_action(
        request, session, subject, ACTION, "denied", PROJECT_ID, "r3_rollback_probe",
    )
    # 模拟路由层拒绝后的业务回滚
    session.rollback()

    assert _count(session, AuditLog, action=ACTION, outcome="denied") == 1
    assert (
        _count(session, SecurityEvent, event_type=f"access_denied:{ACTION}") == 1
    ), "denied 必须同时落安全事件"


def test_failed_audit_survives_business_rollback(session):
    """failed 结果同样走独立事务，不随业务回滚丢失。"""
    subject = make_subject("viewer", "L2_INTERNAL")
    request = _fake_request()

    audit_action(
        request, session, subject, ACTION, "failed", PROJECT_ID, "r3_failed_probe",
    )
    session.rollback()

    assert _count(session, AuditLog, action=ACTION, outcome="failed") == 1


def test_allowed_audit_still_follows_business_transaction(session):
    """allowed 行为不变：仍写业务会话（由路由 commit 提交），回滚即消失。"""
    subject = make_subject("viewer", "L2_INTERNAL")
    request = _fake_request()

    audit_action(request, session, subject, ACTION, "allowed", PROJECT_ID, None)
    session.rollback()

    assert _count(session, AuditLog, action=ACTION, outcome="allowed") == 0


def test_repeated_denials_all_persisted_on_sqlite(client, viewer_headers, session):
    """锁回归：连续 N 次拒绝，必须落 N 条 denied 审计（SQLite 不允许丢行）。"""
    viewer = session.execute(
        select(User).where(User.subject == "viewer@corp.local")
    ).scalar_one()
    before = _count(session, AuditLog, action="resource:list", outcome="denied", actor_id=viewer.id)
    sec_before = _count(session, SecurityEvent, event_type="access_denied:resource:list")

    for _ in range(DENY_ROUNDS):
        resp = client.get(
            "/api/v1/resources", params={"project_id": PROJECT_ID}, headers=viewer_headers
        )
        assert resp.status_code == 403

    # 刷新视图：独立事务已提交，新查询必须可见
    session.expire_all()
    after = _count(session, AuditLog, action="resource:list", outcome="denied", actor_id=viewer.id)
    sec_after = _count(session, SecurityEvent, event_type="access_denied:resource:list")

    assert after - before == DENY_ROUNDS, f"期望新增 {DENY_ROUNDS} 条 denied 审计，实际 {after - before}"
    assert sec_after - sec_before == DENY_ROUNDS
