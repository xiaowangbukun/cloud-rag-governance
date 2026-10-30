"""P1 回归（QA 复核 R2-B）：能力校验拒绝路径必须留审计。

QA 实测 13 条拒绝路径里有 6 条 ``Δdenied=0``——``assert_capability()``
与 ``_require_admin()`` 的签名里没有 request/session，拒绝时**根本没法
写审计**，于是「谁因缺能力被拒绝」在审计里完全不可见。

修复：两个入口都接受可选关键字参数 ``request`` / ``session``，两者齐备
且判定拒绝时走独立事务写一条 denied 审计；缺省时保持原样只抛异常。

覆盖端点：collection:run、knowledge:write、knowledge:reindex，以及
_require_admin 影响的 admin 端点。两个方言共用同一套用例。
"""

from __future__ import annotations

import pytest
from conftest import login
from rg_contracts.db.models import AuditLog, User
from sqlalchemy import func, select

# (capability, method, path, 登录账号, 密码, 请求体)
# 注意：POST 端点必须给**合法**请求体——FastAPI 的 body 校验先于函数体内
# 的能力校验执行，非法体会先返回 422 而走不到被测的拒绝路径。
# base_url 用不可达回落而非集群 DNS：测试不得写死环境拓扑（该 body 只用于
# 拿 403，网关不会被创建、更不会 test_connection，不会出网）。
_GATEWAY_BODY = {
    "name": "p1-denial-probe",
    "provider": "internal",
    "base_url": "http://127.0.0.1:9",
    "model": "probe-model",
}
DENY_CASES = [
    ("collection:run", "post", "/api/v1/collection/run", "viewer@corp.local", "View@2026", {}),
    (
        "knowledge:write",
        "post",
        "/api/v1/knowledge/documents",
        "viewer@corp.local",
        "View@2026",
        {"title": "p1-denial-probe", "content": "占位内容"},
    ),
    ("knowledge:reindex", "post", "/api/v1/knowledge/reindex", "viewer@corp.local", "View@2026", None),
    ("admin:config", "get", "/api/v1/admin/config", "governance@corp.local", "Gov@2026", None),
    ("admin:config", "get", "/api/v1/admin/gateways", "governance@corp.local", "Gov@2026", None),
    ("admin:config", "get", "/api/v1/attribution/gateways", "governance@corp.local", "Gov@2026", None),
    ("admin:config", "get", "/api/v1/admin/directory/sync", "governance@corp.local", "Gov@2026", None),
    ("admin:config", "post", "/api/v1/admin/gateways", "governance@corp.local", "Gov@2026", _GATEWAY_BODY),
    ("admin:config", "post", "/api/v1/admin/directory/sync", "governance@corp.local", "Gov@2026", {}),
]


def _actor_id(session, username: str) -> str:
    return session.execute(select(User.id).where(User.subject == username)).scalar_one()


def _count_denied(session, action: str, actor_id: str) -> int:
    return int(
        session.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == action,
                AuditLog.outcome == "denied",
                AuditLog.actor_id == actor_id,
            )
        ).scalar_one()
    )


@pytest.mark.parametrize(
    ("capability", "method", "path", "username", "password", "body"),
    DENY_CASES,
    ids=[
        f"{method}-{path.rsplit('/', 1)[-1] or 'root'}-{(u or '').split('@')[0]}"
        for _, method, path, u, _, _ in DENY_CASES
    ],
)
def test_capability_denial_is_audited(
    client, session, capability, method, path, username, password, body
):
    """核心回归：缺能力被拒 → 该 action 的 denied 审计增量恰好为 1。"""
    headers = login(client, username, password)
    actor_id = _actor_id(session, username)
    before = _count_denied(session, capability, actor_id)

    if method == "get":
        resp = client.get(path, headers=headers)
    else:
        resp = client.post(path, json=body if body is not None else {}, headers=headers)
    assert resp.status_code == 403, f"{method.upper()} {path} 期望 403，实际 {resp.status_code}"

    session.expire_all()
    after = _count_denied(session, capability, actor_id)
    assert after - before == 1, (
        f"{method.upper()} {path} 拒绝后审计缺失：denied Δ={after - before}（期望 1）"
    )


def test_capability_denial_audit_records_reason_code(client, session, viewer_headers):
    """附加断言：审计带 missing_capability 原因码，可用于告警聚合。"""
    actor_id = _actor_id(session, "viewer@corp.local")
    before = _count_denied(session, "knowledge:write", actor_id)

    resp = client.post(
        "/api/v1/knowledge/documents",
        json={"title": "t", "content": "c"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403

    session.expire_all()
    rows = session.execute(
        select(AuditLog).where(
            AuditLog.action == "knowledge:write",
            AuditLog.outcome == "denied",
            AuditLog.actor_id == actor_id,
        )
    ).scalars().all()
    assert len(rows) == before + 1
    assert rows[-1].reason_code == "missing_capability"


def test_assert_capability_without_request_keeps_old_behaviour():
    """缺省参数（无 HTTP 上下文，如脚本/后台任务）仍只抛异常，不要求审计。"""
    from conftest import make_subject
    from rg_contracts.errors import PermissionDeniedError

    from rg_api.services.access import assert_capability

    viewer = make_subject("viewer", "L2_INTERNAL")
    with pytest.raises(PermissionDeniedError):
        assert_capability(viewer, "collection:run")

    governance = make_subject("governance", "L3_CONFIDENTIAL")
    assert_capability(governance, "collection:run")  # 有能力则静默通过