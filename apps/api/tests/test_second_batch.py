"""第二批加固的回归用例：跨副本运行期状态、指标端点、保留任务。

覆盖五条容易「看起来做了、实际等于没做」的不变量：

1. 查询预算与登录锁定必须**落库**：进程内计数在 ``replicas: 2`` 下会把阈值
   放大一倍，且新副本一上线计数就归零；
2. 计数写入必须独立提交：预算超限会抛异常回滚业务会话，复用业务会话会让
   计数随回滚消失；
3. ``/metrics`` 的路由标签必须取**模板**（否则 ``/resources/{id}`` 会打爆
   时序基数），且自身不得被计入；
4. 保留任务只删口径已定的数据，快照**每月基线必须保留**（否则 diff 无法回溯）；
5. ``audit_log`` / ``security_event`` 只统计超期规模、绝不删除。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import login
from rg_contracts.config import get_settings
from rg_contracts.db.models import (
    AuditLog,
    CloudAccount,
    OidcLoginState,
    Resource,
    RetrievalLedger,
    RuntimeCounter,
    SecurityEvent,
    Snapshot,
    SnapshotState,
    new_id,
    ts,
)
from rg_contracts.security.budget import DbQueryBudget
from rg_contracts.security.state_store import SCOPE_LOGIN_FAILURE, SCOPE_RETRIEVAL, RuntimeStateStore
from sqlalchemy import func, select

from rg_api.metrics import REGISTRY
from rg_api.retention import run_retention
from rg_api.routes import auth as auth_module
from rg_api.routes import health as health_module

NOW = datetime.now(timezone.utc)


# --------------------------------------------------------- ① 计数落库 & 跨副本


def test_retrieval_budget_is_shared_across_processes(client, session):
    """预算计数必须落库：另一个「副本」读到的窗口与写入方一致。"""
    actor = f"budget-batch2-{new_id('u')}"
    settings = get_settings().model_copy(update={"SECURITY_QUERY_BUDGET_PER_HOUR": 2})
    budget = DbQueryBudget(settings)

    assert budget.check_retrieval(actor, ["prj_core_policy"])[0] is True
    assert budget.check_retrieval(actor, ["prj_core_policy"])[0] is True
    ok, reason, details = budget.check_retrieval(actor, ["prj_core_policy"])
    assert ok is False and reason == "hourly_budget_exceeded", details
    assert details["count"] == 3

    # 全新实例（等价于另一个 Pod）不持有任何进程内状态，仍能读到同一窗口
    replica_view = RuntimeStateStore().count(SCOPE_RETRIEVAL, actor, 3600)
    assert replica_view == 3, "计数没有落库，多副本下预算会被放大"

    budget.reset()
    assert RuntimeStateStore().count(SCOPE_RETRIEVAL, actor, 3600) == 0


def test_cross_project_probe_state_is_shared_across_processes(session):
    """跨项目探测靠 distinct project_id 统计，同样必须落库。"""
    actor = f"probe-batch2-{new_id('u')}"
    settings = get_settings().model_copy(update={"SECURITY_QUERY_BUDGET_PER_HOUR": 1000})
    budget = DbQueryBudget(settings)
    try:
        for index in range(12):
            ok, reason, _ = budget.check_retrieval(actor, [f"prj_probe_{index}"])
            assert ok is True and reason == "ok"

        # 第 13 个不同项目触发探测（每个项目只查一次，仍能被累积出来）
        ok, reason, details = budget.check_retrieval(actor, ["prj_probe_12"])
        assert ok is False and reason == "cross_project_probing", details
        assert details["distinct"] == 13
    finally:
        budget.reset()


def test_login_failure_count_is_persisted_for_lockout(client, session):
    """登录失败计数落库：5 次失败后第 6 次必须被拒，计数对任意实例可见。"""
    username = f"lockout-batch2-{new_id('u')}@corp.local"
    auth_module.reset_login_state()
    try:
        for _ in range(auth_module.LOGIN_MAX_FAILURES):
            resp = client.post(
                "/api/v1/auth/login", json={"username": username, "password": "Wrong@2026"}
            )
            assert resp.status_code == 401, resp.text

        persisted = RuntimeStateStore().count(
            SCOPE_LOGIN_FAILURE, username, auth_module.LOGIN_LOCKOUT_SECONDS
        )
        assert persisted == auth_module.LOGIN_MAX_FAILURES

        locked = client.post(
            "/api/v1/auth/login", json={"username": username, "password": "Wrong@2026"}
        )
        assert locked.status_code == 429, locked.text
    finally:
        auth_module.reset_login_state()


def test_successful_login_clears_persisted_failures(client, session):
    """登录成功后必须清零已落库的失败计数，否则窗口内会误锁正常用户。"""
    username = "admin@corp.local"
    auth_module.reset_login_state()
    try:
        for _ in range(auth_module.LOGIN_MAX_FAILURES - 1):
            resp = client.post(
                "/api/v1/auth/login", json={"username": username, "password": "Wrong@2026"}
            )
            assert resp.status_code == 401, resp.text
        assert login(client, username, "Admin@2026")
        assert (
            RuntimeStateStore().count(
                SCOPE_LOGIN_FAILURE, username, auth_module.LOGIN_LOCKOUT_SECONDS
            )
            == 0
        )
    finally:
        auth_module.reset_login_state()


# ---------------------------------------------------------------- ② 指标端点


def test_metrics_endpoint_renders_prometheus_text(client):
    REGISTRY.reset()
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/resources/projects").status_code in (200, 401)

    resp = client.get("/metrics")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "# TYPE rg_http_requests_total counter" in body
    assert "# TYPE rg_http_request_duration_seconds histogram" in body
    # 路由模板作为标签（不是原始路径），否则时序基数会爆炸
    assert 'path="/health"' in body
    assert 'le="+Inf"' in body
    # 抓取端点自身不得被计入，否则每次抓取都会自增
    assert 'path="/metrics"' not in body


def test_metrics_labels_unmatched_routes_as_unmatched(client):
    REGISTRY.reset()
    resp = client.get("/api/v1/not-a-real-endpoint")
    assert resp.status_code == 404, resp.text

    body = client.get("/metrics").text
    assert 'path="unmatched"' in body, "未匹配路由必须单独归组，不能把原始路径当标签"


def test_metrics_disabled_returns_404(client, monkeypatch):
    settings = get_settings().model_copy(update={"METRICS_ENABLED": False})
    monkeypatch.setattr(health_module, "get_settings", lambda: settings)
    resp = client.get("/metrics")
    assert resp.status_code == 404, resp.text
    assert resp.json()["code"] == "not_found"


# ---------------------------------------------------------------- ③ 保留任务


def _make_snapshot(session, account_id: str, platform: str, taken_at: datetime, status: str = "success") -> Snapshot:
    snapshot = Snapshot(
        id=new_id("snap"),
        platform=platform,
        account_id=account_id,
        taken_at=ts(taken_at),
        status=status,
        resource_count=1,
    )
    session.add(snapshot)
    return snapshot


def _add_state(session, snapshot: Snapshot, resource: Resource) -> SnapshotState:
    state = SnapshotState(
        id=new_id("ss"),
        snapshot_id=snapshot.id,
        resource_id=resource.id,
        project_id=resource.project_id,
        platform=resource.platform,
        kind=resource.kind,
        fingerprint=f"fp-{new_id('x')}",
        payload={"name": "retention-test"},
    )
    session.add(state)
    return state


def test_retention_prunes_expired_state_and_keeps_monthly_baseline(session):
    account = session.execute(select(CloudAccount)).scalars().first()
    resource = session.execute(select(Resource)).scalars().first()
    assert account is not None and resource is not None, "需要种子数据提供账号与资源"

    # 同一个月内两份成功快照：后一份是该月基线，前一份的明细应被清理
    old_early = _make_snapshot(session, account.id, account.platform, datetime(2024, 3, 5, tzinfo=timezone.utc))
    old_late = _make_snapshot(session, account.id, account.platform, datetime(2024, 3, 25, tzinfo=timezone.utc))
    recent = _make_snapshot(session, account.id, account.platform, NOW - timedelta(days=2))
    for snapshot in (old_early, old_late, recent):
        _add_state(session, snapshot, resource)

    stale_ledger = RetrievalLedger(
        id=new_id("rl"), ts=ts(NOW - timedelta(days=30)), actor_id="retention-test",
        chunk_id=new_id("chunk"), project_id=resource.project_id,
    )
    fresh_ledger = RetrievalLedger(
        id=new_id("rl"), ts=ts(NOW - timedelta(hours=1)), actor_id="retention-test",
        chunk_id=new_id("chunk"), project_id=resource.project_id,
    )
    expired_state = OidcLoginState(
        id=new_id("ols"), state_hash=new_id("h"), code_verifier="v", nonce="n",
        created_at=ts(NOW - timedelta(hours=2)), expires_at=ts(NOW - timedelta(hours=1)),
    )
    valid_state = OidcLoginState(
        id=new_id("ols"), state_hash=new_id("h"), code_verifier="v", nonce="n",
        created_at=ts(NOW), expires_at=ts(NOW + timedelta(minutes=5)),
    )
    stale_counter = RuntimeCounter(
        id=new_id("rc"), scope=SCOPE_RETRIEVAL, subject="retention-test", ts=ts(NOW - timedelta(days=3)),
    )
    fresh_counter = RuntimeCounter(
        id=new_id("rc"), scope=SCOPE_RETRIEVAL, subject="retention-test", ts=ts(NOW),
    )
    old_audit = AuditLog(
        id=new_id("aud"), ts=ts(NOW - timedelta(days=400)), action="retention_test_old",
        outcome="success", metadata_json={},
    )
    old_event = SecurityEvent(
        id=new_id("sec"), ts=ts(NOW - timedelta(days=400)), event_type="retention_test_old",
        severity="low", detail="保留任务不得删除安全事件", metadata_json={},
    )
    session.add_all([
        stale_ledger, fresh_ledger, expired_state, valid_state,
        stale_counter, fresh_counter, old_audit, old_event,
    ])
    session.commit()

    snapshots_before = int(session.execute(select(func.count(Snapshot.id))).scalar() or 0)
    report = run_retention(get_settings(), dry_run=False)

    # 注意：不能 expire_all——被删行的实例一旦过期，下次取属性就会抛
    # ObjectDeletedError；这里用 fresh count 查询判定存在性。
    assert not _exists(session, RetrievalLedger, stale_ledger.id), "过期检索账本必须删除"
    assert _exists(session, RetrievalLedger, fresh_ledger.id)
    assert not _exists(session, OidcLoginState, expired_state.id), "过期 OIDC state 必须删除"
    assert _exists(session, OidcLoginState, valid_state.id)
    assert not _exists(session, RuntimeCounter, stale_counter.id), "过期运行期计数必须删除"
    assert _exists(session, RuntimeCounter, fresh_counter.id)

    # 快照：更早的月份删除非基线明细，每月最后一份成功快照的明细必须保留
    assert _state_count(session, old_early.id) == 0, "非基线月份明细应被清理"
    assert _state_count(session, old_late.id) == 1, "该月最后一份成功快照必须作为基线保留"
    assert _state_count(session, recent.id) == 1, "保留期内快照不受影响"
    assert int(session.execute(select(func.count(Snapshot.id))).scalar() or 0) == snapshots_before, (
        "快照主体（含 resource_diff 的基线引用）不得删除"
    )

    assert report["snapshot_state"]["baseline_snapshots_kept"] >= 2
    assert report["audit_log"]["deleted"] == 0
    assert report["security_event"]["deleted"] == 0

    # 审计与安全事件只报规模，不删除
    assert _exists(session, AuditLog, old_audit.id), "审计记录绝不能删除"
    assert _exists(session, SecurityEvent, old_event.id), "安全事件绝不能删除"
    assert report["audit_log"]["rows_older_than_target"] >= 1
    assert report["security_event"]["rows_older_than_target"] >= 1

    # 清理动作本身必须留痕
    actions = session.execute(
        select(AuditLog.action).where(AuditLog.action == "retention_run")
    ).scalars().all()
    assert actions, "保留任务执行必须写审计"


def test_retention_dry_run_deletes_nothing(session):
    stale = RetrievalLedger(
        id=new_id("rl"), ts=ts(NOW - timedelta(days=30)), actor_id="retention-dry",
        chunk_id=new_id("chunk"),
    )
    session.add(stale)
    session.commit()

    report = run_retention(get_settings(), dry_run=True)
    assert _exists(session, RetrievalLedger, stale.id), "dry-run 不得删除任何数据"
    assert report["dry_run"] is True
    assert report["retrieval_ledger"]["candidates"] >= 1
    assert report["retrieval_ledger"]["deleted"] == 0


def _exists(session, model, pk: str) -> bool:
    """用计数查存在性：``session.get`` 会把已删除的实例从身份映射抛出来。"""
    return bool(
        session.execute(
            select(func.count()).select_from(model).where(model.id == pk)
        ).scalar()
    )


def _state_count(session, snapshot_id: str) -> int:
    return int(
        session.execute(
            select(func.count(SnapshotState.id)).where(SnapshotState.snapshot_id == snapshot_id)
        ).scalar()
        or 0
    )
