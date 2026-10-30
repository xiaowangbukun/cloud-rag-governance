"""P0 回归（QA 复核 R2-A）：独立审计写入失败时不得牵连业务会话。

QA 实测的缺陷：``_record_independent`` 用无差别 ``except Exception:``
回滚业务会话，于是**非锁类**审计失败（RuntimeError 等）也会把业务暂存区
丢掉。受害路径：``routes/attribution.py`` blocked=True 时 outcome=denied
走独立事务 → 独立写失败 → 归因记录被回滚 → API 仍返回 200 与
attribution id，客户端拿到一个库里根本不存在的 id。

修复后铁律：只有 SQLite 写锁竞争才允许回滚业务会话（单写者适配，
PostgreSQL 不需要）；其他任何异常一律只记日志、绝不碰业务数据。
"""

from __future__ import annotations

import pytest
from conftest import is_pg, make_subject
from rg_contracts.db.models import (
    Attribution,
    AuditLog,
    KnowledgeDocument,
    ResourceDiff,
    new_id,
    ts,
)
from rg_contracts.security.dlp import default_dlp
from sqlalchemy import select

from rg_api.services import audit as audit_service_module
from rg_api.services.audit import audit_action

PROJECT_ID = "prj_claim"
ACTION = "audit:p0-regression"


class _EnforceBlockingProxy:
    """只把 ``enforce`` 变成必然拦截；``inspect`` 委托真实 DLP。

    真实 DLP 必须保留：网关出网前的 ``assert_payload_safe`` 会读
    ``inspect()`` 的结果对象（需要 ``severity`` 属性），整体替换会让
    请求在到达被测路径之前就 500。
    """

    def __init__(self, real) -> None:
        self._real = real

    def inspect(self, payload):
        return self._real.inspect(payload)

    def enforce(self, text, subject=None):  # noqa: ARG002
        raise RuntimeError("forced_dlp_block")


def _fake_request():
    from fastapi import Request

    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/attribution/run",
            "headers": [(b"user-agent", b"pytest-p0")],
            "query_string": b"",
            "client": ("127.0.0.1", 50111),
        }
    )


def _document(document_id: str, title: str) -> KnowledgeDocument:
    return KnowledgeDocument(
        id=document_id,
        title=title,
        doc_type="rule",
        project_id=None,
        classification="L2_INTERNAL",
        content="占位内容",
        sanitized=True,
        metadata_json={},
    )


def test_non_lock_audit_failure_never_touches_business_session(session, monkeypatch):
    """核心回归①：注入非锁错误 → 业务暂存区数量不变，随后 commit 能落库。

    修复前：pending 由 1 → 0，业务行被回滚丢弃，且独立写被无谓重试 2 次。
    """
    calls: list[int] = []

    def _boom(**_kwargs) -> None:
        calls.append(1)
        raise RuntimeError("非锁类故障（QA 注入）")

    monkeypatch.setattr(audit_service_module, "_record_independent_once", _boom)

    subject = make_subject("governance", "L3_CONFIDENTIAL")
    probe_id = new_id("kd")
    session.add(_document(probe_id, "p0-业务暂存探针"))
    assert len(session.new) == 1, "前置条件：业务会话应有 1 条待写入"

    audit_action(
        _fake_request(), session, subject, ACTION, "denied", PROJECT_ID, "p0_probe",
    )

    assert len(session.new) == 1, "非锁类审计失败不得回滚业务会话的暂存区"
    assert len(calls) == 1, "非锁类失败不应触发无谓重试"

    session.commit()
    assert session.get(KnowledgeDocument, probe_id) is not None, "业务数据必须能正常落库"
    session.delete(session.get(KnowledgeDocument, probe_id))
    session.commit()


@pytest.mark.skipif(is_pg(), reason="PG 是 MVCC，独立事务不会被业务写锁阻塞，无此场景")
def test_real_sqlite_lock_contention_still_recovers(session):
    """核心回归②：真实 SQLite 写锁竞争下，审计仍然落库（适配逻辑未被误伤）。

    业务会话先 flush 一条 INSERT 持有写锁，独立事务首次提交必然因
    database is locked 失败 → 判定为锁错误 → 回滚暂存区释放锁 → 重试成功。
    """
    from rg_contracts.db.session import get_session_factory

    subject = make_subject("governance", "L3_CONFIDENTIAL")
    session.add(_document(new_id("kd"), "p0-锁竞争探针"))
    session.flush()  # 打开写事务并持有 SQLite 写锁

    audit_action(
        _fake_request(), session, subject, ACTION, "denied", PROJECT_ID, "p0_lock_probe",
    )

    # 用全新会话确认审计已落库（业务会话此刻仍持锁，只能靠独立事务写进去）
    checker = get_session_factory()()
    try:
        rows = checker.execute(
            select(AuditLog).where(AuditLog.action == ACTION)
        ).scalars().all()
    finally:
        checker.close()
    assert rows, "真实锁竞争下审计必须仍能落库"


def test_blocked_attribution_id_exists_after_non_lock_audit_failure(
    client, session, gov_headers, monkeypatch
):
    """核心回归③（受害路径端到端）：非锁类审计失败后，返回的归因 id 真实存在。

    修复前：业务会话被回滚 → 返回 200 + id，但库里查不到该行（幽灵 id）。
    """
    diff = ResourceDiff(
        id=new_id("diff"),
        project_id=PROJECT_ID,
        platform="aliyun",
        native_id=f"p0-{new_id('x')[-8:]}",
        resource_name="p0-resource",
        kind="vm",
        diff_kind="cost_increase",
        detected_at=ts(),
        cost_delta_cny=99.0,
        classification="L3_CONFIDENTIAL",
        rule_hint="p0-rule-hint",
        summary="p0-summary",
        payload={},
        status="open",
    )
    session.add(diff)
    session.commit()

    def _boom(**_kwargs) -> None:
        raise RuntimeError("非锁类故障（QA 注入）")

    monkeypatch.setattr(audit_service_module, "_record_independent_once", _boom)
    real_dlp = default_dlp()
    monkeypatch.setattr(
        "rg_api.routes.attribution.default_dlp",
        lambda: _EnforceBlockingProxy(real_dlp),
    )

    try:
        resp = client.post(
            "/api/v1/attribution/run",
            json={"diff_id": diff.id, "question": "这个差异可能是什么原因", "top_k": 3},
            headers=gov_headers,
        )
        assert resp.status_code == 200, resp.text
        attribution_id = resp.json()["id"]

        session.expire_all()
        stored = session.get(Attribution, attribution_id)
        assert stored is not None, (
            f"返回了 attribution id={attribution_id}，但库里不存在——业务数据被审计失败牵连丢弃"
        )
    finally:
        for row in session.execute(
            select(Attribution).where(Attribution.diff_id == diff.id)
        ).scalars().all():
            session.delete(row)
        session.delete(diff)
        session.commit()