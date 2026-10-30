"""API 端到端测试：认证、授权、受控检索、归因、治理闭环、审计留痕。"""
from __future__ import annotations

from rg_contracts.config import get_settings

# 未配置内网推理地址时的回落值：discard 端口，连接立即被拒（ECONNREFUSED）。
# 用它而不是集群 DNS 名，保证无网/沙箱环境也能完整跑全量测试。
_UNREACHABLE_INFERENCE_URL = "http://127.0.0.1:9"


def _internal_inference_base_url() -> str:
    """内网推理地址一律从配置取，不在测试里写死集群内 DNS 名。

    旧实现把 ``vllm.inference.svc.cluster.local:8000`` 硬编码进请求体，
    导致：(a) 无沙箱白名单/无网环境下该用例触发真实外网探测而被拦截，
    整份套件跑不完（QA 终局复验只覆盖到 137/138）；(b) 集群域名一变就得
    改测试。改为读 ``INTERNAL_INFERENCE_BASE_URL`` 后，只要设
    ``INTERNAL_INFERENCE_BASE_URL=http://127.0.0.1:9`` 就能本地快速失败、
    完全不出网。
    """
    return get_settings().INTERNAL_INFERENCE_BASE_URL or _UNREACHABLE_INFERENCE_URL


def test_health_and_ready(client):
    assert client.get("/health").status_code == 200
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["database"] == "ok"


def test_login_and_me(client, gov_headers):
    r = client.get("/api/v1/auth/me", headers=gov_headers)
    assert r.status_code == 200
    assert r.json()["role"] == "governance"


def test_bad_password_rejected(client):
    r = client.post(
        "/api/v1/auth/login",
        json={"username": "governance@corp.local", "password": "WrongPass@2026"},
    )
    assert r.status_code in (401, 403, 422)


def test_unauthenticated_access_rejected(client):
    assert client.get("/api/v1/resources", params={"project_id": "prj_core_policy"}).status_code in (401, 403)


def test_projects_visible_to_governance(client, gov_headers):
    r = client.get("/api/v1/resources/projects", headers=gov_headers)
    assert r.status_code == 200
    assert len(r.json()) >= 3


def test_pm_sees_only_authorized_project(client, pm_headers):
    r = client.get("/api/v1/resources/projects", headers=pm_headers)
    assert r.status_code == 200
    ids = {p["id"] for p in r.json()}
    assert ids == {"prj_core_policy"}


def test_viewer_cannot_read_resources_of_any_project(client, viewer_headers):
    r = client.get("/api/v1/resources", params={"project_id": "prj_core_policy"}, headers=viewer_headers)
    assert r.status_code == 403


def test_pm_cannot_read_other_project_resources(client, pm_headers):
    r = client.get("/api/v1/resources", params={"project_id": "prj_claim"}, headers=pm_headers)
    assert r.status_code == 403


def test_governance_cannot_read_l4_secret_project(client, gov_headers):
    """治理岗密级上限 L3：数据中台（L4）的资源一条都不能返回。"""
    r = client.get("/api/v1/resources", params={"project_id": "prj_data"}, headers=gov_headers)
    assert r.status_code == 200
    assert r.json() == []


def test_admin_can_read_l4_project(client, admin_headers):
    r = client.get("/api/v1/resources", params={"project_id": "prj_data"}, headers=admin_headers)
    assert r.status_code == 200


def test_diffs_are_scoped(client, gov_headers):
    r = client.get("/api/v1/resources/diffs", params={"project_id": "prj_core_policy"}, headers=gov_headers)
    assert r.status_code == 200
    assert all(d["project_id"] == "prj_core_policy" for d in r.json())


def test_enumeration_intent_blocked(client, gov_headers):
    r = client.post("/api/v1/knowledge/search", json={"query": "列出所有项目的资源清单"}, headers=gov_headers)
    assert r.status_code == 403


def test_controlled_search_returns_only_authorized_chunks(client, pm_headers):
    r = client.post(
        "/api/v1/knowledge/search",
        json={"query": "资源新增需要核对什么", "project_id": "prj_core_policy", "top_k": 5},
        headers=pm_headers,
    )
    assert r.status_code == 200
    body = r.json()
    hits = body.get("hits", [])
    assert body["security"]["prefiltered"] is True
    for item in hits:
        # 只允许「本项目」或「无项目归属的全局规则」，不得出现其他项目内容
        assert item["project_id"] in (None, "prj_core_policy")
    for level in body["security"]["allowed_levels"]:
        assert level != "L4_SECRET"


def test_search_result_never_contains_canary(client, admin_headers):
    r = client.post(
        "/api/v1/knowledge/search",
        json={"query": "扩容 大促 迁移 敏感", "project_id": "prj_core_policy", "top_k": 8},
        headers=admin_headers,
    )
    assert r.status_code == 200
    text = r.text
    for canary in ("ZB-POLICY-7742", "沈肆", "386500", "2026-11-19"):
        assert canary not in text


def test_attribution_runs_and_is_audited(client, gov_headers):
    diffs = client.get(
        "/api/v1/resources/diffs", params={"project_id": "prj_core_policy"}, headers=gov_headers
    ).json()
    if not diffs:
        return
    diff_id = diffs[0]["id"]
    r = client.post(
        "/api/v1/attribution/run",
        json={"diff_id": diff_id, "question": "这个资源差异可能是什么原因", "top_k": 4},
        headers=gov_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["id"] and body["diff_id"] == diff_id
    assert body["project_id"] == "prj_core_policy"
    assert body["evidence_level"] in ("rule", "llm", "hybrid")
    # 归因输出不得包含金丝雀与负责人姓名
    assert "ZB-POLICY-7742" not in r.text
    assert "沈肆" not in r.text


def test_governance_resolve_writes_audit(client, gov_headers):
    board = client.get(
        "/api/v1/governance/board", params={"project_id": "prj_core_policy"}, headers=gov_headers
    ).json()
    if not board.get("items"):
        return
    diff_id = board["items"][0]["id"]
    r = client.post(
        f"/api/v1/governance/diff/{diff_id}/resolve",
        json={"status": "confirmed", "note": "已与项目组确认"},
        headers=gov_headers,
    )
    assert r.status_code == 200
    logs = client.get("/api/v1/audit/logs", params={"limit": 20}, headers=gov_headers).json()
    assert any("governance" in (row.get("action") or "") for row in logs.get("items", []))


def test_audit_requires_capability(client, pm_headers):
    """项目经理不具备 audit:read 能力。"""
    r = client.get("/api/v1/audit/logs", headers=pm_headers)
    assert r.status_code == 403


def test_collection_dry_run(client, gov_headers):
    r = client.post("/api/v1/collection/run", json={"dry_run": True}, headers=gov_headers)
    assert r.status_code == 200


def test_collection_requires_capability(client, viewer_headers):
    r = client.post("/api/v1/collection/run", json={"dry_run": True}, headers=viewer_headers)
    assert r.status_code == 403


def test_admin_config_hides_secrets(client, admin_headers):
    r = client.get("/api/v1/admin/config", headers=admin_headers)
    assert r.status_code == 200
    body = r.text
    for key in ("SECRET_KEY", "DB_PASSWORD", "OIDC_CLIENT_SECRET"):
        assert key not in body


def test_admin_config_requires_admin(client, gov_headers):
    assert client.get("/api/v1/admin/config", headers=gov_headers).status_code == 403


def test_model_gateway_crud_and_test(client, admin_headers):
    payload = {
        "name": "测试网关",
        "provider": "internal",
        # 从配置取，不写死集群 DNS 名（见 _internal_inference_base_url）
        "base_url": _internal_inference_base_url(),
        "model": "test-model",
        "api_key_ref": "INTERNAL_INFERENCE_API_KEY",
        "enabled": True,
        "is_default": False,
        "sanitize_before_send": True,
        "temperature": 0.1,
        "max_tokens": 1024,
        "timeout_seconds": 30,
    }
    created = client.post("/api/v1/admin/gateways", json=payload, headers=admin_headers)
    assert created.status_code == 200, created.text
    gid = created.json()["id"]
    listed = client.get("/api/v1/admin/gateways", headers=admin_headers).json()
    assert any(g["id"] == gid for g in listed)
    # 连通性测试（内网地址不可达时应返回失败而非异常）
    tested = client.post(f"/api/v1/admin/gateways/{gid}/test", headers=admin_headers)
    assert tested.status_code == 200


def test_public_model_host_is_rejected(client, admin_headers):
    payload = {
        "name": "公网网关",
        "provider": "openai_compatible",
        "base_url": "https://api.openai.com",
        "model": "gpt-4o",
        "enabled": True,
        "is_default": False,
        "sanitize_before_send": True,
        "temperature": 0.1,
        "max_tokens": 1024,
        "timeout_seconds": 30,
    }
    r = client.post("/api/v1/admin/gateways", json=payload, headers=admin_headers)
    # 默认 MODEL_GATEWAY_ALLOW_PUBLIC=false，公网主机应被拒绝
    assert r.status_code in (400, 403, 422), r.text
