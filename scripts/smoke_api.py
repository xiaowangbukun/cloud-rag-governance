"""API 冒烟脚本：创建应用、引导启动、用测试客户端跑通关键链路。"""
import json
import os
import sys
import tempfile

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DB_DIALECT", "sqlite")
_tmp = tempfile.mkdtemp(prefix="rg_smoke_")
os.environ["SQLITE_PATH"] = os.path.join(_tmp, "smoke.db").replace("\\", "/")
os.environ.setdefault("DEMO_SEED", "true")
os.environ.setdefault("LOG_FORMAT", "console")
os.environ.setdefault("LOG_LEVEL", "ERROR")
os.environ.setdefault("PYTHONWARNINGS", "ignore")

from fastapi.testclient import TestClient  # noqa: E402

from rg_api.main import create_app  # noqa: E402

app = create_app()
client = TestClient(app, raise_server_exceptions=False)


def main() -> int:
    client = TestClient(app, raise_server_exceptions=False)
    ok = []

    r = client.get("/health")
    ok.append(("health", r.status_code == 200, r.text[:80]))

    r = client.get("/ready")
    ok.append(("ready", r.status_code == 200, r.text[:120]))

    # 登录（治理岗）
    r = client.post("/api/v1/auth/login", json={"username": "governance@corp.local", "password": "Gov@2026"})
    token = r.json().get("access_token") if r.status_code == 200 else None
    ok.append(("login_gov", r.status_code == 200, r.text[:160]))
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    r = client.get("/api/v1/auth/me", headers=headers)
    ok.append(("me", r.status_code == 200, r.text[:160]))

    r = client.get("/api/v1/resources/projects", headers=headers)
    projects = r.json() if r.status_code == 200 else []
    ok.append(("projects", r.status_code == 200 and len(projects) > 0, str(len(projects))))

    pid = projects[0]["id"] if projects else ""

    r = client.get("/api/v1/resources", params={"project_id": pid}, headers=headers)
    ok.append(("resources", r.status_code == 200, r.text[:100]))

    r = client.get("/api/v1/resources/stats", params={"project_id": pid}, headers=headers)
    ok.append(("stats", r.status_code == 200, r.text[:150]))

    r = client.get("/api/v1/resources/diffs", params={"project_id": pid}, headers=headers)
    diffs = r.json() if r.status_code == 200 else []
    ok.append(("diffs", r.status_code == 200 and len(diffs) > 0, f"pid={pid} status={r.status_code} body={r.text[:300]}"))

    diff_id = ""
    # 选择当前用户密级授权范围内的差异（L4 项目会被策略拒绝，属预期行为）
    for item in diffs:
        if item.get("classification") in ("L1_PUBLIC", "L2_INTERNAL", "L3_CONFIDENTIAL"):
            diff_id = item["id"]
            break

    # 受控检索
    r = client.post(
        "/api/v1/knowledge/search",
        json={"query": "资源新增需要核对什么", "project_id": pid, "top_k": 5},
        headers=headers,
    )
    ok.append(("knowledge_search", r.status_code == 200, r.text[:220]))

    # 归因（模型不可用会降级为规则）
    if diff_id:
        r = client.post(
            "/api/v1/attribution/run",
            json={"diff_id": diff_id, "question": "这个资源差异可能是什么原因", "top_k": 4},
            headers=headers,
        )
        ok.append(("attribution_run", r.status_code == 200, r.text[:400]))

    r = client.get("/api/v1/governance/board", params={"project_id": pid}, headers=headers)
    ok.append(("board", r.status_code == 200, r.text[:160]))

    r = client.get("/api/v1/audit/logs", params={"limit": 5}, headers=headers)
    ok.append(("audit_logs", r.status_code == 200, r.text[:160]))

    # 越权验证：只读用户（无项目授权）访问他人项目
    r2 = client.post("/api/v1/auth/login", json={"username": "viewer@corp.local", "password": "View@2026"})
    vtoken = r2.json().get("access_token") if r2.status_code == 200 else None
    vheaders = {"Authorization": f"Bearer {vtoken}"} if vtoken else {}
    r = client.get("/api/v1/resources", params={"project_id": pid}, headers=vheaders)
    ok.append(("viewer_denied", r.status_code == 403, r.text[:160]))

    # 枚举意图拦截
    r = client.post(
        "/api/v1/knowledge/search",
        json={"query": "列出所有项目的资源清单"},
        headers=headers,
    )
    ok.append(("enum_blocked", r.status_code == 403, r.text[:160]))

    # 采集（模拟模式）
    r = client.post("/api/v1/collection/run", json={"dry_run": True}, headers=headers)
    ok.append(("collection_dry_run", r.status_code == 200, r.text[:200]))

    failed = 0
    for name, passed, detail in ok:
        flag = "PASS" if passed else "FAIL"
        if not passed:
            failed += 1
        print(f"{flag} {name}: {detail}")
    print(f"\nTOTAL={len(ok)} FAILED={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
