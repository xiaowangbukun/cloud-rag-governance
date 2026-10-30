"""启动真实 uvicorn 服务并做一次端到端 HTTP 验证（非 TestClient）。"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def _get(url: str, token: str | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _post(url: str, body: dict, token: str | None = None) -> tuple[int, str]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rg_live_")
    env = dict(os.environ)
    env.update(
        {
            "APP_ENV": "test",
            "DB_DIALECT": "sqlite",
            "SQLITE_PATH": os.path.join(tmp, "live.db").replace("\\", "/"),
            "DEMO_SEED": "true",
            "LOG_LEVEL": "WARNING",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "rg_api.main:app", "--host", "127.0.0.1", "--port", "8099"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = "http://127.0.0.1:8099"
    results: list[tuple[str, bool, str]] = []
    try:
        for _ in range(60):
            try:
                code, _ = _get(f"{base}/health")
                if code == 200:
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        else:
            print("FAIL 服务未能在 30s 内启动")
            return 1

        code, body = _get(f"{base}/ready")
        results.append(("ready", code == 200, body[:100]))

        code, body = _post(
            f"{base}/api/v1/auth/login",
            {"username": "governance@corp.local", "password": "Gov@2026"},
        )
        token = json.loads(body).get("access_token") if code == 200 else None
        results.append(("login", bool(token), body[:80]))

        code, body = _get(f"{base}/api/v1/resources/projects", token)
        projects = json.loads(body) if code == 200 else []
        results.append(("projects", len(projects) > 0, str(len(projects))))

        pid = projects[0]["id"] if projects else ""
        code, body = _get(f"{base}/api/v1/resources/diffs?project_id={pid}", token)
        results.append(("diffs", code == 200, f"{code} {body[:80]}"))

        code, body = _post(
            f"{base}/api/v1/knowledge/search",
            {"query": "资源新增需要核对什么", "project_id": pid, "top_k": 4},
            token,
        )
        results.append(("search", code == 200, f"{code} {body[:80]}"))

        code, body = _get(f"{base}/api/v1/governance/board?project_id={pid}", token)
        results.append(("board", code == 200, f"{code} {body[:80]}"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # noqa: F821
            proc.kill()

    failed = 0
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
        if not ok:
            failed += 1
    print(f"\nTOTAL={len(results)} FAILED={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
