"""R10 回归：OIDC state 服务端一次性校验 + 刷新令牌只走 HttpOnly Cookie。

覆盖两条被加固的不变量：

1. **state 由服务端落库校验并一次性消费**——伪造 / 重放 / 超期三条拒绝路径，
   且校验发生在与 IdP 换 token **之前**（否则伪造 state 能消耗掉我们的会话）。
   PKCE verifier 与 nonce 只留在服务端，不再下发浏览器。
2. **刷新令牌不出现在响应体**，只在 HttpOnly + Secure + SameSite=Strict
   Cookie 里；请求体传令牌一律无效（否则前端会为了兼容把它放回可读存储）。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from rg_contracts.config import Settings
from rg_contracts.db.models import OidcLoginState, TimestampCodec
from sqlalchemy import select

from rg_api.routes import auth as auth_module

OIDC_SUBJECT = "alice@corp.local"
REFRESH_COOKIE = auth_module.REFRESH_COOKIE_NAME
DEV_LOGIN = {"username": "admin@corp.local", "password": "Admin@2026"}


@pytest.fixture
def oidc_mode(monkeypatch):
    """把 auth 模块切到 OIDC 模式，并桩掉与 IdP 的网络交互。

    返回 (settings, calls)：``calls`` 记录桩函数被调用的顺序，用来断言
    「先校验 state、再换 token」。
    """
    settings = Settings(
        APP_ENV="test",
        AUTH_MODE="oidc",
        DB_DIALECT="sqlite",
        OIDC_ISSUER="https://idp.test",
        OIDC_CLIENT_ID="cloud-rag",
        OIDC_AUTHORIZE_URL="https://idp.test/authorize",
        OIDC_TOKEN_URL="https://idp.test/token",
        OIDC_REDIRECT_URI="http://localhost:5173/auth/callback",
        DEV_LOGIN_ENABLED=False,
        DIRECTORY_MODE="static",
        SECRET_KEY="test-secret-key",
        SECURITY_TOKEN_SALT="test-token-salt",
    )
    calls: list[str] = []

    def fake_exchange(self, code, code_verifier):
        calls.append(f"exchange:{code}:{code_verifier}")
        return {"id_token": "fake.id.token", "access_token": "fake-access"}

    def fake_verify(self, id_token, nonce=None):
        calls.append(f"verify:{nonce}")
        return {"sub": OIDC_SUBJECT, "email": OIDC_SUBJECT, "name": "Alice"}

    monkeypatch.setattr(auth_module, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_module.OidcClient, "exchange_code", fake_exchange)
    monkeypatch.setattr(auth_module.OidcClient, "verify_id_token", fake_verify)
    return settings, calls


def _authorize(client) -> dict:
    resp = client.get("/api/v1/auth/oidc/authorize")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _state_record(session, state: str) -> OidcLoginState:
    digest = hashlib.sha256(state.encode()).hexdigest()
    record = session.execute(
        select(OidcLoginState).where(OidcLoginState.state_hash == digest)
    ).scalar_one()
    return record


# --------------------------------------------------------------- ① state 校验


def test_authorize_persists_state_and_keeps_verifier_server_side(client, oidc_mode, session):
    """签发即落库；PKCE verifier 与 nonce 不再返回给浏览器。"""
    data = _authorize(client)
    assert data["authorize_url"].startswith("https://idp.test/authorize?")
    assert data["state"]
    assert "code_verifier" not in data, "PKCE verifier 不得下发浏览器"
    assert "nonce" not in data, "nonce 不得下发浏览器"

    record = _state_record(session, data["state"])
    assert record.code_verifier and record.nonce
    assert record.consumed_at is None
    assert record.redirect_uri == "http://localhost:5173/auth/callback"
    # 有效期约 5 分钟（OIDC_STATE_TTL_SECONDS）。用 TimestampCodec.decode 归一化：
    # SQLite 上 TS() 存 ISO 文本，PG 上 timestamptz 直接回 datetime。
    window = TimestampCodec.decode(record.expires_at) - TimestampCodec.decode(record.created_at)
    assert timedelta(minutes=4) < window <= timedelta(minutes=5, seconds=5)


def test_callback_with_matching_state_succeeds(client, oidc_mode, session):
    """正常流程：state 匹配即消费，PKCE verifier / nonce 取服务端落库值。"""
    data = _authorize(client)
    resp = client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "auth-code", "state": data["state"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["subject"] == OIDC_SUBJECT
    assert "refresh_token" not in body, "响应体不得出现刷新令牌明文"

    record = _state_record(session, data["state"])
    assert record.consumed_at is not None
    assert record.subject == OIDC_SUBJECT, "消费主体要回填，便于事后审计"

    _, calls = oidc_mode
    stored = _state_record(session, data["state"])
    assert f"exchange:auth-code:{stored.code_verifier}" in calls
    assert f"verify:{stored.nonce}" in calls


def test_callback_rejects_unknown_state_before_token_exchange(client, oidc_mode):
    """伪造 / 不属于本服务的 state 一律拒绝，且不得触发与 IdP 的换 token。"""
    resp = client.post(
        "/api/v1/auth/oidc/callback",
        json={"code": "auth-code", "state": "forged-state"},
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["code"] == "unauthenticated"
    _, calls = oidc_mode
    assert calls == [], "state 校验必须发生在换 token 之前"


def test_callback_rejects_replayed_state(client, oidc_mode, session):
    """重放：同一个 state 只能消费一次。"""
    data = _authorize(client)
    first = client.post(
        "/api/v1/auth/oidc/callback", json={"code": "auth-code", "state": data["state"]}
    )
    assert first.status_code == 200, first.text

    replay = client.post(
        "/api/v1/auth/oidc/callback", json={"code": "auth-code", "state": data["state"]}
    )
    assert replay.status_code == 401, replay.text
    assert "已被使用" in replay.json()["message"]


def test_callback_rejects_expired_state(client, oidc_mode, session):
    """超期（默认 5 分钟窗口）：即使没被用过也必须拒绝。"""
    data = _authorize(client)
    stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    record = _state_record(session, data["state"])
    record.expires_at = stale
    session.commit()

    resp = client.post(
        "/api/v1/auth/oidc/callback", json={"code": "auth-code", "state": data["state"]}
    )
    assert resp.status_code == 401, resp.text
    assert "过期" in resp.json()["message"]


def test_callback_requires_state_field(client, oidc_mode):
    """缺 state 直接 422：没有 state 就没有 CSRF 防护，不能默认放行。"""
    resp = client.post("/api/v1/auth/oidc/callback", json={"code": "auth-code"})
    assert resp.status_code == 422, resp.text


# --------------------------------------------------------- ② 刷新令牌 Cookie


def _set_cookie_value(resp, name: str) -> str:
    raw = resp.headers.get("set-cookie", "")
    for part in raw.split(";"):
        if part.strip().startswith(f"{name}="):
            return part.split("=", 1)[1]
    raise AssertionError(f"Set-Cookie 中没有 {name}: {raw!r}")


def test_login_returns_no_refresh_token_and_sets_hardened_cookie(client):
    """登录：响应体无明文；Cookie 必须 HttpOnly + Secure + SameSite=Strict。"""
    resp = client.post("/api/v1/auth/login", json=DEV_LOGIN)
    assert resp.status_code == 200, resp.text
    assert "refresh_token" not in resp.json()

    raw = resp.headers.get("set-cookie", "")
    assert f"{REFRESH_COOKIE}=" in raw
    assert "httponly" in raw.lower()
    assert "secure" in raw.lower()
    assert "samesite=strict" in raw.lower()
    assert f"path={auth_module.REFRESH_COOKIE_PATH}" in raw.lower()


def test_refresh_reads_cookie_and_issues_access_token(client):
    """刷新：只认 Cookie，换回新的访问令牌且不再回传刷新令牌。"""
    login = client.post("/api/v1/auth/login", json=DEV_LOGIN)
    cookie = _set_cookie_value(login, REFRESH_COOKIE)

    resp = client.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{REFRESH_COOKIE}={cookie}"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert "refresh_token" not in body
    assert f"{REFRESH_COOKIE}=" in resp.headers.get("set-cookie", ""), "刷新后续期 Cookie"


def test_refresh_without_cookie_is_rejected(client):
    resp = client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401, resp.text
    assert resp.json()["code"] == "unauthenticated"


def test_refresh_rejects_token_sent_in_request_body(client):
    """请求体传刷新令牌必须无效——否则前端会为了兼容把它放回可读存储。"""
    login = client.post("/api/v1/auth/login", json=DEV_LOGIN)
    cookie = _set_cookie_value(login, REFRESH_COOKIE)

    resp = client.post("/api/v1/auth/refresh", json={"refresh_token": cookie})
    assert resp.status_code == 401, resp.text


def test_refresh_rejects_access_token_used_as_refresh(client, admin_headers):
    """拿访问令牌当刷新令牌用必须被拒（typ 校验）。"""
    token = admin_headers["Authorization"].split(" ", 1)[1]
    resp = client.post(
        "/api/v1/auth/refresh", headers={"Cookie": f"{REFRESH_COOKIE}={token}"}
    )
    assert resp.status_code == 401, resp.text


def test_logout_clears_refresh_cookie(client, admin_headers):
    resp = client.post("/api/v1/auth/logout", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    raw = resp.headers.get("set-cookie", "")
    assert f"{REFRESH_COOKIE}=" in raw
    assert "max-age=0" in raw.lower()


def test_logout_works_with_invalid_access_token(client):
    """令牌过期恰恰是最需要登出的时刻：不能 401 把 Cookie 卡住。"""
    resp = client.post(
        "/api/v1/auth/logout", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert resp.status_code == 200, resp.text
    assert f"{REFRESH_COOKIE}=" in resp.headers.get("set-cookie", "")