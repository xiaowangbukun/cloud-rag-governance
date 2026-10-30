"""R4（P0-7）回归：生产环境弱密钥/占位符必须拒绝启动 + k8s 清单无明文占位。

缺陷形态：``SECRET_KEY`` 是 JWT 签名密钥，k8s 清单曾内置 ``CHANGE_ME``
占位符且配置层无弱值校验——占位符一旦被原样部署，任何人均可伪造
令牌。修复：k8s 值改为 ``REPLACE_VIA_EXTERNAL_SECRET``，配置层在生产
环境对弱值/占位符/过短密钥/DEMO_SEED/dev 认证直接 fail-fast。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from rg_contracts.config import Settings

STRONG_KEY = "k7Fp2QvXzR9mT4wYbN6cH3jL8sD5gA1e"  # 32 位强随机样式
STRONG_SALT = "r8Hc3NwZqT5mV1yKbP7dLfJ4sX9gU2aE"  # 32 位强随机样式

_K8S_CONFIG = Path(__file__).resolve().parents[3] / "deploy" / "k8s" / "01-config.yaml"


def _prod_settings(**overrides) -> Settings:
    """构造一份「除覆盖项外均合法」的生产配置。"""
    base = {
        "APP_ENV": "prod",
        "AUTH_MODE": "oidc",
        "OIDC_ISSUER": "https://sso.corp.local/realms/corp",
        "DB_DIALECT": "postgresql",
        "DEV_LOGIN_ENABLED": False,
        "DEMO_SEED": False,
        "SECRET_KEY": STRONG_KEY,
        "SECURITY_TOKEN_SALT": STRONG_SALT,
    }
    base.update(overrides)
    return Settings(**base)


def test_prod_accepts_strong_secret_key():
    """控制组：合法生产配置必须能构造（防止校验过度收紧）。"""
    settings = _prod_settings()
    assert settings.is_prod
    assert settings.SECRET_KEY == STRONG_KEY


def test_prod_derives_require_sslmode():
    """SSLMODE 默认值必须在实例化时按 APP_ENV 求值（旧实现恒为 prefer）。"""
    assert _prod_settings().DB_SSLMODE == "require"
    assert Settings(APP_ENV="local").DB_SSLMODE == "prefer"


@pytest.mark.parametrize("sslmode", ["disable", "allow", "prefer"])
def test_prod_rejects_sslmode_downgrade(sslmode):
    """生产禁止明文/降级 TLS 的 sslmode。"""
    with pytest.raises(ValidationError, match="DB_SSLMODE"):
        _prod_settings(DB_SSLMODE=sslmode)


def test_prod_requires_explicit_token_salt():
    """生产必须显式提供 salt：缺省回退「每进程随机」会让多副本互不认账。"""
    params = {
        "APP_ENV": "prod",
        "AUTH_MODE": "oidc",
        "OIDC_ISSUER": "https://sso.corp.local/realms/corp",
        "DB_DIALECT": "postgresql",
        "DEV_LOGIN_ENABLED": False,
        "DEMO_SEED": False,
        "SECRET_KEY": STRONG_KEY,
    }
    with pytest.raises(ValidationError, match="SECURITY_TOKEN_SALT"):
        Settings(**params)


@pytest.mark.parametrize(
    "weak_salt",
    ["REPLACE_VIA_EXTERNAL_SECRET", "change_me", "secret", "too-short"],
)
def test_prod_rejects_weak_or_placeholder_token_salt(weak_salt):
    """salt 参与令牌派生：占位符/弱值等价于缺省，生产必须拒绝。"""
    with pytest.raises(ValidationError, match="SECURITY_TOKEN_SALT"):
        _prod_settings(SECURITY_TOKEN_SALT=weak_salt)


def test_prod_rejects_insecure_refresh_cookie():
    """生产必须 HTTPS：Secure Cookie 被关掉意味着刷新令牌可经明文发送。"""
    with pytest.raises(ValidationError, match="AUTH_COOKIE_SECURE"):
        _prod_settings(AUTH_COOKIE_SECURE=False)


@pytest.mark.parametrize(
    "weak_key",
    [
        "CHANGE_ME",
        "change_me",
        "REPLACE_VIA_EXTERNAL_SECRET",
        "replace_via_external_secret",
        "secret",
        "test",
        "dev",
        "",
        "too-short",
        "k7Fp2QvXzR9mT4wYbN6cH3jL8sD5gA1",  # 31 位：差一位也不放行
    ],
)
def test_prod_rejects_weak_or_placeholder_secret_key(weak_key):
    """核心回归：占位符/弱值/过短密钥在生产环境一律拒绝启动。"""
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        _prod_settings(SECRET_KEY=weak_key)


def test_prod_rejects_demo_seed():
    """生产开 DEMO_SEED 会灌入演示账号，必须拒绝。"""
    with pytest.raises(ValidationError, match="DEMO_SEED"):
        _prod_settings(DEMO_SEED=True)


def test_prod_rejects_dev_auth_mode():
    """生产禁用 AUTH_MODE=dev（本地登录后门）。"""
    with pytest.raises(ValidationError, match="AUTH_MODE"):
        _prod_settings(AUTH_MODE="dev")


def test_non_prod_environments_allow_weak_key():
    """local/test 保持开发友好：弱密钥不拦截（仅生产 fail-fast）。"""
    for env in ("local", "test"):
        settings = Settings(APP_ENV=env, SECRET_KEY="CHANGE_ME")
        assert settings.SECRET_KEY == "CHANGE_ME"


def _deploy_files() -> list[Path]:
    """全部部署清单：k8s/*.yaml + docker-compose.yml。

    QA 复核发现：守卫原先只读 01-config.yaml，导致 02-postgres.yaml 里的
    ``POSTGRES_PASSWORD: "CHANGE_ME"`` 溜过。扫描必须覆盖全部部署文件。
    """
    deploy_dir = _K8S_CONFIG.parent.parent
    files = sorted(deploy_dir.glob("k8s/*.yaml")) + sorted(deploy_dir.glob("k8s/*.yml"))
    compose = deploy_dir / "docker-compose.yml"
    if compose.exists():
        files.append(compose)
    assert files, f"未找到任何部署清单：{deploy_dir}"
    return files


def test_deploy_manifests_have_no_plaintext_placeholder():
    """全部部署清单：不得残留 CHANGE_ME（逐文件断言，报告里点名是哪一份）。"""
    for path in _deploy_files():
        content = path.read_text(encoding="utf-8")
        assert "CHANGE_ME" not in content, f"{path.name} 仍残留 CHANGE_ME 占位符"


def test_api_secret_manifest_has_all_expected_placeholders():
    """api-secrets：6 个敏感项齐全且均为外部注入占位。

    ``DB_APP_PASSWORD`` 是运行角色（rg_app）的独立密码，与属主的 ``DB_PASSWORD``
    分开：凭据不分开，业务进程就能用属主身份绕过 RLS（见 docs/rls.md）。
    """
    content = _K8S_CONFIG.read_text(encoding="utf-8")
    value_marker = ': "REPLACE_VIA_EXTERNAL_SECRET"'
    placeholders = content.count(value_marker)
    assert placeholders == 6, f"期望 6 个 REPLACE_VIA_EXTERNAL_SECRET 占位，实际 {placeholders}"
    for key in (
        "DB_PASSWORD",
        "DB_APP_PASSWORD",
        "SECRET_KEY",
        "SECURITY_TOKEN_SALT",
        "OIDC_CLIENT_SECRET",
        "DIRECTORY_HTTP_TOKEN",
    ):
        assert f'{key}: "REPLACE_VIA_EXTERNAL_SECRET"' in content, f"{key} 未使用外部注入占位"


def test_postgres_secret_manifest_uses_external_placeholder():
    """postgres-secret：数据库密码同样走外部注入占位，不得明文。"""
    content = (_K8S_CONFIG.parent / "02-postgres.yaml").read_text(encoding="utf-8")
    assert 'POSTGRES_PASSWORD: "REPLACE_VIA_EXTERNAL_SECRET"' in content
