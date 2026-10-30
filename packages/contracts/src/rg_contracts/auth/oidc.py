"""OIDC 认证。

- 授权码 + PKCE 换取 token，JWKS 验签 ID Token
- 支持从 roles/groups/org 声明映射角色与组织
- 预留 `DirectoryProvider`：登录后用统一身份接口补全组织信息（项目范围、密级上限）
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from rg_contracts.config import Settings, get_settings
from rg_contracts.errors import AuthenticationError, ConfigurationError
from rg_contracts.logging_setup import get_logger
from rg_contracts.security.policy import Subject

logger = get_logger(__name__)


@dataclass
class AuthorizeUrl:
    url: str
    state: str
    code_verifier: str
    nonce: str


class OidcClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._jwks_cache: dict[str, Any] | None = None
        self._jwks_ts: float = 0.0

    # -------------------------------------------------------------- discovery
    def _discover(self) -> dict:
        issuer = self.settings.OIDC_ISSUER
        if not issuer:
            raise ConfigurationError("OIDC_ISSUER 未配置")
        try:
            with httpx.Client(timeout=self.settings.OIDC_TIMEOUT_SECONDS) as client:
                resp = client.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise ConfigurationError("OIDC 发现文档获取失败", error=str(exc)) from exc

    def _endpoints(self) -> tuple[str, str, str, str]:
        """返回 (authorize_url, token_url, jwks_url, userinfo_url)。"""
        if self.settings.OIDC_AUTHORIZE_URL and self.settings.OIDC_TOKEN_URL:
            return (
                self.settings.OIDC_AUTHORIZE_URL,
                self.settings.OIDC_TOKEN_URL,
                self.settings.OIDC_JWKS_URL or f"{self.settings.OIDC_ISSUER.rstrip('/')}/.well-known/jwks.json",
                self.settings.OIDC_USERINFO_URL,
            )
        doc = self._discover()
        return (
            str(doc.get("authorization_endpoint", "")),
            str(doc.get("token_endpoint", "")),
            self.settings.OIDC_JWKS_URL or str(doc.get("jwks_uri", "")),
            self.settings.OIDC_USERINFO_URL or str(doc.get("userinfo_endpoint", "")),
        )

    # -------------------------------------------------------------- authorize
    def build_authorize_url(self) -> AuthorizeUrl:
        authorize_url, _, _, _ = self._endpoints()
        if not authorize_url:
            raise ConfigurationError("OIDC 授权端点未配置")
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        params = {
            "response_type": "code",
            "client_id": self.settings.OIDC_CLIENT_ID,
            "redirect_uri": self.settings.OIDC_REDIRECT_URI,
            "scope": self.settings.OIDC_SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return AuthorizeUrl(
            url=f"{authorize_url}?{urlencode(params)}", state=state, code_verifier=code_verifier, nonce=nonce
        )

    # ------------------------------------------------------------------ token
    def exchange_code(self, code: str, code_verifier: str) -> dict:
        _, token_url, _, _ = self._endpoints()
        if not token_url:
            raise ConfigurationError("OIDC token 端点未配置")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.settings.OIDC_REDIRECT_URI,
            "client_id": self.settings.OIDC_CLIENT_ID,
            "code_verifier": code_verifier,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.settings.OIDC_CLIENT_SECRET:
            basic = base64.b64encode(
                f"{self.settings.OIDC_CLIENT_ID}:{self.settings.OIDC_CLIENT_SECRET}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {basic}"
        try:
            with httpx.Client(timeout=self.settings.OIDC_TIMEOUT_SECONDS) as client:
                resp = client.post(token_url, data=data, headers=headers)
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError("OIDC 换取 token 失败", error=str(exc)) from exc

    def userinfo(self, access_token: str) -> dict:
        _, _, _, userinfo_url = self._endpoints()
        if not userinfo_url:
            return {}
        try:
            with httpx.Client(timeout=self.settings.OIDC_TIMEOUT_SECONDS) as client:
                resp = client.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("oidc_userinfo_failed", extra={"extra_fields": {"error": str(exc)}})
            return {}

    # --------------------------------------------------------------- verify
    def _jwks(self) -> dict:
        if self._jwks_cache and time.time() - self._jwks_ts < 600:
            return self._jwks_cache
        _, _, jwks_url, _ = self._endpoints()
        if not jwks_url:
            raise ConfigurationError("OIDC JWKS 地址未配置")
        try:
            with httpx.Client(timeout=self.settings.OIDC_TIMEOUT_SECONDS) as client:
                resp = client.get(jwks_url)
                resp.raise_for_status()
                self._jwks_cache = resp.json()
                self._jwks_ts = time.time()
                return self._jwks_cache
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError("JWKS 获取失败", error=str(exc)) from exc

    def verify_id_token(self, id_token: str, nonce: str | None = None) -> dict:
        jwks = self._jwks()
        try:
            header = jwt.get_unverified_header(id_token)
            key = next(k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid"))
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        except StopIteration:
            raise AuthenticationError("ID Token 的 kid 未匹配到 JWKS")
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError("ID Token 解析失败", error=str(exc)) from exc

        audience = self.settings.OIDC_CLIENT_ID or None
        try:
            claims = jwt.decode(
                id_token,
                key=public_key,
                algorithms=["RS256", "RS384", "RS512"],
                audience=audience,
                issuer=self.settings.OIDC_ISSUER or None,
                options={"verify_aud": bool(audience), "verify_iss": bool(self.settings.OIDC_ISSUER)},
            )
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError("ID Token 校验失败", error=str(exc)) from exc
        if nonce and claims.get("nonce") and claims["nonce"] != nonce:
            raise AuthenticationError("OIDC nonce 校验失败")
        return claims


@dataclass
class DirectoryProfile:
    """目录服务返回的组织信息。"""

    subject: str
    display_name: str
    email: str | None
    role: str
    org_id: str | None
    org_name: str | None
    classification_ceiling: str
    project_ids: list[str]
    visible_ceilings: dict[str, str]
    attributes: dict


class DirectoryProvider:
    """公司统一身份/组织信息接口。实现时替换 fetch 即可，无需改动调用方。"""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def fetch(self, subject: str, claims: dict | None = None) -> DirectoryProfile:
        mode = self.settings.DIRECTORY_MODE.value
        claims = claims or {}
        if mode == "http":
            return self._fetch_http(subject, claims)
        if mode == "ldap":
            return self._fetch_ldap(subject, claims)
        return self._fetch_static(subject, claims)

    # ------------------------------------------------------------- static
    def _fetch_static(self, subject: str, claims: dict) -> DirectoryProfile:
        from rg_contracts.config import load_json_config

        data = load_json_config(self.settings.DIRECTORY_STATIC_FILE)
        users = data.get("users", {}) if isinstance(data, dict) else {}
        profile = users.get(subject) or users.get(claims.get("email", "")) or {}
        return DirectoryProfile(
            subject=subject,
            display_name=profile.get("display_name") or claims.get("name") or subject,
            email=profile.get("email") or claims.get("email"),
            role=profile.get("role")
            or _role_from_claims(claims, self.settings)
            or "viewer",
            org_id=profile.get("org_id"),
            org_name=profile.get("org_name"),
            classification_ceiling=profile.get("classification_ceiling", "L2_INTERNAL"),
            project_ids=list(profile.get("project_ids", [])),
            visible_ceilings=dict(profile.get("visible_ceilings", {})),
            attributes=dict(profile.get("attributes", {})),
        )

    # --------------------------------------------------------------- http
    def _fetch_http(self, subject: str, claims: dict) -> DirectoryProfile:
        url = self.settings.DIRECTORY_HTTP_URL
        if not url:
            raise ConfigurationError("DIRECTORY_HTTP_URL 未配置")
        headers = {"Content-Type": "application/json"}
        if self.settings.DIRECTORY_HTTP_TOKEN:
            headers["Authorization"] = f"Bearer {self.settings.DIRECTORY_HTTP_TOKEN}"
        try:
            with httpx.Client(timeout=self.settings.DIRECTORY_TIMEOUT_SECONDS) as client:
                resp = client.post(url, json={"subject": subject, "claims": claims}, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise ConfigurationError("目录服务调用失败", error=str(exc)) from exc
        return DirectoryProfile(
            subject=subject,
            display_name=data.get("display_name") or subject,
            email=data.get("email"),
            role=data.get("role") or "viewer",
            org_id=data.get("org_id"),
            org_name=data.get("org_name"),
            classification_ceiling=data.get("classification_ceiling", "L2_INTERNAL"),
            project_ids=list(data.get("project_ids", [])),
            visible_ceilings=dict(data.get("visible_ceilings", {})),
            attributes=dict(data.get("attributes", {})),
        )

    # --------------------------------------------------------------- ldap
    def _fetch_ldap(self, subject: str, claims: dict) -> DirectoryProfile:
        """预留：接入公司 LDAP/AD。默认回退静态配置并标记来源。"""
        profile = self._fetch_static(subject, claims)
        profile.attributes["directory_source"] = "ldap_not_wired"
        logger.warning(
            "directory_ldap_not_implemented",
            extra={"extra_fields": {"url": self.settings.DIRECTORY_LDAP_URL}},
        )
        return profile


def _role_from_claims(claims: dict, settings: Settings) -> str | None:
    groups = claims.get(settings.OIDC_GROUPS_CLAIM) or []
    roles = claims.get(settings.OIDC_ROLES_CLAIM) or []
    role_map = {
        "rg-admin": "admin",
        "rg-governance": "governance",
        "rg-pm": "pm",
        "rg-auditor": "auditor",
    }
    for item in list(roles) + list(groups):
        key = str(item).lower()
        if key in role_map:
            return role_map[key]
    return None


def profile_to_subject(profile: DirectoryProfile, user_id: str) -> Subject:
    return Subject(
        user_id=user_id,
        subject=profile.subject,
        display_name=profile.display_name,
        role=profile.role,
        org_id=profile.org_id,
        classification_ceiling=profile.classification_ceiling,
        project_ids=frozenset(profile.project_ids),
        visible_ceilings=profile.visible_ceilings,
        auth_mode="oidc",
        attributes=profile.attributes,
    )


__all__ = [
    "AuthorizeUrl",
    "DirectoryProfile",
    "DirectoryProvider",
    "OidcClient",
    "profile_to_subject",
]
