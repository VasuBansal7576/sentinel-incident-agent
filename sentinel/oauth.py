from __future__ import annotations

import base64
import hmac
import os
import time
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlencode

import httpx

from sentinel.config import DATADOG_ALLOWED_SITES, SentinelSettings, _normalize_datadog_site
from sentinel.errors import ToolErrorKind, ToolExecutionError, redact_sensitive_text


@dataclass(frozen=True)
class OAuthState:
    nonce: str
    provider: str
    issued_at: int
    signature: str

    def encode(self) -> str:
        raw = f"{self.provider}:{self.nonce}:{self.issued_at}:{self.signature}"
        return base64.urlsafe_b64encode(raw.encode()).decode()


class OAuthManager:
    def __init__(self, settings: SentinelSettings):
        self.settings = settings
        self._state_secret = self._resolve_state_secret()

    def slack_install_url(self, *, state: str | None = None) -> str:
        self._require(self.settings.slack_client_id, "SLACK_CLIENT_ID")
        self._require(self.settings.slack_client_secret, "SLACK_CLIENT_SECRET")
        self._require(self.settings.slack_redirect_uri, "SLACK_REDIRECT_URI")
        params = {
            "client_id": self.settings.slack_client_id,
            "scope": ",".join(self.settings.slack_oauth_scopes),
            "redirect_uri": self.settings.slack_redirect_uri,
            "state": state or self.issue_state("slack"),
        }
        return "https://slack.com/oauth/v2/authorize?" + urlencode(params)

    def github_install_url(self, *, state: str | None = None) -> str:
        self._require(self.settings.github_client_id, "GITHUB_CLIENT_ID")
        self._require(self.settings.github_client_secret, "GITHUB_CLIENT_SECRET")
        self._require(self.settings.github_redirect_uri, "GITHUB_REDIRECT_URI")
        params = {
            "client_id": self.settings.github_client_id,
            "scope": ",".join(self.settings.github_oauth_scopes),
            "state": state or self.issue_state("github"),
            "redirect_uri": self.settings.github_redirect_uri,
        }
        return "https://github.com/login/oauth/authorize?" + urlencode(params)

    def datadog_install_url(self, *, state: str | None = None, code_verifier: str | None = None) -> str:
        self._require(self.settings.datadog_client_id, "DD_CLIENT_ID")
        self._require(self.settings.datadog_client_secret, "DD_CLIENT_SECRET")
        self._require(self.settings.datadog_redirect_uri, "DD_REDIRECT_URI")
        verifier = code_verifier or self.issue_pkce_verifier()
        params = {
            "client_id": self.settings.datadog_client_id,
            "redirect_uri": self.settings.datadog_redirect_uri,
            "response_type": "code",
            "code_challenge": self.pkce_challenge(verifier),
            "code_challenge_method": "S256",
            "state": state or self.issue_state("datadog"),
        }
        return datadog_app_base_url(self.settings.datadog_site) + "/oauth2/v1/authorize?" + urlencode(params)

    def exchange_slack_code(self, code: str, state: str) -> dict:
        self.verify_state(state, "slack")
        self._require(self.settings.slack_client_id, "SLACK_CLIENT_ID")
        self._require(self.settings.slack_client_secret, "SLACK_CLIENT_SECRET")
        data = {
            "client_id": self.settings.slack_client_id,
            "client_secret": self.settings.slack_client_secret,
            "code": code,
        }
        if self.settings.slack_redirect_uri:
            data["redirect_uri"] = self.settings.slack_redirect_uri
        response = _post_oauth("Slack", "https://slack.com/api/oauth.v2.access", data=data)
        payload = _oauth_json(response, "Slack")
        if response.status_code >= 400 or not payload.get("ok"):
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"Slack OAuth exchange failed: {payload.get('error') or redact_sensitive_text(response.text, max_length=300)}",
                retryable=False,
            )
        _require_oauth_access_token(payload, "Slack")
        _validate_oauth_scopes("Slack", payload, self.settings.slack_oauth_scopes)
        return payload

    def exchange_github_code(self, code: str, state: str) -> dict:
        self.verify_state(state, "github")
        self._require(self.settings.github_client_id, "GITHUB_CLIENT_ID")
        self._require(self.settings.github_client_secret, "GITHUB_CLIENT_SECRET")
        body = {
            "client_id": self.settings.github_client_id,
            "client_secret": self.settings.github_client_secret,
            "code": code,
        }
        if self.settings.github_redirect_uri:
            body["redirect_uri"] = self.settings.github_redirect_uri
        response = _post_oauth(
            "GitHub",
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            json=body,
        )
        payload = _oauth_json(response, "GitHub")
        if response.status_code >= 400:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"GitHub OAuth exchange failed: {payload.get('error') or redact_sensitive_text(response.text, max_length=300)}",
                retryable=False,
            )
        _require_oauth_access_token(payload, "GitHub")
        _validate_oauth_scopes("GitHub", payload, self.settings.github_oauth_scopes)
        return payload

    def exchange_datadog_code(
        self,
        code: str,
        state: str,
        *,
        code_verifier: str,
        domain: str | None = None,
    ) -> dict:
        self.verify_state(state, "datadog")
        self._require(self.settings.datadog_client_id, "DD_CLIENT_ID")
        self._require(self.settings.datadog_client_secret, "DD_CLIENT_SECRET")
        self._require(self.settings.datadog_redirect_uri, "DD_REDIRECT_URI")
        site_domain = datadog_api_domain(domain, self.settings.datadog_site)
        data = {
            "client_id": self.settings.datadog_client_id,
            "client_secret": self.settings.datadog_client_secret,
            "redirect_uri": self.settings.datadog_redirect_uri,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
        }
        response = _post_oauth("Datadog", f"https://api.{site_domain}/oauth2/v1/token", data=data)
        payload = _oauth_json(response, "Datadog")
        if response.status_code >= 400:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"Datadog OAuth exchange failed: {payload.get('error') or redact_sensitive_text(response.text, max_length=300)}",
                retryable=False,
            )
        _require_oauth_access_token(payload, "Datadog")
        _validate_oauth_scopes("Datadog", payload, self.settings.datadog_oauth_required_scopes)
        payload.setdefault("domain", site_domain)
        return payload

    def refresh_datadog_token(self, refresh_token: str, *, domain: str | None = None) -> dict:
        self._require(self.settings.datadog_client_id, "DD_CLIENT_ID")
        self._require(self.settings.datadog_client_secret, "DD_CLIENT_SECRET")
        self._require(self.settings.datadog_redirect_uri, "DD_REDIRECT_URI")
        self._require(refresh_token, "Datadog refresh_token")
        site_domain = datadog_api_domain(domain, self.settings.datadog_site)
        data = {
            "client_id": self.settings.datadog_client_id,
            "client_secret": self.settings.datadog_client_secret,
            "redirect_uri": self.settings.datadog_redirect_uri,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        response = _post_oauth("Datadog", f"https://api.{site_domain}/oauth2/v1/token", data=data)
        payload = _oauth_json(response, "Datadog")
        if response.status_code >= 400:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"Datadog OAuth refresh failed: {payload.get('error') or redact_sensitive_text(response.text, max_length=300)}",
                retryable=False,
            )
        _require_oauth_access_token(payload, "Datadog")
        _validate_oauth_scopes("Datadog", payload, self.settings.datadog_oauth_required_scopes)
        payload.setdefault("domain", site_domain)
        payload.setdefault("refresh_token", refresh_token)
        return payload

    def issue_state(self, provider: str) -> str:
        nonce = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
        issued_at = int(time.time())
        signature = self._sign(f"{provider}:{nonce}:{issued_at}")
        return OAuthState(nonce, provider, issued_at, signature).encode()

    def issue_pkce_verifier(self) -> str:
        return base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")

    def pkce_challenge(self, code_verifier: str) -> str:
        digest = sha256(code_verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def verify_state(self, encoded: str, expected_provider: str, *, max_age_seconds: int = 600) -> OAuthState:
        try:
            decoded = base64.urlsafe_b64decode(encoded.encode()).decode()
            provider, nonce, issued_at_raw, signature = decoded.split(":", 3)
            issued_at = int(issued_at_raw)
        except Exception as exc:
            raise ToolExecutionError(ToolErrorKind.PERMANENT, "Invalid OAuth state", retryable=False) from exc
        if provider != expected_provider:
            raise ToolExecutionError(ToolErrorKind.PERMANENT, "OAuth state provider mismatch", retryable=False)
        if time.time() - issued_at > max_age_seconds:
            raise ToolExecutionError(ToolErrorKind.PERMANENT, "OAuth state expired", retryable=False)
        expected = self._sign(f"{provider}:{nonce}:{issued_at}")
        if not hmac.compare_digest(signature, expected):
            raise ToolExecutionError(ToolErrorKind.PERMANENT, "OAuth state signature mismatch", retryable=False)
        return OAuthState(nonce, provider, issued_at, signature)

    def _sign(self, value: str) -> str:
        return hmac.new(self._state_secret.encode(), value.encode(), sha256).hexdigest()

    def _require(self, value: str | None, name: str) -> None:
        if not value:
            raise ToolExecutionError(ToolErrorKind.PERMANENT, f"{name} is required", retryable=False)

    def _resolve_state_secret(self) -> str:
        secret = (
            self.settings.oauth_state_secret
            or self.settings.pagerduty_webhook_secret
            or self.settings.slack_client_secret
            or self.settings.github_client_secret
            or self.settings.datadog_client_secret
        )
        if isinstance(secret, str) and secret.strip():
            return secret.strip()
        if self.settings.runtime_environment != "production":
            return "sentinel-dev-state-secret"
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "SENTINEL_OAUTH_STATE_SECRET or another OAuth/webhook secret is required for OAuth state signing in production",
            retryable=False,
        )


def _post_oauth(provider: str, url: str, **kwargs) -> httpx.Response:
    try:
        return httpx.post(url, timeout=20, **kwargs)
    except httpx.TimeoutException as exc:
        raise ToolExecutionError(
            ToolErrorKind.RETRYABLE,
            f"{provider} OAuth exchange timed out: {exc}",
            retryable=True,
        ) from exc
    except httpx.HTTPError as exc:
        raise ToolExecutionError(
            ToolErrorKind.RETRYABLE,
            f"{provider} OAuth transport error: {exc}",
            retryable=True,
        ) from exc


def _oauth_json(response: httpx.Response, provider: str) -> dict:
    try:
        payload = response.json()
    except ValueError as exc:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} OAuth returned non-JSON response: {redact_sensitive_text(response.text, max_length=300)}",
            retryable=False,
        ) from exc
    if not isinstance(payload, dict):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} OAuth returned unexpected JSON payload",
            retryable=False,
        )
    return payload


def _require_oauth_access_token(payload: dict, provider: str) -> None:
    access_token = payload.get("access_token")
    if isinstance(access_token, str) and access_token.strip():
        return
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} OAuth response missing usable access_token",
        retryable=False,
    )


def _validate_oauth_scopes(provider: str, payload: dict, required_scopes: tuple[str, ...]) -> None:
    required = tuple(scope.strip() for scope in required_scopes if isinstance(scope, str) and scope.strip())
    raw_scope = payload.get("scope")
    if not required or raw_scope is None:
        return
    if not isinstance(raw_scope, str):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} OAuth response field 'scope' must be a string when present",
            retryable=False,
        )
    granted = set(_split_scopes(raw_scope))
    missing = [scope for scope in required if scope not in granted]
    if missing:
        raise ToolExecutionError(
            ToolErrorKind.AUTHORIZATION,
            f"{provider} OAuth token is missing required scope(s): {', '.join(missing)}",
            retryable=False,
        )


def _split_scopes(value: str) -> list[str]:
    return [item.strip() for item in value.replace(",", " ").split() if item.strip()]


def datadog_api_domain(callback_domain: str | None, configured_site: str) -> str:
    try:
        domain = _normalize_datadog_site(callback_domain or configured_site)
        _normalize_datadog_site(configured_site)
    except ValueError as exc:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"Datadog OAuth callback domain is not allowed: {redact_sensitive_text(exc, max_length=300)}",
            retryable=False,
        ) from exc
    if domain in DATADOG_ALLOWED_SITES:
        return domain
    raise ToolExecutionError(
        ToolErrorKind.PERMANENT,
        f"Datadog OAuth callback domain is not allowed: {redact_sensitive_text(domain, max_length=120)}",
        retryable=False,
    )


def datadog_app_base_url(configured_site: str) -> str:
    return f"https://app.{datadog_api_domain(None, configured_site)}"


def verify_pagerduty_signature(
    raw_body: bytes,
    signature_header: str | None,
    secret: str | None,
    previous_secret: str | None = None,
) -> bool:
    secrets = [item for item in (secret, previous_secret) if item]
    if not secrets:
        return True
    if not signature_header:
        return False

    expected_signatures = {
        _pagerduty_v3_signature(raw_body, candidate)
        for candidate in secrets
    }
    for item in signature_header.split(","):
        version, separator, candidate = item.strip().partition("=")
        if not separator or version != "v1":
            continue
        for expected in expected_signatures:
            if hmac.compare_digest(candidate, expected):
                return True
    return False


def pagerduty_signature_header(raw_body: bytes, secret: str) -> str:
    return f"v1={_pagerduty_v3_signature(raw_body, secret)}"


def _pagerduty_v3_signature(raw_body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), b"v1:" + raw_body, sha256).hexdigest()
