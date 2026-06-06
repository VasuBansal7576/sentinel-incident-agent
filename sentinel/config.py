from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DATADOG_ALLOWED_SITES = frozenset(
    {
        "datadoghq.com",
        "us3.datadoghq.com",
        "us5.datadoghq.com",
        "datadoghq.eu",
        "ap1.datadoghq.com",
        "ap2.datadoghq.com",
        "ddog-gov.com",
    }
)

DATADOG_LIVE_READ_OAUTH_SCOPES = (
    "logs_read_data",
    "metrics_read",
    "apm_read",
)

SLACK_LIVE_OAUTH_SCOPES = (
    "chat:write",
    "channels:read",
    "channels:manage",
    "groups:read",
    "groups:write",
)

GITHUB_LIVE_OAUTH_SCOPES = (
    "repo",
    "read:org",
)


@dataclass(frozen=True)
class SentinelSettings:
    datadog_api_key: str | None
    datadog_app_key: str | None
    datadog_site: str
    datadog_oauth_token: str | None
    prometheus_url: str | None
    loki_url: str | None
    datadog_client_id: str | None
    datadog_client_secret: str | None
    datadog_redirect_uri: str | None
    datadog_oauth_required_scopes: tuple[str, ...]
    github_token: str | None
    github_owner: str | None
    github_repo: str | None
    github_write_enabled: bool
    pagerduty_api_key: str | None
    pagerduty_requester_email: str | None
    slack_bot_token: str | None
    slack_channel_id: str | None
    discord_webhook_url: str | None
    slack_client_id: str | None
    slack_client_secret: str | None
    slack_redirect_uri: str | None
    slack_oauth_scopes: tuple[str, ...]
    github_client_id: str | None
    github_client_secret: str | None
    github_redirect_uri: str | None
    github_oauth_scopes: tuple[str, ...]
    oauth_state_secret: str | None
    api_token: str | None
    pagerduty_webhook_secret: str | None
    pagerduty_webhook_previous_secret: str | None
    pagerduty_webhook_subscription_id: str | None
    kubeconfig: str | None
    kubernetes_namespace: str
    kubectl_timeout_seconds: float
    live_max_pages: int
    database_url: str | None
    redis_url: str | None
    default_service: str
    approver_id: str | None
    service_aliases: dict[str, str]
    environment: str

    @classmethod
    def from_env(cls) -> "SentinelSettings":
        return cls(
            datadog_api_key=_env_optional_text("DD_API_KEY"),
            datadog_app_key=_env_optional_text("DD_APP_KEY") or _env_optional_text("DATADOG_APP_KEY"),
            datadog_site=_env_datadog_site("DD_SITE", "datadoghq.com"),
            datadog_oauth_token=_env_optional_text("DD_OAUTH_TOKEN"),
            prometheus_url=_env_optional_text("PROMETHEUS_URL"),
            loki_url=_env_optional_text("LOKI_URL"),
            datadog_client_id=_env_optional_text("DD_CLIENT_ID") or _env_optional_text("DATADOG_CLIENT_ID"),
            datadog_client_secret=_env_optional_text("DD_CLIENT_SECRET") or _env_optional_text("DATADOG_CLIENT_SECRET"),
            datadog_redirect_uri=_env_optional_text("DD_REDIRECT_URI") or _env_optional_text("DATADOG_REDIRECT_URI"),
            datadog_oauth_required_scopes=_env_scope_tuple(
                "DD_OAUTH_REQUIRED_SCOPES",
                DATADOG_LIVE_READ_OAUTH_SCOPES,
            ),
            github_token=_env_optional_text("GITHUB_TOKEN"),
            github_owner=_env_optional_text("GITHUB_OWNER"),
            github_repo=_env_optional_text("GITHUB_REPO"),
            github_write_enabled=_env_bool("SENTINEL_GITHUB_WRITE_ENABLED", False),
            pagerduty_api_key=_env_optional_text("PAGERDUTY_API_KEY"),
            pagerduty_requester_email=_env_optional_text("PAGERDUTY_REQUESTER_EMAIL"),
            slack_bot_token=_env_optional_text("SLACK_BOT_TOKEN"),
            slack_channel_id=_env_optional_text("SLACK_CHANNEL_ID"),
            discord_webhook_url=_env_optional_text("DISCORD_WEBHOOK_URL"),
            slack_client_id=_env_optional_text("SLACK_CLIENT_ID"),
            slack_client_secret=_env_optional_text("SLACK_CLIENT_SECRET"),
            slack_redirect_uri=_env_optional_text("SLACK_REDIRECT_URI"),
            slack_oauth_scopes=_env_scope_tuple("SLACK_OAUTH_SCOPES", SLACK_LIVE_OAUTH_SCOPES),
            github_client_id=_env_optional_text("GITHUB_CLIENT_ID"),
            github_client_secret=_env_optional_text("GITHUB_CLIENT_SECRET"),
            github_redirect_uri=_env_optional_text("GITHUB_REDIRECT_URI"),
            github_oauth_scopes=_env_scope_tuple("GITHUB_OAUTH_SCOPES", GITHUB_LIVE_OAUTH_SCOPES),
            oauth_state_secret=_env_optional_text("SENTINEL_OAUTH_STATE_SECRET"),
            api_token=_env_optional_text("SENTINEL_API_TOKEN"),
            pagerduty_webhook_secret=_env_optional_text("PAGERDUTY_WEBHOOK_SECRET"),
            pagerduty_webhook_previous_secret=_env_optional_text("PAGERDUTY_WEBHOOK_PREVIOUS_SECRET"),
            pagerduty_webhook_subscription_id=_env_optional_text("PAGERDUTY_WEBHOOK_SUBSCRIPTION_ID"),
            kubeconfig=_env_optional_text("KUBECONFIG"),
            kubernetes_namespace=_env_text("KUBERNETES_NAMESPACE", "default"),
            kubectl_timeout_seconds=_env_positive_float("SENTINEL_KUBECTL_TIMEOUT_SECONDS", 20.0),
            live_max_pages=_env_positive_int("SENTINEL_LIVE_MAX_PAGES", 25),
            database_url=_env_optional_text("DATABASE_URL"),
            redis_url=_env_optional_text("REDIS_URL"),
            default_service=_env_text("SENTINEL_DEFAULT_SERVICE", "payment-service"),
            approver_id=_env_optional_text("SENTINEL_APPROVER_ID"),
            service_aliases=_service_aliases_from_env(_env_optional_text("SENTINEL_SERVICE_ALIASES")),
            environment=_env_text("SENTINEL_ENV", "production"),
        )

    def missing_live_credentials(self) -> list[str]:
        required = {
            "GITHUB_TOKEN": self.github_token,
            "GITHUB_OWNER": self.github_owner,
            "GITHUB_REPO": self.github_repo,
            "KUBECONFIG": self.existing_kubeconfig,
        }
        missing = []
        free_observability_configured = bool(self.prometheus_url and self.loki_url)
        datadog_configured = bool(
            self.datadog_oauth_token or (self.datadog_api_key and self.datadog_app_key)
        )
        if not free_observability_configured and not self.datadog_oauth_token:
            if not self.datadog_api_key:
                missing.append("DD_API_KEY")
            if not self.datadog_app_key:
                missing.append("DD_APP_KEY")
        if not datadog_configured:
            if not self.prometheus_url:
                missing.append("PROMETHEUS_URL")
            if not self.loki_url:
                missing.append("LOKI_URL")
        if not self.pagerduty_api_key and not self.approver_id:
            missing.append("SENTINEL_APPROVER_ID")
        if self.pagerduty_api_key:
            required["PAGERDUTY_API_KEY"] = self.pagerduty_api_key
        if not self.slack_bot_token and not self.discord_webhook_url:
            missing.append("SLACK_BOT_TOKEN")
            missing.append("DISCORD_WEBHOOK_URL")
        if self.slack_bot_token and not self.slack_channel_id:
            missing.append("SLACK_CHANNEL_ID")
        if self.api_auth_required and not self.api_token:
            missing.append("SENTINEL_API_TOKEN")
        if self.pagerduty_api_key and self.webhook_signature_required and not self.pagerduty_webhook_secret:
            missing.append("PAGERDUTY_WEBHOOK_SECRET")
        if self.production_infrastructure_required and not self.database_url:
            missing.append("DATABASE_URL")
        if self.production_infrastructure_required and not self.redis_url:
            missing.append("REDIS_URL")
        missing.extend(name for name, value in required.items() if not value)
        return missing

    @property
    def runtime_environment(self) -> str:
        return self.environment.strip().lower() or "production"

    @property
    def api_auth_required(self) -> bool:
        return self.runtime_environment == "production"

    @property
    def webhook_signature_required(self) -> bool:
        return self.runtime_environment == "production"

    @property
    def production_infrastructure_required(self) -> bool:
        return self.runtime_environment == "production"

    @property
    def datadog_base_url(self) -> str:
        return f"https://api.{_normalize_datadog_site(self.datadog_site)}"

    def resolve_service_alias(self, label: str) -> str:
        label = label.strip()
        for alias, target in self.service_aliases.items():
            if alias == label or alias.lower() == label.lower():
                return target
        return label

    @property
    def default_kubeconfig(self) -> str | None:
        path = Path.home() / ".kube" / "config"
        return str(path) if path.exists() else None

    @property
    def effective_kubeconfig(self) -> str | None:
        return self.kubeconfig or self.default_kubeconfig

    @property
    def existing_kubeconfig(self) -> str | None:
        path = self.effective_kubeconfig
        if not path:
            return None
        expanded = Path(path).expanduser()
        return str(expanded) if expanded.is_file() else None


def _service_aliases_from_env(value: str | None) -> dict[str, str]:
    if not value or not value.strip():
        return {}
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("SENTINEL_SERVICE_ALIASES must be a JSON object") from exc
    if not isinstance(raw, dict):
        raise ValueError("SENTINEL_SERVICE_ALIASES must be a JSON object")
    aliases: dict[str, str] = {}
    for key, item in raw.items():
        alias = _required_alias_text(key, "SENTINEL_SERVICE_ALIASES key")
        target = _required_alias_text(item, f"SENTINEL_SERVICE_ALIASES[{alias!r}]")
        aliases[alias] = target
    return aliases


def _normalize_datadog_site(value: str) -> str:
    raw = value.strip().lower()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    domain = parsed.netloc or parsed.path
    domain = domain.split("/")[0].split(":")[0]
    for prefix in ("api.", "app."):
        if domain.startswith(prefix):
            domain = domain.removeprefix(prefix)
            break
    if domain not in DATADOG_ALLOWED_SITES:
        raise ValueError(f"DD_SITE must be one of: {', '.join(sorted(DATADOG_ALLOWED_SITES))}")
    return domain


def _env_positive_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def _env_optional_text(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _env_text(name: str, default: str) -> str:
    return _env_optional_text(name) or default


def _env_datadog_site(name: str, default: str) -> str:
    return _normalize_datadog_site(_env_text(name, default))


def _env_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean: true/false")


def _env_scope_tuple(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _env_optional_text(name)
    if raw is None:
        return default
    scopes: list[str] = []
    seen = set()
    for item in raw.replace(",", " ").split():
        scope = item.strip()
        if scope and scope not in seen:
            scopes.append(scope)
            seen.add(scope)
    return tuple(scopes) or default


def _required_alias_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()
