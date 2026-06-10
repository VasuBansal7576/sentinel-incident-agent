from __future__ import annotations

from datetime import UTC, datetime, timedelta
from dataclasses import replace
from typing import Any

from sentinel.config import SentinelSettings
from sentinel.errors import ToolErrorKind, ToolExecutionError, redact_sensitive_text
from sentinel.oauth import OAuthManager, datadog_api_domain


OAUTH_STORE_BACKED_CREDENTIALS = frozenset(
    {"DD_API_KEY", "DD_APP_KEY", "GITHUB_TOKEN", "SLACK_BOT_TOKEN"}
)


class OAuthTokenStoreError(RuntimeError):
    def __init__(self, provider: str, exc: Exception):
        self.provider = provider
        super().__init__(
            f"OAuth token store read failed for {provider}: "
            f"{redact_sensitive_text(exc, max_length=500)}"
        )


def resolve_settings(
    settings: SentinelSettings,
    store: Any | None = None,
    *,
    refresh_expired_datadog: bool = False,
) -> SentinelSettings:
    """Overlay persisted OAuth tokens onto env-based settings."""

    use_stored_datadog_oauth = _uses_stored_datadog_oauth(settings)
    datadog_record = _load_oauth_token(store, "datadog") if use_stored_datadog_oauth else None
    if refresh_expired_datadog and use_stored_datadog_oauth:
        datadog_record = _refresh_datadog_oauth_if_needed(settings, store, datadog_record)
    datadog_oauth_token = settings.datadog_oauth_token or _access_token(datadog_record)
    datadog_site = settings.datadog_site
    if datadog_oauth_token and not settings.datadog_oauth_token:
        datadog_site = _stored_datadog_site(datadog_record, settings.datadog_site) or settings.datadog_site
    github_token = settings.github_token or _load_access_token(store, "github")
    slack_bot_token = settings.slack_bot_token or _load_access_token(store, "slack")
    return replace(
        settings,
        datadog_oauth_token=datadog_oauth_token,
        datadog_site=datadog_site,
        github_token=github_token,
        slack_bot_token=slack_bot_token,
    )


def missing_live_credentials(
    settings: SentinelSettings,
    store: Any | None = None,
) -> list[str]:
    missing = resolve_settings(settings, store).missing_live_credentials()
    missing.extend(_stored_datadog_oauth_missing_requirements(settings, store))
    missing.extend(_stored_github_oauth_missing_requirements(settings, store))
    missing.extend(_stored_slack_oauth_missing_requirements(settings, store))
    return _unique(missing)


def token_source_status(settings: SentinelSettings, store: Any | None = None) -> dict[str, str]:
    return {
        "datadog_oauth_token": _datadog_source(settings, store),
        "github_token": _source(settings.github_token, store, "github", settings.github_oauth_scopes),
        "slack_bot_token": _source(settings.slack_bot_token, store, "slack", settings.slack_oauth_scopes),
    }


def missing_live_credentials_without_oauth_store(settings: SentinelSettings) -> list[str]:
    return [
        name
        for name in settings.missing_live_credentials()
        if name not in OAUTH_STORE_BACKED_CREDENTIALS
    ]


def save_slack_oauth_payload(store: Any, payload: dict[str, Any]) -> None:
    access_token = _required_access_token(payload, "Slack")
    _optional_payload_object(payload.get("authed_user"), "Slack", "authed_user")
    scopes = _split_scopes(payload.get("scope"))
    team = _optional_payload_object(payload.get("team"), "Slack", "team") or {}
    store.save_oauth_token(
        provider="slack",
        access_token=access_token,
        subject=team.get("id") or team.get("name"),
        token_type=payload.get("token_type") or "bot",
        scopes=scopes,
        metadata={
            "team": team,
            "bot_user_id": payload.get("bot_user_id"),
            "app_id": payload.get("app_id"),
        },
    )


def save_github_oauth_payload(store: Any, payload: dict[str, Any]) -> None:
    access_token = _required_access_token(payload, "GitHub")
    store.save_oauth_token(
        provider="github",
        access_token=access_token,
        subject=payload.get("scope"),
        token_type=payload.get("token_type") or "bearer",
        scopes=_split_scopes(payload.get("scope")),
        metadata={"raw_scope": payload.get("scope")},
    )


def save_datadog_oauth_payload(store: Any, payload: dict[str, Any]) -> None:
    access_token = _required_access_token(payload, "Datadog")
    issued_at = datetime.now(UTC)
    expires_in = payload.get("expires_in")
    store.save_oauth_token(
        provider="datadog",
        access_token=access_token,
        subject=payload.get("domain") or payload.get("scope"),
        token_type=payload.get("token_type") or "bearer",
        refresh_token=payload.get("refresh_token"),
        scopes=_split_scopes(payload.get("scope")),
        metadata={
            "domain": payload.get("domain"),
            "raw_scope": payload.get("scope"),
            "expires_in": expires_in,
            "issued_at": issued_at.isoformat(),
            "expires_at": _expires_at(issued_at, expires_in),
        },
    )


def _load_access_token(store: Any | None, provider: str) -> str | None:
    return _access_token(_load_oauth_token(store, provider))


def _load_oauth_token(store: Any | None, provider: str) -> dict[str, Any] | None:
    if store is None:
        return None
    try:
        load_token = getattr(store, "load_oauth_token", None)
    except Exception as exc:
        raise OAuthTokenStoreError(provider, exc) from exc
    if not callable(load_token):
        return None
    try:
        token = load_token(provider)
    except Exception as exc:
        raise OAuthTokenStoreError(provider, exc) from exc
    return token if isinstance(token, dict) and token else None


def _access_token(token: dict[str, Any] | None) -> str | None:
    if not token:
        return None
    value = token.get("access_token")
    return value if isinstance(value, str) and value else None


def _stored_datadog_site(token: dict[str, Any] | None, configured_site: str) -> str | None:
    if not token:
        return None
    metadata = token.get("metadata")
    domain = metadata.get("domain") if isinstance(metadata, dict) else None
    if not isinstance(domain, str) or not domain.strip():
        subject = token.get("subject")
        domain = subject if isinstance(subject, str) else None
    if not isinstance(domain, str) or not domain.strip():
        return None
    try:
        return datadog_api_domain(domain, configured_site)
    except ToolExecutionError:
        return None


def _refresh_datadog_oauth_if_needed(
    settings: SentinelSettings,
    store: Any | None,
    token: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if store is None or not token or not _datadog_refresh_due(token):
        return token
    refresh_token = token.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        return token
    domain = _stored_datadog_site(token, settings.datadog_site)
    manager = OAuthManager(replace(settings, datadog_site=domain or settings.datadog_site))
    payload = manager.refresh_datadog_token(refresh_token.strip(), domain=domain)
    save_datadog_oauth_payload(store, payload)
    return _load_oauth_token(store, "datadog")


def _datadog_refresh_due(token: dict[str, Any], *, skew_seconds: int = 300) -> bool:
    expires_at = _datadog_expires_at(token)
    if expires_at is None:
        return False
    return expires_at <= datetime.now(UTC) + timedelta(seconds=skew_seconds)


def _stored_datadog_oauth_missing_requirements(
    settings: SentinelSettings,
    store: Any | None,
) -> list[str]:
    if not _uses_stored_datadog_oauth(settings):
        return []
    token = _load_oauth_token(store, "datadog")
    if not _access_token(token) or not token:
        return []
    if not _datadog_refresh_due(token):
        return [
            f"DD_OAUTH_TOKEN_SCOPE:{scope}"
            for scope in _stored_datadog_oauth_missing_scopes(settings, token)
        ]
    refresh_token = token.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        return ["DD_API_KEY", "DD_APP_KEY"]
    missing = []
    if not settings.datadog_client_id:
        missing.append("DD_CLIENT_ID")
    if not settings.datadog_client_secret:
        missing.append("DD_CLIENT_SECRET")
    if not settings.datadog_redirect_uri:
        missing.append("DD_REDIRECT_URI")
    return missing


def _stored_datadog_oauth_missing_scopes(
    settings: SentinelSettings,
    token: dict[str, Any],
) -> list[str]:
    granted = _stored_oauth_scopes(token)
    if not granted:
        return []
    required = [
        scope.strip()
        for scope in settings.datadog_oauth_required_scopes
        if isinstance(scope, str) and scope.strip()
    ]
    return [scope for scope in required if scope not in granted]


def _stored_github_oauth_missing_requirements(
    settings: SentinelSettings,
    store: Any | None,
) -> list[str]:
    if settings.github_token:
        return []
    token = _load_oauth_token(store, "github")
    if not _access_token(token) or not token:
        return []
    return [
        f"GITHUB_OAUTH_TOKEN_SCOPE:{scope}"
        for scope in _stored_oauth_missing_scopes(token, settings.github_oauth_scopes)
    ]


def _stored_slack_oauth_missing_requirements(
    settings: SentinelSettings,
    store: Any | None,
) -> list[str]:
    if settings.slack_bot_token:
        return []
    token = _load_oauth_token(store, "slack")
    if not _access_token(token) or not token:
        return []
    return [
        f"SLACK_OAUTH_TOKEN_SCOPE:{scope}"
        for scope in _stored_oauth_missing_scopes(token, settings.slack_oauth_scopes)
    ]


def _stored_oauth_missing_scopes(token: dict[str, Any], required_scopes: tuple[str, ...]) -> list[str]:
    granted = _stored_oauth_scopes(token)
    if not granted:
        return []
    required = [
        scope.strip()
        for scope in required_scopes
        if isinstance(scope, str) and scope.strip()
    ]
    return [scope for scope in required if scope not in granted]


def _stored_oauth_scopes(token: dict[str, Any]) -> set[str]:
    raw_scopes = token.get("scopes")
    scopes: list[str] = []
    if isinstance(raw_scopes, list):
        scopes.extend(item.strip() for item in raw_scopes if isinstance(item, str) and item.strip())
    metadata = token.get("metadata")
    if isinstance(metadata, dict):
        raw_scope = metadata.get("raw_scope")
        if isinstance(raw_scope, str) and raw_scope.strip():
            scopes.extend(_split_scopes(raw_scope))
    return set(scopes)


def _datadog_expires_at(token: dict[str, Any]) -> datetime | None:
    metadata = token.get("metadata")
    if isinstance(metadata, dict):
        expires_at = _parse_datetime(metadata.get("expires_at"))
        if expires_at is not None:
            return expires_at
        expires_in = _optional_int(metadata.get("expires_in"))
        updated_at = _parse_datetime(token.get("updated_at"))
        if expires_in is not None and updated_at is not None:
            return updated_at + timedelta(seconds=expires_in)
    return None


def _expires_at(issued_at: datetime, expires_in: Any) -> str | None:
    seconds = _optional_int(expires_in)
    if seconds is None:
        return None
    return (issued_at + timedelta(seconds=seconds)).isoformat()


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _required_access_token(payload: dict[str, Any], provider: str) -> str:
    access_token = payload.get("access_token")
    if isinstance(access_token, str) and access_token.strip():
        return access_token
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} OAuth payload missing usable access_token",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _optional_payload_object(value: Any, provider: str, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} OAuth payload field '{field}' must be an object",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _source(
    env_value: str | None,
    store: Any | None,
    provider: str,
    required_scopes: tuple[str, ...] = (),
) -> str:
    if env_value:
        return "env"
    try:
        token = _load_oauth_token(store, provider)
        if _access_token(token):
            if token and _stored_oauth_missing_scopes(token, required_scopes):
                return "oauth_store_insufficient_scopes"
            return "oauth_store"
    except OAuthTokenStoreError:
        return "oauth_store_unavailable"
    return "missing"


def _datadog_source(settings: SentinelSettings, store: Any | None) -> str:
    if settings.datadog_oauth_token:
        return "env"
    if settings.datadog_api_key and settings.datadog_app_key:
        return "api_keys"
    try:
        token = _load_oauth_token(store, "datadog") if _uses_stored_datadog_oauth(settings) else None
    except OAuthTokenStoreError:
        return "oauth_store_unavailable"
    if _access_token(token):
        if token and _datadog_refresh_due(token):
            return "oauth_store_expired"
        if token and _stored_datadog_oauth_missing_scopes(settings, token):
            return "oauth_store_insufficient_scopes"
        return "oauth_store"
    return "missing"


def _uses_stored_datadog_oauth(settings: SentinelSettings) -> bool:
    return (
        not settings.datadog_oauth_token
        and not (settings.datadog_api_key and settings.datadog_app_key)
    )


def _unique(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _split_scopes(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.replace(",", " ").split() if item.strip()]
