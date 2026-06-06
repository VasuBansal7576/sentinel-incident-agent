from datetime import UTC, datetime, timedelta
from dataclasses import replace

import httpx

from sentinel.config import SentinelSettings
from sentinel.credentials import (
    OAuthTokenStoreError,
    missing_live_credentials,
    resolve_settings,
    save_datadog_oauth_payload,
    save_github_oauth_payload,
    save_slack_oauth_payload,
    token_source_status,
)
from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.store import SQLiteInvestigationStore


def test_resolve_settings_uses_stored_oauth_tokens_for_datadog_slack_and_github():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token=None,
        slack_bot_token=None,
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(provider="datadog", access_token="dd-oauth")
    store.save_oauth_token(provider="github", access_token="gh-oauth")
    store.save_oauth_token(provider="slack", access_token="xoxb-oauth")

    resolved = resolve_settings(settings, store)

    assert resolved.datadog_oauth_token == "dd-oauth"
    assert resolved.github_token == "gh-oauth"
    assert resolved.slack_bot_token == "xoxb-oauth"
    assert missing_live_credentials(settings, store) == []
    assert token_source_status(settings, store) == {
        "datadog_oauth_token": "oauth_store",
        "github_token": "oauth_store",
        "slack_bot_token": "oauth_store",
    }


def test_resolve_settings_raises_when_oauth_store_read_fails():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
    )

    class BrokenStore:
        def load_oauth_token(self, provider):
            raise RuntimeError("store down Authorization: Bearer dd-secret-token")

    try:
        resolve_settings(settings, BrokenStore())
    except OAuthTokenStoreError as exc:
        assert exc.provider == "datadog"
        assert "datadog" in str(exc)
        assert "dd-secret-token" not in str(exc)
        assert "[redacted]" in str(exc)
    else:
        raise AssertionError("expected token store read failure to propagate")


def test_token_source_status_reports_unavailable_oauth_store_read():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token=None,
        slack_bot_token=None,
    )

    class BrokenStore:
        def load_oauth_token(self, provider):
            raise RuntimeError(f"{provider} token store unavailable")

    assert token_source_status(settings, BrokenStore()) == {
        "datadog_oauth_token": "oauth_store_unavailable",
        "github_token": "oauth_store_unavailable",
        "slack_bot_token": "oauth_store_unavailable",
    }


def test_resolve_settings_uses_stored_datadog_oauth_domain_for_api_site():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_site="datadoghq.com",
        datadog_oauth_token=None,
    )
    store = SQLiteInvestigationStore()
    save_datadog_oauth_payload(
        store,
        {
            "access_token": "dd-oauth",
            "refresh_token": "dd-refresh",
            "scope": "logs_read_data",
            "domain": "datadoghq.eu",
            "expires_in": 3600,
        },
    )

    resolved = resolve_settings(settings, store)

    assert resolved.datadog_oauth_token == "dd-oauth"
    assert resolved.datadog_site == "datadoghq.eu"
    assert resolved.datadog_base_url == "https://api.datadoghq.eu"


def test_datadog_base_url_normalizes_full_site_urls_and_api_hosts():
    base = SentinelSettings.from_env()

    cases = [
        ("datadoghq.com", "https://api.datadoghq.com"),
        ("api.datadoghq.eu", "https://api.datadoghq.eu"),
        ("app.us3.datadoghq.com", "https://api.us3.datadoghq.com"),
        ("https://api.us5.datadoghq.com", "https://api.us5.datadoghq.com"),
        ("https://app.datadoghq.eu/account/login", "https://api.datadoghq.eu"),
    ]

    for site, expected in cases:
        settings = replace(base, datadog_site=site)

        assert settings.datadog_base_url == expected


def test_from_env_normalizes_and_allows_known_datadog_sites(monkeypatch):
    monkeypatch.setenv("DD_SITE", " https://app.datadoghq.eu/account/login ")

    settings = SentinelSettings.from_env()

    assert settings.datadog_site == "datadoghq.eu"
    assert settings.datadog_base_url == "https://api.datadoghq.eu"


def test_from_env_rejects_unknown_datadog_site_before_client_build(monkeypatch):
    monkeypatch.setenv("DD_SITE", "https://evil.example")

    try:
        SentinelSettings.from_env()
    except ValueError as exc:
        assert "DD_SITE must be one of" in str(exc)
        assert "evil.example" not in str(exc)
    else:
        raise AssertionError("expected DD_SITE allowlist validation to fail")


def test_from_env_defaults_datadog_oauth_required_scopes(monkeypatch):
    monkeypatch.delenv("DD_OAUTH_REQUIRED_SCOPES", raising=False)

    settings = SentinelSettings.from_env()

    assert settings.datadog_oauth_required_scopes == (
        "logs_read_data",
        "metrics_read",
        "apm_read",
    )


def test_from_env_parses_datadog_oauth_required_scopes(monkeypatch):
    monkeypatch.setenv(
        "DD_OAUTH_REQUIRED_SCOPES",
        "metrics_read, logs_read_data apm_read metrics_read",
    )

    settings = SentinelSettings.from_env()

    assert settings.datadog_oauth_required_scopes == (
        "metrics_read",
        "logs_read_data",
        "apm_read",
    )


def test_from_env_defaults_slack_oauth_scopes(monkeypatch):
    monkeypatch.delenv("SLACK_OAUTH_SCOPES", raising=False)

    settings = SentinelSettings.from_env()

    assert settings.slack_oauth_scopes == (
        "chat:write",
        "channels:read",
        "channels:manage",
        "groups:read",
        "groups:write",
    )


def test_from_env_parses_slack_oauth_scopes(monkeypatch):
    monkeypatch.setenv("SLACK_OAUTH_SCOPES", "chat:write, channels:read groups:read chat:write")

    settings = SentinelSettings.from_env()

    assert settings.slack_oauth_scopes == ("chat:write", "channels:read", "groups:read")


def test_from_env_defaults_github_oauth_scopes(monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_SCOPES", raising=False)

    settings = SentinelSettings.from_env()

    assert settings.github_oauth_scopes == ("repo", "read:org")


def test_from_env_parses_github_oauth_scopes(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_SCOPES", "repo, read:org repo")

    settings = SentinelSettings.from_env()

    assert settings.github_oauth_scopes == ("repo", "read:org")


def test_resolve_settings_keeps_env_datadog_oauth_site_over_stored_token_domain():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_site="us3.datadoghq.com",
        datadog_oauth_token="env-dd-oauth",
    )
    store = SQLiteInvestigationStore()
    save_datadog_oauth_payload(
        store,
        {
            "access_token": "stored-dd-oauth",
            "scope": "logs_read_data",
            "domain": "datadoghq.eu",
        },
    )

    resolved = resolve_settings(settings, store)

    assert resolved.datadog_oauth_token == "env-dd-oauth"
    assert resolved.datadog_site == "us3.datadoghq.com"
    assert resolved.datadog_base_url == "https://api.us3.datadoghq.com"


def test_resolve_settings_prefers_datadog_api_keys_over_stored_oauth_token(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_site="us5.datadoghq.com",
        datadog_oauth_token=None,
    )
    store = SQLiteInvestigationStore()
    save_datadog_oauth_payload(
        store,
        {
            "access_token": "stored-dd-oauth",
            "refresh_token": "stored-dd-refresh",
            "scope": "logs_read_data",
            "domain": "datadoghq.eu",
            "expires_in": 1,
        },
    )
    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected refresh")),
    )

    resolved = resolve_settings(settings, store, refresh_expired_datadog=True)

    assert resolved.datadog_oauth_token is None
    assert resolved.datadog_api_key == "dd-api"
    assert resolved.datadog_app_key == "dd-app"
    assert resolved.datadog_site == "us5.datadoghq.com"
    assert resolved.datadog_base_url == "https://api.us5.datadoghq.com"
    assert token_source_status(settings, store)["datadog_oauth_token"] == "api_keys"


def test_resolve_settings_refreshes_expired_stored_datadog_oauth_token(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_site="datadoghq.com",
        datadog_oauth_token=None,
        datadog_client_id="datadog-client",
        datadog_client_secret="datadog-secret",
        datadog_redirect_uri="http://localhost:8000/oauth/datadog/callback",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh",
        token_type="bearer",
        scopes=["logs_read_data"],
        metadata={
            "domain": "datadoghq.eu",
            "expires_in": 3600,
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )
    captured = {}

    def post(url, **kwargs):
        captured["url"] = url
        captured["data"] = kwargs["data"]
        return httpx.Response(
            200,
            json={
                "access_token": "new-dd-oauth",
                "refresh_token": "new-dd-refresh",
                "token_type": "bearer",
                "scope": "logs_read_data metrics_read apm_read",
                "expires_in": 3600,
            },
        )

    monkeypatch.setattr("sentinel.oauth.httpx.post", post)

    resolved = resolve_settings(settings, store, refresh_expired_datadog=True)

    assert captured["url"] == "https://api.datadoghq.eu/oauth2/v1/token"
    assert captured["data"]["grant_type"] == "refresh_token"
    assert captured["data"]["refresh_token"] == "old-dd-refresh"
    assert captured["data"]["client_id"] == "datadog-client"
    assert captured["data"]["client_secret"] == "datadog-secret"
    assert resolved.datadog_oauth_token == "new-dd-oauth"
    assert resolved.datadog_site == "datadoghq.eu"
    token = store.load_oauth_token("datadog")
    assert token["access_token"] == "new-dd-oauth"
    assert token["refresh_token"] == "new-dd-refresh"
    assert token["metadata"]["domain"] == "datadoghq.eu"
    assert datetime.fromisoformat(token["metadata"]["expires_at"]) > datetime.now(UTC)


def test_resolve_settings_does_not_refresh_unexpired_datadog_oauth_token(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id="datadog-client",
        datadog_client_secret="datadog-secret",
        datadog_redirect_uri="http://localhost:8000/oauth/datadog/callback",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="dd-oauth",
        refresh_token="dd-refresh",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    )
    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected refresh")),
    )

    resolved = resolve_settings(settings, store, refresh_expired_datadog=True)

    assert resolved.datadog_oauth_token == "dd-oauth"
    assert resolved.datadog_site == "datadoghq.eu"


def test_missing_live_credentials_requires_refresh_config_for_expired_stored_datadog_oauth():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id=None,
        datadog_client_secret=None,
        datadog_redirect_uri=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )

    assert missing_live_credentials(settings, store) == [
        "DD_CLIENT_ID",
        "DD_CLIENT_SECRET",
        "DD_REDIRECT_URI",
    ]
    assert token_source_status(settings, store)["datadog_oauth_token"] == "oauth_store_expired"


def test_missing_live_credentials_rejects_explicitly_insufficient_stored_datadog_oauth_scopes():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="dd-oauth",
        scopes=["logs_read_data"],
    )

    assert missing_live_credentials(settings, store) == [
        "DD_OAUTH_TOKEN_SCOPE:metrics_read",
        "DD_OAUTH_TOKEN_SCOPE:apm_read",
    ]
    assert token_source_status(settings, store)["datadog_oauth_token"] == "oauth_store_insufficient_scopes"


def test_missing_live_credentials_rejects_explicitly_insufficient_stored_github_oauth_scopes():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        github_token=None,
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="github",
        access_token="gh-oauth",
        scopes=["read:org"],
    )

    assert missing_live_credentials(settings, store) == ["GITHUB_OAUTH_TOKEN_SCOPE:repo"]
    assert token_source_status(settings, store)["github_token"] == "oauth_store_insufficient_scopes"


def test_missing_live_credentials_rejects_explicitly_insufficient_stored_slack_oauth_scopes():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token=None,
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="slack",
        access_token="xoxb-oauth",
        scopes=["chat:write", "channels:read"],
    )

    assert missing_live_credentials(settings, store) == [
        "SLACK_OAUTH_TOKEN_SCOPE:channels:manage",
        "SLACK_OAUTH_TOKEN_SCOPE:groups:read",
        "SLACK_OAUTH_TOKEN_SCOPE:groups:write",
    ]
    assert token_source_status(settings, store)["slack_bot_token"] == "oauth_store_insufficient_scopes"


def test_missing_live_credentials_requires_api_keys_when_expired_stored_datadog_oauth_cannot_refresh():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )

    assert missing_live_credentials(settings, store) == ["DD_API_KEY", "DD_APP_KEY"]
    assert token_source_status(settings, store)["datadog_oauth_token"] == "oauth_store_expired"


def test_slack_oauth_payload_requires_usable_access_token_before_persistence():
    store = SQLiteInvestigationStore()

    try:
        save_slack_oauth_payload(store, {"team": {"id": "T1"}})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "access_token" in str(exc)
    else:
        raise AssertionError("expected malformed Slack OAuth payload to fail")

    assert store.load_oauth_token("slack") is None


def test_slack_oauth_payload_rejects_malformed_team_object_before_persistence():
    store = SQLiteInvestigationStore()

    try:
        save_slack_oauth_payload(store, {"access_token": "xoxb-oauth", "team": "T1"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "team" in str(exc)
    else:
        raise AssertionError("expected malformed Slack team payload to fail")

    assert store.load_oauth_token("slack") is None


def test_slack_oauth_payload_does_not_treat_user_scope_as_bot_token_scope():
    store = SQLiteInvestigationStore()

    save_slack_oauth_payload(
        store,
        {
            "access_token": "xoxb-oauth",
            "authed_user": {"id": "U1", "scope": "users:read"},
            "team": {"id": "T1", "name": "Sentinel"},
        },
    )

    token = store.load_oauth_token("slack")
    assert token["access_token"] == "xoxb-oauth"
    assert token["scopes"] == []


def test_slack_oauth_payload_persists_top_level_bot_scope_metadata():
    store = SQLiteInvestigationStore()

    save_slack_oauth_payload(
        store,
        {
            "access_token": "xoxb-oauth",
            "scope": "chat:write,channels:read",
            "authed_user": {"id": "U1", "scope": "users:read"},
            "team": {"id": "T1", "name": "Sentinel"},
        },
    )

    token = store.load_oauth_token("slack")
    assert token["scopes"] == ["chat:write", "channels:read"]


def test_github_oauth_payload_requires_usable_access_token_before_persistence():
    store = SQLiteInvestigationStore()

    try:
        save_github_oauth_payload(store, {"access_token": ""})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "access_token" in str(exc)
    else:
        raise AssertionError("expected malformed GitHub OAuth payload to fail")

    assert store.load_oauth_token("github") is None


def test_datadog_oauth_payload_requires_usable_access_token_before_persistence():
    store = SQLiteInvestigationStore()

    try:
        save_datadog_oauth_payload(store, {"scope": "apm_read"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "access_token" in str(exc)
    else:
        raise AssertionError("expected malformed Datadog OAuth payload to fail")

    assert store.load_oauth_token("datadog") is None


def test_datadog_oauth_payload_persists_bearer_token_metadata():
    store = SQLiteInvestigationStore()

    save_datadog_oauth_payload(
        store,
        {
            "access_token": " dd-oauth ",
            "refresh_token": "dd-refresh",
            "scope": "logs_read_data metrics_read apm_read",
            "domain": "datadoghq.eu",
            "expires_in": 3600,
        },
    )

    token = store.load_oauth_token("datadog")
    assert token["access_token"] == "dd-oauth"
    assert token["refresh_token"] == "dd-refresh"
    assert token["subject"] == "datadoghq.eu"
    assert token["token_type"] == "bearer"
    assert token["scopes"] == ["logs_read_data", "metrics_read", "apm_read"]
    assert token["metadata"]["domain"] == "datadoghq.eu"
    assert token["metadata"]["expires_in"] == 3600


def test_missing_live_credentials_accepts_datadog_oauth_token_instead_of_api_app_keys():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token="dd-oauth",
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == []


def test_missing_live_credentials_does_not_require_pagerduty_requester_for_readiness():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        pagerduty_requester_email=None,
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == []


def test_missing_live_credentials_requires_api_token_in_production():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token=None,
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == ["SENTINEL_API_TOKEN"]


def test_missing_live_credentials_requires_database_and_redis_urls_in_production():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        environment="production",
        database_url=None,
        redis_url=None,
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == [
        "DATABASE_URL",
        "REDIS_URL",
    ]


def test_missing_live_credentials_requires_datadog_api_and_app_keys_without_oauth():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
    )

    missing = missing_live_credentials(settings, SQLiteInvestigationStore())

    assert "DD_API_KEY" in missing
    assert "DD_APP_KEY" in missing


def test_missing_live_credentials_rejects_nonexistent_kubeconfig_path():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig="/tmp/sentinel-missing-kubeconfig",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == ["KUBECONFIG"]


def test_missing_live_credentials_requires_pagerduty_webhook_secret_in_production():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret=None,
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == [
        "PAGERDUTY_WEBHOOK_SECRET"
    ]


def test_missing_live_credentials_does_not_accept_only_previous_webhook_secret_in_production():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret=None,
        pagerduty_webhook_previous_secret="pd-previous",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == [
        "PAGERDUTY_WEBHOOK_SECRET"
    ]


def test_missing_live_credentials_allows_unsigned_local_webhooks_outside_production():
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        datadog_oauth_token=None,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        pagerduty_webhook_secret=None,
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        environment="development",
    )

    assert missing_live_credentials(settings, SQLiteInvestigationStore()) == []
