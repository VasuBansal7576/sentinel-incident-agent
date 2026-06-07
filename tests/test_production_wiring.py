import json
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from sentinel.config import SentinelSettings
from sentinel.connectivity import ConnectivityCheck, ConnectivityReport
from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.live_clients import LiveApiClient, LiveProviderClients
from sentinel.models import Evidence, ApprovalRequest, InvestigationState, InvestigationStatus, Recommendation, StateName, ToolCallRecord
from sentinel.oauth import OAuthManager, pagerduty_signature_header
from sentinel.rate_limiters import SharedRateLimiter
from sentinel.real_tools import LIVE_TOOL_HANDLERS, LiveToolFactory, RealTool
from sentinel.store import SQLiteInvestigationStore
from sentinel.tools import build_tool_contracts
from sentinel.webapp import (
    create_app,
    GenericWebhookRequest,
    _build_live_orchestrator,
    _create_received_investigation,
    _extract_generic_incident_id,
    _extract_generic_services,
    _extract_incident_id,
    _extract_services,
    _redis_reachable,
    _run_live_investigation,
    _run_live_investigation_safely,
    _webhook_idempotency_key,
)


def test_live_tool_factory_binds_all_52_contracts_to_real_handlers():
    contracts = build_tool_contracts()
    assert len(contracts) == 52
    assert set(LIVE_TOOL_HANDLERS) == {contract.name for contract in contracts}

    settings = SentinelSettings.from_env()
    clients = LiveProviderClients.from_settings(settings)
    try:
        registry = LiveToolFactory(clients).build_registry()
    finally:
        clients.close()

    assert len(registry) == 52
    assert all(isinstance(tool, RealTool) for tool in registry.tools.values())


def test_live_tool_factory_fails_fast_when_contract_lacks_live_handler(monkeypatch):
    monkeypatch.delitem(LIVE_TOOL_HANDLERS, "observe.fetch_service_logs")

    try:
        LiveToolFactory(SimpleNamespace()).build_registry()
    except RuntimeError as exc:
        assert "missing live handler(s): observe.fetch_service_logs" in str(exc)
    else:
        raise AssertionError("expected missing live handler to fail registry construction")


def test_live_tool_factory_fails_fast_when_live_handler_has_no_contract(monkeypatch):
    monkeypatch.setitem(LIVE_TOOL_HANDLERS, "observe.uncontracted_live_probe", lambda _router, _payload: {})

    try:
        LiveToolFactory(SimpleNamespace()).build_registry()
    except RuntimeError as exc:
        assert "unregistered live handler(s): observe.uncontracted_live_probe" in str(exc)
    else:
        raise AssertionError("expected extra live handler to fail registry construction")


def test_webapp_health_reports_missing_credentials_without_hardcoded_tokens():
    app = create_app(SentinelSettings.from_env())

    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert "missing_live_credentials" in response.json()


def test_webapp_shutdown_closes_investigation_store(monkeypatch):
    class ClosableStore:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    store = ClosableStore()
    monkeypatch.setattr("sentinel.webapp.build_store", lambda database_url: store)
    app = create_app(SentinelSettings.from_env())

    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert store.closed is False

    assert store.closed is True


def test_webapp_ready_reports_missing_live_credentials():
    response = TestClient(create_app(SentinelSettings.from_env())).get("/ready")

    assert response.status_code == 503
    assert response.json()["ready"] is False
    assert "DD_API_KEY" in response.json()["missing_live_credentials"]


def test_webapp_metrics_endpoint_exposes_prometheus_demo_series():
    app = create_app(_stub_live_settings(default_service="checkout-service"))

    response = TestClient(app).get("/metrics")

    assert response.status_code == 200
    body = response.text
    assert 'sentinel_demo_info{service="checkout-service"} 1' in body
    assert 'http_requests_total{service="checkout-service",status="500"}' in body
    assert 'container_cpu_usage_seconds_total{pod="checkout-service-demo",container="app"}' in body
    assert 'container_memory_working_set_bytes{pod="checkout-service-demo",container="app"}' in body


def test_webapp_ready_reports_invalid_env_configuration(monkeypatch):
    monkeypatch.setenv("SENTINEL_LIVE_MAX_PAGES", "0")

    app = create_app()
    client = TestClient(app)
    ready = client.get("/ready")
    health = client.get("/health")
    unavailable = client.get("/live/connectivity")

    assert ready.status_code == 503
    assert ready.json()["ready"] is False
    assert ready.json()["status"] == "configuration_error"
    assert ready.json()["missing_live_credentials"] == []
    assert "SENTINEL_LIVE_MAX_PAGES" in ready.json()["config_error"]
    assert health.status_code == 200
    assert health.json()["status"] == "configuration_error"
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["message"] == "SENTINEL configuration is invalid"


def test_webapp_live_connectivity_endpoint_reports_missing_without_network_in_development():
    settings = replace(SentinelSettings.from_env(), environment="development")

    response = TestClient(create_app(settings)).get("/live/connectivity")

    assert response.status_code == 200
    assert response.json()["ready"] is False
    checks = response.json()["checks"]
    assert [check["name"] for check in checks] == ["sentinel.state_store", "sentinel.redis"]
    assert all(check["provider"] == "sentinel" for check in checks)
    assert "DD_API_KEY" in response.json()["missing_live_credentials"]


def test_operator_endpoint_requires_bearer_token_in_production():
    app = create_app(_stub_live_settings(api_token="sentinel-api-token"))
    state = _waiting_approval_state()
    app.state.store.save_state(state)
    client = TestClient(app)

    missing = client.get(f"/investigations/{state.id}")
    wrong = client.get(
        f"/investigations/{state.id}",
        headers={"authorization": "Bearer wrong-token"},
    )
    valid = client.get(f"/investigations/{state.id}", headers=_api_headers())

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert valid.status_code == 200
    assert valid.json()["receiver_process"]["started_at"]
    assert valid.json()["receiver_process"]["uptime_seconds"] >= 0


def test_operator_endpoint_allows_development_without_configured_token():
    app = create_app(_stub_live_settings(api_token=None, environment="development"))
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}")

    assert response.status_code == 200
    assert response.json()["investigation_id"] == state.id


def test_oauth_install_endpoints_require_operator_token_before_issuing_state():
    app = create_app(
        _stub_live_settings(
            slack_client_id="slack-client",
            slack_client_secret="slack-secret",
            slack_redirect_uri="http://localhost/slack",
            github_client_id="github-client",
            github_client_secret="github-secret",
            github_redirect_uri="http://localhost/github",
            datadog_client_id="datadog-client",
            datadog_client_secret="datadog-secret",
            datadog_redirect_uri="http://localhost/datadog",
        )
    )
    client = TestClient(app)

    missing_slack = client.get("/oauth/slack/install", follow_redirects=False)
    missing_github = client.get("/oauth/github/install", follow_redirects=False)
    missing_datadog = client.get("/oauth/datadog/install", follow_redirects=False)
    valid_slack = client.get("/oauth/slack/install", headers=_api_headers(), follow_redirects=False)
    valid_github = client.get("/oauth/github/install", headers=_api_headers(), follow_redirects=False)
    valid_datadog = client.get("/oauth/datadog/install", headers=_api_headers(), follow_redirects=False)

    assert missing_slack.status_code == 401
    assert missing_github.status_code == 401
    assert missing_datadog.status_code == 401
    assert valid_slack.status_code == 307
    assert valid_github.status_code == 307
    assert valid_datadog.status_code == 307
    state = _redirect_state(valid_slack)
    github_state = _redirect_state(valid_github)
    datadog_state = _redirect_state(valid_datadog)
    assert app.state.store.lookup_idempotency_key(f"oauth:slack:{state}:issued") == "slack"
    assert app.state.store.lookup_idempotency_key(f"oauth:github:{github_state}:issued") == "github"
    assert app.state.store.lookup_idempotency_key(f"oauth:datadog:{datadog_state}:issued") == "datadog"
    assert app.state.store.lookup_idempotency_key(f"oauth:datadog:{datadog_state}:pkce_verifier")
    assert app.state.store.count_rows("idempotency_keys") == 4


def test_oauth_install_rejects_missing_provider_config_before_issuing_state():
    cases = [
        (
            "/oauth/slack/install",
            {
                "slack_client_id": "slack-client",
                "slack_client_secret": None,
                "slack_redirect_uri": "http://localhost/slack",
            },
            "SLACK_CLIENT_SECRET",
        ),
        (
            "/oauth/github/install",
            {
                "github_client_id": "github-client",
                "github_client_secret": "github-secret",
                "github_redirect_uri": None,
            },
            "GITHUB_REDIRECT_URI",
        ),
        (
            "/oauth/datadog/install",
            {
                "datadog_client_id": None,
                "datadog_client_secret": "datadog-secret",
                "datadog_redirect_uri": "http://localhost/datadog",
            },
            "DD_CLIENT_ID",
        ),
    ]

    for path, overrides, missing_name in cases:
        app = create_app(_stub_live_settings(**overrides))

        response = TestClient(app).get(path, headers=_api_headers(), follow_redirects=False)

        assert response.status_code == 503
        assert missing_name in response.json()["detail"]
        assert app.state.store.count_rows("idempotency_keys") == 0


def test_oauth_install_rejects_store_construction_failure_with_503(monkeypatch):
    def fail_store(database_url):
        raise RuntimeError(
            f"could not connect to {database_url} api_key=dd-secret Authorization: Bearer ghp-secret-token"
        )

    monkeypatch.setattr("sentinel.webapp.build_store", fail_store)
    settings = _stub_live_settings(
        database_url="postgresql://sentinel:db-secret@db/sentinel",
        slack_client_id="slack-client",
        slack_client_secret="slack-secret",
        slack_redirect_uri="http://localhost/slack",
    )

    response = TestClient(create_app(settings)).get(
        "/oauth/slack/install",
        headers=_api_headers(),
        follow_redirects=False,
    )

    assert response.status_code == 503
    rendered = json.dumps(response.json())
    assert "Investigation Store unavailable" in response.json()["detail"]
    assert "db-secret" not in rendered
    assert "dd-secret" not in rendered
    assert "ghp-secret-token" not in rendered


def test_oauth_callback_rejects_state_that_was_not_issued_by_receiver(monkeypatch):
    exchanged = []

    def no_network_exchange(self, code, state):
        exchanged.append((code, state))
        return {"access_token": "xoxb-oauth", "team": {"id": "T1"}}

    monkeypatch.setattr("sentinel.oauth.OAuthManager.exchange_slack_code", no_network_exchange)
    settings = _stub_live_settings(
        slack_client_id="slack-client",
        slack_client_secret="slack-secret",
        slack_redirect_uri="http://localhost/slack",
    )
    state = OAuthManager(settings).issue_state("slack")

    response = TestClient(create_app(settings)).get(
        "/oauth/slack/callback",
        params={"code": "oauth-code", "state": state},
    )

    assert response.status_code == 400
    assert "not issued" in response.json()["detail"]
    assert exchanged == []


def test_oauth_callback_consumes_issued_state_once_before_saving_token(monkeypatch):
    exchanges = []

    def no_network_exchange(self, code, state):
        exchanges.append((code, state))
        return {
            "access_token": "xoxb-oauth",
            "scope": "chat:write",
            "team": {"id": "T1", "name": "Sentinel"},
            "bot_user_id": "B1",
        }

    monkeypatch.setattr("sentinel.oauth.OAuthManager.exchange_slack_code", no_network_exchange)
    settings = _stub_live_settings(
        slack_client_id="slack-client",
        slack_client_secret="slack-secret",
        slack_redirect_uri="http://localhost/slack",
    )
    app = create_app(settings)
    client = TestClient(app)
    install = client.get("/oauth/slack/install", headers=_api_headers(), follow_redirects=False)
    state = _redirect_state(install)

    first = client.get("/oauth/slack/callback", params={"code": "oauth-code", "state": state})
    second = client.get("/oauth/slack/callback", params={"code": "second-code", "state": state})

    assert first.status_code == 200
    assert first.json()["token_received"] is True
    assert second.status_code == 409
    assert "already been used" in second.json()["detail"]
    assert exchanges == [("oauth-code", state)]
    token = app.state.store.load_oauth_token("slack")
    assert token["access_token"] == "xoxb-oauth"
    assert app.state.store.lookup_idempotency_key(f"oauth:slack:{state}:used") == "slack"


def test_oauth_callback_rejects_malformed_token_payload_without_persisting(monkeypatch):
    exchanges = []

    def malformed_exchange(self, code, state):
        exchanges.append((code, state))
        return {"ok": True, "team": {"id": "T1", "name": "Sentinel"}}

    monkeypatch.setattr("sentinel.oauth.OAuthManager.exchange_slack_code", malformed_exchange)
    settings = _stub_live_settings(
        slack_client_id="slack-client",
        slack_client_secret="slack-secret",
        slack_redirect_uri="http://localhost/slack",
    )
    app = create_app(settings)
    client = TestClient(app)
    install = client.get("/oauth/slack/install", headers=_api_headers(), follow_redirects=False)
    state = _redirect_state(install)

    response = client.get("/oauth/slack/callback", params={"code": "oauth-code", "state": state})

    assert response.status_code == 502
    assert "access_token" in response.json()["detail"]
    assert exchanges == [("oauth-code", state)]
    assert app.state.store.load_oauth_token("slack") is None
    assert app.state.store.lookup_idempotency_key(f"oauth:slack:{state}:used") == "slack"


def test_datadog_oauth_callback_consumes_issued_state_once_before_saving_token(monkeypatch):
    exchanges = []

    def no_network_exchange(self, code, state, *, code_verifier, domain=None):
        exchanges.append((code, state, code_verifier, domain))
        return {
            "access_token": "dd-oauth",
            "refresh_token": "dd-refresh",
            "token_type": "bearer",
            "scope": "logs_read_data metrics_read apm_read",
            "domain": domain or "datadoghq.com",
            "expires_in": 3600,
        }

    monkeypatch.setattr("sentinel.oauth.OAuthManager.exchange_datadog_code", no_network_exchange)
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id="datadog-client",
        datadog_client_secret="datadog-secret",
        datadog_redirect_uri="http://localhost/datadog",
    )
    app = create_app(settings)
    client = TestClient(app)
    install = client.get("/oauth/datadog/install", headers=_api_headers(), follow_redirects=False)
    state = _redirect_state(install)
    verifier = app.state.store.lookup_idempotency_key(f"oauth:datadog:{state}:pkce_verifier")

    first = client.get(
        "/oauth/datadog/callback",
        params={"code": "oauth-code", "state": state, "domain": "datadoghq.eu"},
    )
    second = client.get(
        "/oauth/datadog/callback",
        params={"code": "second-code", "state": state, "domain": "datadoghq.eu"},
    )

    assert first.status_code == 200
    assert first.json()["token_received"] is True
    assert first.json()["refresh_token_received"] is True
    assert second.status_code == 409
    assert "already been used" in second.json()["detail"]
    assert exchanges == [("oauth-code", state, verifier, "datadoghq.eu")]
    token = app.state.store.load_oauth_token("datadog")
    assert token["access_token"] == "dd-oauth"
    assert token["refresh_token"] == "dd-refresh"
    assert token["metadata"]["domain"] == "datadoghq.eu"
    assert app.state.store.lookup_idempotency_key(f"oauth:datadog:{state}:used") == "datadog"


def test_datadog_oauth_callback_rejects_malformed_token_payload_without_persisting(monkeypatch):
    exchanges = []

    def malformed_exchange(self, code, state, *, code_verifier, domain=None):
        exchanges.append((code, state, code_verifier, domain))
        return {"token_type": "bearer", "domain": domain or "datadoghq.com"}

    monkeypatch.setattr("sentinel.oauth.OAuthManager.exchange_datadog_code", malformed_exchange)
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id="datadog-client",
        datadog_client_secret="datadog-secret",
        datadog_redirect_uri="http://localhost/datadog",
    )
    app = create_app(settings)
    client = TestClient(app)
    install = client.get("/oauth/datadog/install", headers=_api_headers(), follow_redirects=False)
    state = _redirect_state(install)
    verifier = app.state.store.lookup_idempotency_key(f"oauth:datadog:{state}:pkce_verifier")

    response = client.get(
        "/oauth/datadog/callback",
        params={"code": "oauth-code", "state": state, "domain": "datadoghq.com"},
    )

    assert response.status_code == 502
    assert "access_token" in response.json()["detail"]
    assert exchanges == [("oauth-code", state, verifier, "datadoghq.com")]
    assert app.state.store.load_oauth_token("datadog") is None
    assert app.state.store.lookup_idempotency_key(f"oauth:datadog:{state}:used") == "datadog"


def test_run_live_investigation_closes_provider_clients(monkeypatch):
    closed = []

    class StubOrchestrator:
        def run_live_incident(self, **kwargs):
            return InvestigationState(
                incident_id=kwargs["incident_id"],
                scenario_name="live",
                affected_services=kwargs["affected_services"],
                service_priority=kwargs["affected_services"],
            )

    class StubClients:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(
        "sentinel.webapp._build_live_orchestrator",
        lambda settings, store: (StubOrchestrator(), StubClients()),
    )

    state = _run_live_investigation(
        _stub_live_settings(),
        {},
        "PD-LIVE-CLOSE",
        services=["checkout-service"],
        store=create_app(_stub_live_settings()).state.store,
    )

    assert state.incident_id == "PD-LIVE-CLOSE"
    assert closed == [True]


def test_live_provider_clients_close_shared_rate_limiter_backend_once():
    backend = _ClosableRateLimitBackend()
    rate_limiter = SharedRateLimiter(backend, limit=10, window_seconds=60)
    apis = [
        LiveApiClient(base_url="https://example.test", headers={}, name=name, rate_limiter=rate_limiter)
        for name in ("datadog", "github", "pagerduty", "slack")
    ]
    clients = LiveProviderClients(
        datadog=SimpleNamespace(api=apis[0]),
        github=SimpleNamespace(api=apis[1]),
        pagerduty=SimpleNamespace(api=apis[2]),
        slack=SimpleNamespace(api=apis[3]),
        kubernetes=SimpleNamespace(rate_limiter=rate_limiter),
        generic_alerts=SimpleNamespace(rate_limiter=rate_limiter),
    )

    clients.close()

    assert backend.close_count == 1
    assert all(api.client.is_closed for api in apis)


def test_safe_live_investigation_failure_redacts_persisted_error(monkeypatch):
    def fail_live_investigation(*args, **kwargs):
        raise RuntimeError(
            "provider failed with Authorization: Bearer xoxb-secret-token and refresh_token=ghp-secret-token"
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation", fail_live_investigation)
    settings = _stub_live_settings()
    app = create_app(settings)
    store = app.state.store

    _run_live_investigation_safely(
        settings,
        store,
        {"event": {"data": {"incident": {"id": "PD-LIVE-LEAK"}}}},
        "PD-LIVE-LEAK",
        ["payment-service"],
        "inv-live-leak",
    )

    state = store.load_state("inv-live-leak")
    audit_errors = [
        event.payload.get("error", "")
        for event in state.audit_events
        if event.event_type == "live_investigation_failed"
    ]

    assert state.status == InvestigationStatus.FAILED
    assert "xoxb-secret-token" not in state.context_summary
    assert "ghp-secret-token" not in state.context_summary
    assert "[redacted]" in state.context_summary
    assert audit_errors
    assert all("xoxb-secret-token" not in error for error in audit_errors)

    response = TestClient(app).get("/investigations/inv-live-leak", headers=_api_headers())
    assert response.status_code == 200
    assert response.json()["audit"]["event_count"] == 1
    assert response.json()["audit"]["latest_event"]["event_type"] == "live_investigation_failed"
    assert "payload" not in response.json()["audit"]["latest_event"]
    assert all("ghp-secret-token" not in error for error in audit_errors)


def test_ready_rejects_nonexistent_kubeconfig_path():
    settings = _stub_live_settings(kubeconfig="/tmp/sentinel-missing-kubeconfig")

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["kubeconfig_configured"] is False
    assert body["missing_live_credentials"] == ["KUBECONFIG"]


def test_ready_reports_datadog_api_key_auth_mode():
    response = TestClient(create_app(_stub_live_settings())).get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["token_sources"]["datadog_oauth_token"] == "api_keys"


def test_ready_accepts_datadog_github_and_slack_tokens_from_oauth_store():
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token=None,
        slack_bot_token=None,
    )
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="datadog",
        access_token="dd-oauth",
        scopes=["logs_read_data", "metrics_read", "apm_read"],
    )
    app.state.store.save_oauth_token(
        provider="github",
        access_token="gh-oauth",
        scopes=["repo", "read:org"],
    )
    app.state.store.save_oauth_token(
        provider="slack",
        access_token="xoxb-oauth",
        scopes=["chat:write", "channels:read", "channels:manage", "groups:read", "groups:write"],
    )

    response = TestClient(app).get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert "DD_API_KEY" not in body["missing_live_credentials"]
    assert "DD_APP_KEY" not in body["missing_live_credentials"]
    assert "GITHUB_TOKEN" not in body["missing_live_credentials"]
    assert "SLACK_BOT_TOKEN" not in body["missing_live_credentials"]
    assert body["token_sources"]["datadog_oauth_token"] == "oauth_store"
    assert body["token_sources"]["github_token"] == "oauth_store"
    assert body["token_sources"]["slack_bot_token"] == "oauth_store"


def test_ready_rejects_datadog_oauth_store_with_insufficient_explicit_scopes():
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
    )
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="datadog",
        access_token="dd-oauth",
        scopes=["logs_read_data"],
    )

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["missing_live_credentials"] == [
        "DD_OAUTH_TOKEN_SCOPE:metrics_read",
        "DD_OAUTH_TOKEN_SCOPE:apm_read",
    ]
    assert body["token_sources"]["datadog_oauth_token"] == "oauth_store_insufficient_scopes"


def test_ready_rejects_github_oauth_store_with_insufficient_explicit_scopes():
    settings = _stub_live_settings(github_token=None)
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="github",
        access_token="gh-oauth",
        scopes=["read:org"],
    )

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["missing_live_credentials"] == ["GITHUB_OAUTH_TOKEN_SCOPE:repo"]
    assert body["token_sources"]["github_token"] == "oauth_store_insufficient_scopes"


def test_ready_rejects_slack_oauth_store_with_insufficient_explicit_scopes():
    settings = _stub_live_settings(slack_bot_token=None)
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="slack",
        access_token="xoxb-oauth",
        scopes=["chat:write", "channels:read"],
    )

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["missing_live_credentials"] == [
        "SLACK_OAUTH_TOKEN_SCOPE:channels:manage",
        "SLACK_OAUTH_TOKEN_SCOPE:groups:read",
        "SLACK_OAUTH_TOKEN_SCOPE:groups:write",
    ]
    assert body["token_sources"]["slack_bot_token"] == "oauth_store_insufficient_scopes"


def test_live_orchestrator_build_uses_stored_oauth_tokens_for_provider_clients():
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        github_token=None,
        slack_bot_token=None,
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="dd-oauth",
        metadata={"domain": "datadoghq.eu"},
    )
    store.save_oauth_token(provider="github", access_token="gh-oauth")
    store.save_oauth_token(provider="slack", access_token="xoxb-oauth")

    _orchestrator, clients = _build_live_orchestrator(settings, store)
    try:
        assert clients.datadog.api.headers["Authorization"] == "Bearer dd-oauth"
        assert "DD-API-KEY" not in clients.datadog.api.headers
        assert clients.datadog.api.base_url == "https://api.datadoghq.eu"
        assert clients.github.api.headers["Authorization"] == "Bearer gh-oauth"
        assert clients.slack.api.headers["Authorization"] == "Bearer xoxb-oauth"
    finally:
        clients.close()


def test_ready_rejects_expired_stored_datadog_oauth_without_refresh_config():
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id=None,
        datadog_client_secret=None,
        datadog_redirect_uri=None,
    )
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh-token",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": "2000-01-01T00:00:00+00:00",
        },
    )

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["missing_live_credentials"] == [
        "DD_CLIENT_ID",
        "DD_CLIENT_SECRET",
        "DD_REDIRECT_URI",
    ]
    assert body["token_sources"]["datadog_oauth_token"] == "oauth_store_expired"


def test_pagerduty_webhook_preserves_stored_datadog_oauth_for_live_refresh(monkeypatch):
    captured = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        captured.append(settings)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id="dd-client",
        datadog_client_secret="dd-secret",
        datadog_redirect_uri="http://localhost:8000/oauth/datadog/callback",
    )
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh-token",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": "2000-01-01T00:00:00+00:00",
        },
    )
    raw = _raw_webhook_body()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    assert captured
    assert captured[0].datadog_oauth_token is None
    assert captured[0].datadog_api_key is None
    assert captured[0].datadog_app_key is None


def test_ready_rejects_unreachable_investigation_store():
    class UnreachableStore:
        def ping(self):
            return False

        def load_oauth_token(self, provider):
            raise RuntimeError(f"{provider} token store unavailable Authorization: Bearer ghp-secret-token")

    app = create_app(
        _stub_live_settings(
            github_token=None,
            slack_bot_token=None,
            discord_webhook_url="https://discord.example/webhook",
        )
    )
    app.state.store = UnreachableStore()

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["database_reachable"] is False
    assert body["redis_reachable"] is True
    assert body["missing_live_credentials"] == []
    assert body["oauth_store_reachable"] is False
    assert body["token_sources"]["github_token"] == "oauth_store_unavailable"
    assert body["token_sources"]["slack_bot_token"] == "oauth_store_unavailable"
    rendered = json.dumps(body)
    assert "ghp-secret-token" not in rendered
    assert "[redacted]" in rendered


def test_ready_rejects_oauth_store_read_failure_after_store_ping_succeeds():
    class BrokenOAuthStore:
        def ping(self):
            return True

        def load_oauth_token(self, provider):
            raise RuntimeError(f"{provider} token store unavailable api_key=dd-secret")

    app = create_app(
        _stub_live_settings(
            github_token=None,
            slack_bot_token=None,
            discord_webhook_url="https://discord.example/webhook",
        )
    )
    app.state.store = BrokenOAuthStore()

    response = TestClient(app).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["database_reachable"] is True
    assert body["oauth_store_reachable"] is False
    assert body["missing_live_credentials"] == []
    assert body["token_sources"]["github_token"] == "oauth_store_unavailable"
    assert body["token_sources"]["slack_bot_token"] == "oauth_store_unavailable"
    rendered = json.dumps(body)
    assert "dd-secret" not in rendered
    assert "[redacted]" in rendered


def test_ready_requires_database_and_redis_urls_in_production():
    settings = _stub_live_settings(environment="production", database_url=None, redis_url=None)

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["database_configured"] is False
    assert body["redis_configured"] is False
    assert "DATABASE_URL" in body["missing_live_credentials"]
    assert "REDIS_URL" in body["missing_live_credentials"]


def test_ready_treats_whitespace_production_env_as_production():
    settings = _stub_live_settings(environment=" production ", database_url=None, redis_url=None)

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert "DATABASE_URL" in body["missing_live_credentials"]
    assert "REDIS_URL" in body["missing_live_credentials"]


def test_ready_reports_store_construction_failure_without_crashing(monkeypatch):
    def fail_store(database_url):
        raise RuntimeError(
            f"could not connect to {database_url} api_key=dd-secret Authorization: Bearer ghp-secret-token"
        )

    monkeypatch.setattr("sentinel.webapp.build_store", fail_store)
    settings = _stub_live_settings(database_url="postgresql://sentinel:db-secret@db/sentinel")

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    rendered = json.dumps(body)
    assert body["ready"] is False
    assert body["database_configured"] is True
    assert body["database_reachable"] is False
    assert body["database_error"]
    assert "[redacted]" in body["database_error"]
    assert "db-secret" not in rendered
    assert "dd-secret" not in rendered
    assert "ghp-secret-token" not in rendered


def test_ready_recovers_when_initial_store_construction_later_succeeds(monkeypatch):
    calls = []

    def flaky_store(database_url):
        calls.append(database_url)
        if len(calls) == 1:
            raise RuntimeError(
                f"database still starting at {database_url} api_key=dd-secret Authorization: Bearer ghp-secret-token"
            )
        return SQLiteInvestigationStore()

    monkeypatch.setattr("sentinel.webapp.build_store", flaky_store)
    settings = _stub_live_settings(database_url="postgresql://sentinel:db-secret@db/sentinel")
    app = create_app(settings)

    response = TestClient(app).get("/ready")

    assert response.status_code == 200
    body = response.json()
    rendered = json.dumps(body)
    assert body["ready"] is True
    assert body["database_reachable"] is True
    assert "database_error" not in body
    assert len(calls) == 2
    assert app.state.store.count_rows("schema_migrations") == 1
    assert "db-secret" not in rendered
    assert "dd-secret" not in rendered
    assert "ghp-secret-token" not in rendered


def test_ready_recovers_stale_managed_store_connection(monkeypatch):
    stale_stores = []

    class StaleStore(SQLiteInvestigationStore):
        def __init__(self):
            super().__init__()
            self.closed = False

        def ping(self):
            return False

        def close(self):
            self.closed = True
            super().close()

    def build_flaky_store(database_url):
        if not stale_stores:
            store = StaleStore()
            stale_stores.append(store)
            return store
        return SQLiteInvestigationStore()

    monkeypatch.setattr("sentinel.webapp.build_store", build_flaky_store)
    settings = _stub_live_settings(database_url="postgresql://sentinel:db-secret@db/sentinel")
    app = create_app(settings)

    response = TestClient(app).get("/ready")

    assert response.status_code == 200
    assert response.json()["ready"] is True
    assert stale_stores[0].closed is True
    assert app.state.store is not stale_stores[0]
    assert app.state.store.ping() is True


def test_ready_rejects_unreachable_redis(monkeypatch):
    class UnreachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return False

    monkeypatch.setattr("sentinel.webapp.RedisRateLimitBackend", UnreachableRedis)
    settings = _stub_live_settings(redis_url="redis://localhost:6379/9")

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["redis_configured"] is True
    assert body["redis_reachable"] is False
    assert body["database_reachable"] is True


def test_redis_readiness_probe_closes_backend(monkeypatch):
    closed = []

    class ReachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return True

        def close(self):
            closed.append(self.redis_url)

    monkeypatch.setattr("sentinel.webapp.RedisRateLimitBackend", ReachableRedis)

    assert _redis_reachable(_stub_live_settings(redis_url="redis://localhost:6379/9")) is True
    assert closed == ["redis://localhost:6379/9"]


def test_ready_requires_webhook_signature_secret_in_production(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    settings = _stub_live_settings(
        environment="production",
        pagerduty_webhook_secret=None,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["webhook_signature_verification"] is False
    assert body["missing_live_credentials"] == ["PAGERDUTY_WEBHOOK_SECRET"]


def test_ready_reports_configured_pagerduty_webhook_subscription_binding(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    settings = _stub_live_settings(
        environment="production",
        pagerduty_webhook_subscription_id="PWSUB123",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["webhook_subscription_bound"] is True


def test_ready_requires_operator_api_token_in_production(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    settings = _stub_live_settings(
        environment="production",
        api_token=None,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    response = TestClient(create_app(settings)).get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["operator_authentication"] is False
    assert body["missing_live_credentials"] == ["SENTINEL_API_TOKEN"]


def test_live_ready_requires_operator_auth_in_production(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    response = TestClient(create_app(settings)).get("/ready/live")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid SENTINEL API token"


def test_live_ready_runs_provider_preflight_in_production(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    provider_calls = []

    def failed_provider_preflight(settings, store):
        provider_calls.append((settings, store))
        return _failed_provider_preflight_report()

    monkeypatch.setattr("sentinel.webapp.run_live_connectivity_checks", failed_provider_preflight)
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    response = TestClient(create_app(settings)).get("/ready/live", headers=_api_headers())

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["base_ready"] is True
    assert body["provider_preflight_ready"] is False
    assert body["provider_preflight_skipped"] is False
    assert body["checks"][0]["name"] == "datadog.logs"
    assert provider_calls


def test_live_ready_skips_provider_preflight_outside_production(monkeypatch):
    provider_calls = []
    monkeypatch.setattr(
        "sentinel.webapp.run_live_connectivity_checks",
        lambda settings, store: provider_calls.append((settings, store)),
    )
    settings = _stub_live_settings(environment="development")

    response = TestClient(create_app(settings)).get("/ready/live", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["base_ready"] is True
    assert body["provider_preflight_ready"] is True
    assert body["provider_preflight_skipped"] is True
    assert provider_calls == []


def test_oauth_token_store_round_trips_provider_token():
    app = create_app(SentinelSettings.from_env())

    app.state.store.save_oauth_token(
        provider="github",
        access_token="gh-token",
        subject="repo,read:org",
        token_type="bearer",
        scopes=["repo", "read:org"],
        metadata={"installation": "manual"},
    )
    token = app.state.store.load_oauth_token("github")

    assert token["access_token"] == "gh-token"
    assert token["token_type"] == "bearer"
    assert token["scopes"] == ["repo", "read:org"]
    assert token["metadata"]["installation"] == "manual"


def test_pagerduty_webhook_rejects_invalid_signature_before_live_work():
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    response = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=_raw_webhook_body(),
        headers={"x-pagerduty-signature": "bad", "content-type": "application/json"},
    )

    assert response.status_code == 401


def test_pagerduty_webhook_accepts_previous_secret_during_rotation(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(
        pagerduty_webhook_secret="pd-current",
        pagerduty_webhook_previous_secret="pd-previous",
    )
    raw = _raw_webhook_body()
    response = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-previous"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    assert calls == [response.json()["investigation_id"]]


def test_pagerduty_webhook_rejects_incident_without_usable_service_before_live_work(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = json.dumps(
        {
            "event": {
                "event_type": "incident.triggered",
                "data": {
                    "id": "PD-NO-SERVICE",
                    "type": "incident",
                    "status": "triggered",
                    "title": "Checkout latency is high",
                },
            }
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "PagerDuty webhook did not include a usable incident service"
    assert app.state.store.count_rows("investigations") == 0
    assert calls == []


def test_pagerduty_webhook_ignores_non_triggering_incident_event_without_live_work(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = json.dumps(
        {
            "event": {
                "event_type": "incident.resolved",
                "data": {
                    "id": "PD-RESOLVED",
                    "type": "incident",
                    "status": "resolved",
                    "service": {"summary": "payment-service"},
                },
            }
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "investigation_id": None,
        "message": "Accepted non-triggering PagerDuty webhook event; no Investigation created",
    }
    assert app.state.store.count_rows("investigations") == 0
    assert calls == []


def test_pagerduty_webhook_uses_triggered_item_when_batch_mixes_lifecycle_events(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(
            {
                "incident_id": incident_id,
                "services": services,
                "investigation_id": investigation_id,
            }
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = json.dumps(
        {
            "messages": [
                {
                    "event": {
                        "event_type": "incident.resolved",
                        "data": {
                            "id": "PD-RESOLVED-FIRST",
                            "type": "incident",
                            "status": "resolved",
                            "service": {"summary": "old-service"},
                        },
                    }
                },
                {
                    "event": {
                        "event_type": "incident.triggered",
                        "data": {
                            "id": "PD-TRIGGERED-SECOND",
                            "type": "incident",
                            "status": "triggered",
                            "service": {"summary": "checkout-service"},
                        },
                    }
                },
            ]
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    body = response.json()
    assert response.status_code == 200
    assert "PD-TRIGGERED-SECOND" in body["message"]
    assert calls == [
        {
            "incident_id": "PD-TRIGGERED-SECOND",
            "services": ["checkout-service"],
            "investigation_id": body["investigation_id"],
        }
    ]
    state = app.state.store.load_state(body["investigation_id"])
    assert state.incident_id == "PD-TRIGGERED-SECOND"
    assert state.affected_services == ["checkout-service"]


def test_pagerduty_webhook_rejects_batch_with_multiple_triggered_incidents(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = json.dumps(
        {
            "messages": [
                {
                    "event": {
                        "event_type": "incident.triggered",
                        "data": {
                            "id": "PD-TRIGGERED-ONE",
                            "type": "incident",
                            "status": "triggered",
                            "service": {"summary": "checkout-service"},
                        },
                    }
                },
                {
                    "event": {
                        "event_type": "incident.triggered",
                        "data": {
                            "id": "PD-TRIGGERED-TWO",
                            "type": "incident",
                            "status": "triggered",
                            "service": {"summary": "billing-service"},
                        },
                    }
                },
            ]
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "PagerDuty webhook contained multiple actionable incidents; send one incident per webhook"
    )
    assert app.state.store.count_rows("investigations") == 0
    assert calls == []


def test_pagerduty_webhook_rejects_unknown_secret_during_rotation():
    settings = _stub_live_settings(
        pagerduty_webhook_secret="pd-current",
        pagerduty_webhook_previous_secret="pd-previous",
    )
    raw = _raw_webhook_body()
    response = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-unknown"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 401


def test_pagerduty_webhook_requires_matching_subscription_when_configured(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(
        pagerduty_webhook_secret="pd-secret",
        pagerduty_webhook_subscription_id="PWSUB123",
    )
    raw = _raw_webhook_body()
    headers = {
        "x-pagerduty-signature": _signature(raw, "pd-secret"),
        "content-type": "application/json",
    }

    missing = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers=headers,
    )
    wrong = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={**headers, "x-webhook-subscription": "PWSUB999"},
    )
    accepted = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={**headers, "x-webhook-subscription": "PWSUB123"},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert calls == [accepted.json()["investigation_id"]]


def test_pagerduty_webhook_rejects_subscription_mismatch_before_parsing_json(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation_safely",
        lambda *args: calls.append(args),
    )
    settings = _stub_live_settings(
        pagerduty_webhook_secret="pd-secret",
        pagerduty_webhook_subscription_id="PWSUB123",
    )
    raw = b"{not-json"

    response = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "x-webhook-subscription": "PWSUB999",
            "content-type": "application/json",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid PagerDuty webhook subscription"
    assert calls == []


def test_pagerduty_webhook_requires_live_credentials_even_with_valid_signature():
    settings = replace(SentinelSettings.from_env(), pagerduty_webhook_secret="pd-secret")
    raw = _raw_webhook_body()
    response = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 503
    assert "DD_API_KEY" in response.json()["detail"]["missing_live_credentials"]


def test_pagerduty_webhook_rejects_unready_runtime_before_creating_investigation(monkeypatch):
    calls = []

    class UnreachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return False

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp.RedisRateLimitBackend", UnreachableRedis)
    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(redis_url="redis://localhost:6379/9")
    app = create_app(settings)
    raw = _raw_webhook_body()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["ready"] is False
    assert detail["redis_reachable"] is False
    assert app.state.store.count_rows("investigations") == 0
    assert calls == []


def test_pagerduty_webhook_rejects_failed_provider_preflight_before_creating_investigation(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    calls = []

    monkeypatch.setattr(
        "sentinel.webapp.run_live_connectivity_checks",
        lambda settings, store: _failed_provider_preflight_report(),
    )
    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation_safely",
        lambda *args: calls.append(args),
    )
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)
    raw = _raw_webhook_body()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["provider_preflight_ready"] is False
    assert detail["checks"][0]["name"] == "datadog.logs"
    assert app.state.store.count_rows("investigations") == 0
    assert calls == []


def test_pagerduty_webhook_runs_provider_preflight_with_whitespace_production_env(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    provider_calls = []
    live_calls = []

    def failed_provider_preflight(settings, store):
        provider_calls.append((settings, store))
        return _failed_provider_preflight_report()

    monkeypatch.setattr("sentinel.webapp.run_live_connectivity_checks", failed_provider_preflight)
    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation_safely",
        lambda *args: live_calls.append(args),
    )
    settings = _stub_live_settings(
        environment=" production ",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)
    raw = _raw_webhook_body()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"]["provider_preflight_ready"] is False
    assert provider_calls
    assert app.state.store.count_rows("investigations") == 0
    assert live_calls == []


def test_pagerduty_webhook_retry_returns_existing_without_provider_preflight(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    provider_calls = []
    live_calls = []

    def fail_if_provider_preflight_runs(settings, store):
        provider_calls.append((settings, store))
        return _failed_provider_preflight_report()

    monkeypatch.setattr("sentinel.webapp.run_live_connectivity_checks", fail_if_provider_preflight_runs)
    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation_safely",
        lambda *args: live_calls.append(args),
    )
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)
    existing = InvestigationState(
        id="inv-existing-retry",
        incident_id="PD-LIVE-1",
        scenario_name="live",
        affected_services=["payment-service"],
        service_priority=["payment-service"],
    )
    app.state.store.save_state(existing)
    assert app.state.store.remember_idempotency_key(
        _webhook_idempotency_key("pagerduty", "PD-LIVE-1"),
        "webhook",
        existing.id,
    )
    raw = _raw_webhook_body()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["investigation_id"] == existing.id
    assert "Duplicate PagerDuty webhook" in body["message"]
    assert provider_calls == []
    assert live_calls == []
    assert app.state.store.count_rows("investigations") == 1


def test_pagerduty_webhook_accepts_signed_v3_test_event_without_investigation(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret", redis_url="redis://localhost:6379/9")
    app = create_app(settings)
    raw = json.dumps(
        {
            "event": {
                "id": "01CH754SM17TWPE2V2H4VPBRO7",
                "event_type": "pagey.ping",
                "resource_type": "pagey",
                "occurred_at": "2021-12-08T22:58:53.510Z",
                "data": {
                    "message": "Hello from your friend Pagey!",
                    "type": "ping",
                },
            }
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "x-webhook-subscription": "PWH-SUBSCRIPTION-1",
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] is True
    assert body["investigation_id"] is None
    assert "test event" in body["message"]
    assert app.state.store.count_rows("investigations") == 0
    assert app.state.store.count_rows("idempotency_keys") == 0
    assert calls == []


def test_pagerduty_webhook_trigger_wins_when_batch_contains_test_ping(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(
            {
                "incident_id": incident_id,
                "services": services,
                "investigation_id": investigation_id,
            }
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = json.dumps(
        {
            "messages": [
                {
                    "event": {
                        "event_type": "pagey.ping",
                        "resource_type": "pagey",
                        "data": {
                            "message": "Hello from your friend Pagey!",
                            "type": "ping",
                        },
                    }
                },
                {
                    "event": {
                        "event_type": "incident.triggered",
                        "data": {
                            "id": "PD-TRIGGERED-AFTER-PING",
                            "type": "incident",
                            "status": "triggered",
                            "service": {"summary": "checkout-service"},
                        },
                    }
                },
            ]
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    body = response.json()
    assert response.status_code == 200
    assert "test event" not in body["message"]
    assert "PD-TRIGGERED-AFTER-PING" in body["message"]
    assert calls == [
        {
            "incident_id": "PD-TRIGGERED-AFTER-PING",
            "services": ["checkout-service"],
            "investigation_id": body["investigation_id"],
        }
    ]
    assert app.state.store.count_rows("investigations") == 1


def test_pagerduty_webhook_test_event_requires_signature_secret_in_production(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    calls = []

    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation_safely",
        lambda *args: calls.append(args),
    )
    settings = _stub_live_settings(
        environment="production",
        pagerduty_webhook_secret=None,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)
    raw = json.dumps(
        {
            "event": {
                "event_type": "pagey.ping",
                "resource_type": "pagey",
                "data": {
                    "message": "Hello from your friend Pagey!",
                    "type": "ping",
                },
            }
        },
        separators=(",", ":"),
    ).encode()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "PAGERDUTY_WEBHOOK_SECRET is required for PagerDuty webhooks"
    assert app.state.store.count_rows("investigations") == 0
    assert calls == []


def test_pagerduty_webhook_rejects_store_construction_failure_before_live_work(monkeypatch):
    calls = []

    def fail_store(database_url):
        raise RuntimeError(
            f"could not connect to {database_url} api_key=dd-secret Authorization: Bearer ghp-secret-token"
        )

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp.build_store", fail_store)
    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(database_url="postgresql://sentinel:db-secret@db/sentinel")
    app = create_app(settings)
    raw = _raw_webhook_body()

    response = TestClient(app).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    rendered = json.dumps(detail)
    assert detail["ready"] is False
    assert detail["database_reachable"] is False
    assert detail["database_error"]
    assert "db-secret" not in rendered
    assert "dd-secret" not in rendered
    assert "ghp-secret-token" not in rendered
    assert calls == []


def test_pagerduty_webhook_rejects_malformed_json_before_live_work():
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    raw = b"{not-json"

    response = TestClient(create_app(settings)).post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "PagerDuty webhook body must be valid JSON"


def test_pagerduty_webhook_returns_investigation_id_and_status(monkeypatch):
    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        return None

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = _raw_webhook_body()
    client = TestClient(app)

    response = client.post(
        "/webhooks/pagerduty",
        content=raw,
        headers={
            "x-pagerduty-signature": _signature(raw, "pd-secret"),
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    investigation_id = response.json()["investigation_id"]
    assert investigation_id.startswith("inv-")

    status = client.get(f"/investigations/{investigation_id}", headers=_api_headers())
    assert status.status_code == 200
    assert status.json()["incident_id"] == "PD-LIVE-1"
    assert status.json()["status"] == "running"
    assert status.json()["audit"]["event_count"] == 1
    assert status.json()["audit"]["latest_event"]["event_type"] == "pagerduty_webhook_accepted"
    assert status.json()["audit"]["events"] == [
        status.json()["audit"]["latest_event"],
    ]


def test_generic_webhook_returns_investigation_id_status_and_schedules_live_work(monkeypatch):
    captured = []
    readiness_checks = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        captured.append(
            {
                "payload": payload,
                "incident_id": incident_id,
                "services": services,
                "investigation_id": investigation_id,
            }
        )

    def ready(*_args, **kwargs):
        readiness_checks.append(kwargs)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    monkeypatch.setattr("sentinel.webapp._require_runtime_ready", ready)
    settings = _stub_live_settings(
        pagerduty_api_key=None,
        pagerduty_webhook_secret=None,
        prometheus_url="http://prometheus:9090",
        loki_url="http://loki:3100",
        slack_bot_token=None,
        slack_channel_id=None,
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
    )
    client = TestClient(create_app(settings))

    response = client.post(
        "/webhooks/generic",
        json={
            "alert_id": "FREE-ALERT-1",
            "services": ["payment-service", {"summary": "checkout-service"}],
            "title": "Free alert source fired",
        },
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["message"] == "Accepted generic webhook for FREE-ALERT-1"
    investigation_id = response.json()["investigation_id"]
    assert investigation_id.startswith("inv-")
    assert readiness_checks == [{"operation": "free-tier live investigation"}]
    assert captured == [
        {
            "payload": {
                "alert_id": "FREE-ALERT-1",
                "services": ["payment-service", {"summary": "checkout-service"}],
                "title": "Free alert source fired",
                "source": "generic_webhook",
            },
            "incident_id": "FREE-ALERT-1",
            "services": ["payment-service", "checkout-service"],
            "investigation_id": investigation_id,
        }
    ]

    status = client.get(f"/investigations/{investigation_id}", headers=_api_headers())

    assert status.status_code == 200
    body = status.json()
    assert body["incident_id"] == "FREE-ALERT-1"
    assert body["status"] == "running"
    assert body["audit"]["event_count"] == 1
    assert body["audit"]["latest_event"]["event_type"] == "generic_webhook_accepted"
    assert body["webhook_source"] == "generic_webhook"
    assert body["generic_webhook_received"] is True
    assert body["webhook_ingress"] == {
        "source": "generic_webhook",
        "incident_id": "FREE-ALERT-1",
        "affected_services": ["payment-service", "checkout-service"],
        "payload_keys": ["alert_id", "services", "source", "title"],
    }
    state = client.app.state.store.load_state(investigation_id)
    assert state.audit_events[0].payload["affected_services"] == [
        "payment-service",
        "checkout-service",
    ]
    assert state.audit_events[0].payload["source"] == "generic_webhook"
    assert state.artifacts["webhook_source"] == "generic_webhook"
    assert state.artifacts["generic_webhook_received"] is True
    assert state.artifacts["webhook_ingress"] == body["webhook_ingress"]


def test_generic_webhook_accepts_alertmanager_grouped_alert_payload(monkeypatch):
    captured = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        captured.append(
            {
                "payload": payload,
                "incident_id": incident_id,
                "services": services,
                "investigation_id": investigation_id,
            }
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    monkeypatch.setattr("sentinel.webapp._require_runtime_ready", lambda *_args, **_kwargs: None)
    settings = _stub_live_settings(
        pagerduty_api_key=None,
        pagerduty_webhook_secret=None,
        prometheus_url="http://prometheus:9090",
        loki_url="http://loki:3100",
        slack_bot_token=None,
        slack_channel_id=None,
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
    )
    client = TestClient(create_app(settings))
    payload = {
        "receiver": "sentinel",
        "groupKey": "alertmanager-group-123",
        "commonLabels": {"service": "checkout-service", "severity": "critical"},
        "groupLabels": {"app": "payments-api"},
        "alerts": [
            {"fingerprint": "am-fp-1", "labels": {"service": "checkout-service"}},
            {"fingerprint": "am-fp-2", "labels": {"service": "billing-service"}},
        ],
    }

    response = client.post("/webhooks/generic", json=payload)

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["message"] == "Accepted generic webhook for am-fp-1"
    investigation_id = response.json()["investigation_id"]
    assert captured == [
        {
            "payload": {
                **payload,
                "source": "generic_webhook",
            },
            "incident_id": "am-fp-1",
            "services": ["checkout-service", "payments-api", "billing-service"],
            "investigation_id": investigation_id,
        }
    ]

    status = client.get(f"/investigations/{investigation_id}", headers=_api_headers())

    assert status.status_code == 200
    body = status.json()
    assert body["incident_id"] == "am-fp-1"
    assert body["webhook_source"] == "generic_webhook"
    assert body["generic_webhook_received"] is True
    assert body["webhook_ingress"] == {
        "source": "generic_webhook",
        "incident_id": "am-fp-1",
        "affected_services": ["checkout-service", "payments-api", "billing-service"],
        "payload_keys": ["alerts", "commonLabels", "groupKey", "groupLabels", "receiver", "source"],
    }


def test_generic_webhook_retry_returns_existing_investigation_without_new_live_work(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    monkeypatch.setattr("sentinel.webapp._require_runtime_ready", lambda *_args, **_kwargs: None)
    settings = _stub_live_settings(
        pagerduty_api_key=None,
        pagerduty_webhook_secret=None,
        prometheus_url="http://prometheus:9090",
        loki_url="http://loki:3100",
        slack_bot_token=None,
        slack_channel_id=None,
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
    )
    client = TestClient(create_app(settings))
    payload = {"incident_id": "FREE-DUP-1", "service": "payment-service"}

    first = client.post("/webhooks/generic", json=payload)
    second = client.post("/webhooks/generic", json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["investigation_id"] == second.json()["investigation_id"]
    assert "Duplicate generic webhook" in second.json()["message"]
    assert calls == [first.json()["investigation_id"]]
    assert client.app.state.store.count_rows("investigations") == 1
    assert client.app.state.store.count_rows("idempotency_keys") == 1


def test_pagerduty_webhook_retry_returns_existing_investigation_without_new_live_work(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(investigation_id)

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    settings = _stub_live_settings(pagerduty_webhook_secret="pd-secret")
    app = create_app(settings)
    raw = _raw_webhook_body()
    headers = {
        "x-pagerduty-signature": _signature(raw, "pd-secret"),
        "content-type": "application/json",
    }
    client = TestClient(app)

    first = client.post("/webhooks/pagerduty", content=raw, headers=headers)
    second = client.post("/webhooks/pagerduty", content=raw, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["investigation_id"] == second.json()["investigation_id"]
    assert "Duplicate PagerDuty webhook" in second.json()["message"]
    assert calls == [first.json()["investigation_id"]]
    assert app.state.store.count_rows("investigations") == 1
    assert app.state.store.count_rows("idempotency_keys") == 1


def test_generic_and_pagerduty_webhooks_do_not_collide_on_same_incident_id(monkeypatch):
    calls = []

    def no_live_network(settings, store, payload, incident_id, services, investigation_id):
        calls.append(
            {
                "incident_id": incident_id,
                "investigation_id": investigation_id,
                "source": payload.get("source") or "pagerduty",
            }
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation_safely", no_live_network)
    monkeypatch.setattr("sentinel.webapp._require_runtime_ready", lambda *_args, **_kwargs: None)
    settings = _stub_live_settings(
        pagerduty_webhook_secret="pd-secret",
        prometheus_url="http://prometheus:9090",
        loki_url="http://loki:3100",
        slack_bot_token=None,
        slack_channel_id=None,
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
    )
    app = create_app(settings)
    client = TestClient(app)
    raw = _raw_webhook_body()
    headers = {
        "x-pagerduty-signature": _signature(raw, "pd-secret"),
        "content-type": "application/json",
    }

    pagerduty = client.post("/webhooks/pagerduty", content=raw, headers=headers)
    generic = client.post(
        "/webhooks/generic",
        json={"incident_id": "PD-LIVE-1", "service": "payment-service"},
    )

    assert pagerduty.status_code == 200
    assert generic.status_code == 200
    assert pagerduty.json()["investigation_id"] != generic.json()["investigation_id"]
    assert pagerduty.json()["message"] == "Accepted PagerDuty webhook for PD-LIVE-1"
    assert generic.json()["message"] == "Accepted generic webhook for PD-LIVE-1"
    assert app.state.store.lookup_idempotency_key(
        _webhook_idempotency_key("pagerduty", "PD-LIVE-1")
    ) == pagerduty.json()["investigation_id"]
    assert app.state.store.lookup_idempotency_key(
        _webhook_idempotency_key("generic_webhook", "PD-LIVE-1")
    ) == generic.json()["investigation_id"]
    assert app.state.store.count_rows("investigations") == 2
    assert app.state.store.count_rows("idempotency_keys") == 2
    assert [call["incident_id"] for call in calls] == ["PD-LIVE-1", "PD-LIVE-1"]


def test_investigation_status_rejects_store_construction_failure_with_503(monkeypatch):
    def fail_store(database_url):
        raise RuntimeError(
            f"could not connect to {database_url} api_key=dd-secret Authorization: Bearer ghp-secret-token"
        )

    monkeypatch.setattr("sentinel.webapp.build_store", fail_store)
    settings = _stub_live_settings(database_url="postgresql://sentinel:db-secret@db/sentinel")

    response = TestClient(create_app(settings)).get("/investigations/inv-missing", headers=_api_headers())

    assert response.status_code == 503
    rendered = json.dumps(response.json())
    assert "Investigation Store unavailable" in response.json()["detail"]
    assert "db-secret" not in rendered
    assert "dd-secret" not in rendered
    assert "ghp-secret-token" not in rendered


def test_investigation_status_exposes_remote_demo_success_flags():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.artifacts["approval_slack_notified"] = True
    state.artifacts["approval_slack_notification_request_id"] = state.approval_request.id
    state.tool_calls = [
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="comms.post_to_slack",
            state=StateName.RESPONSE_PROPOSAL,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        ),
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="observe.fetch_service_logs",
            state=StateName.EVIDENCE_COLLECTION,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        ),
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="repo.get_deploy_history",
            state=StateName.TRIAGE,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        ),
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="comms.page_oncall_engineer",
            state=StateName.RECEIVED,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        ),
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="observe.check_pod_health",
            state=StateName.TRIAGE,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        ),
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="infra.rollback_deployment",
            state=StateName.REMEDIATION,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=False,
            error_kind="permission_denied",
        ),
    ]
    state.evidence = [
        Evidence(
            source="comms.post_to_slack",
            time_window="live",
            affected_service="payment-service",
            claim="Slack proposal posted",
            provenance="live::comms.post_to_slack",
        ),
        Evidence(
            source="observe.fetch_service_logs",
            time_window="live",
            affected_service="payment-service",
            claim="Datadog logs returned event ids",
            provenance="live::observe.fetch_service_logs",
        ),
        Evidence(
            source="repo.get_deploy_history",
            time_window="live",
            affected_service="payment-service",
            claim="GitHub deployments returned ids",
            provenance="live::repo.get_deploy_history",
        ),
        Evidence(
            source="comms.page_oncall_engineer",
            time_window="live",
            affected_service="payment-service",
            claim="PagerDuty incident context returned",
            provenance="live::comms.page_oncall_engineer",
        ),
        Evidence(
            source="observe.check_pod_health",
            time_window="live",
            affected_service="payment-service",
            claim="Kubernetes pods returned names",
            provenance="live::observe.check_pod_health",
        ),
        Evidence(
            source="observe.get_error_rate_timeseries",
            time_window="live",
            affected_service="payment-service",
            claim="Replay evidence should not count as live Datadog proof",
            provenance="golden_path:observe.get_error_rate_timeseries",
        ),
        Evidence(
            source="observe.fetch_apm_data",
            time_window="live",
            affected_service="payment-service",
            claim="Provider returned no APM spans",
            provenance="live_empty::observe.fetch_apm_data",
        ),
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["slack_notified"] is True
    assert body["approval_slack_notified"] is True
    assert body["approval_slack_notification_request_id"] == state.approval_request.id
    assert body["rollback_attempted"] is True
    assert body["rollback_executed"] is False
    assert body["live_provider_proofs"] == {
        "prometheus": 0,
        "loki": 1,
        "datadog": 0,
        "github": 1,
        "generic_webhook": 0,
        "pagerduty": 1,
        "discord": 0,
        "slack": 1,
        "kubernetes": 1,
    }
    assert body["live_tool_proofs"] == {
        "comms.page_oncall_engineer": 1,
        "comms.post_to_slack": 1,
        "observe.check_pod_health": 1,
        "observe.fetch_service_logs": 1,
        "repo.get_deploy_history": 1,
    }
    assert body["recommendation"] == "rollback payment-service to v2.3.1"
    assert body["approval_approver_ids"] == ["eng-oncall"]


def test_investigation_status_counts_free_provider_artifacts_without_paid_defaults():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.artifacts["live_tool_providers"] = {
        "observe.fetch_service_logs": "loki",
        "observe.get_error_rate_timeseries": "prometheus",
        "observe.fetch_apm_data": "loki",
        "comms.page_oncall_engineer": "generic_webhook",
        "comms.post_to_slack": "discord",
        "repo.get_deploy_history": "github",
        "observe.check_pod_health": "kubernetes",
    }
    state.evidence = [
        Evidence(
            source=tool_name,
            time_window="live",
            affected_service="payment-service",
            claim=f"{tool_name} returned live provider evidence.",
            provenance=f"live::{tool_name}",
        )
        for tool_name in state.artifacts["live_tool_providers"]
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["live_provider_proofs"] == {
        "prometheus": 1,
        "loki": 2,
        "datadog": 0,
        "github": 1,
        "generic_webhook": 1,
        "pagerduty": 0,
        "discord": 1,
        "slack": 0,
        "kubernetes": 1,
    }
    assert body["live_tool_proofs"] == {
        "comms.page_oncall_engineer": 1,
        "comms.post_to_slack": 1,
        "observe.check_pod_health": 1,
        "observe.fetch_apm_data": 1,
        "observe.fetch_service_logs": 1,
        "observe.get_error_rate_timeseries": 1,
        "repo.get_deploy_history": 1,
    }


def test_investigation_status_requires_live_slack_post_evidence_for_notification_flag():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.tool_calls = [
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="comms.post_to_slack",
            state=StateName.RESPONSE_PROPOSAL,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        )
    ]
    state.evidence = [
        Evidence(
            source="comms.post_to_slack",
            time_window="live",
            affected_service="payment-service",
            claim="Slack adapter completed without provider-confirming receipt",
            provenance="live_empty::comms.post_to_slack",
        )
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["slack_notified"] is False
    assert body["approval_slack_notified"] is False
    assert body["live_provider_proofs"]["slack"] == 0


def test_investigation_status_distinguishes_general_slack_from_approval_proposal_delivery():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.evidence = [
        Evidence(
            source="comms.post_to_slack",
            time_window="live",
            affected_service="payment-service",
            claim="Initial investigation update posted to Slack",
            provenance="live::comms.post_to_slack",
        )
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["slack_notified"] is True
    assert body["approval_slack_notified"] is False


def test_investigation_status_rejects_stale_approval_slack_notification_request_id():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.artifacts["approval_slack_notified"] = True
    state.artifacts["approval_slack_notification_request_id"] = "approval-old"
    state.evidence = [
        Evidence(
            source="comms.post_to_slack",
            time_window="live",
            affected_service="payment-service",
            claim="Approval request posted to Slack",
            provenance="live::comms.post_to_slack",
        )
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["slack_notified"] is True
    assert body["approval_request_id"] == state.approval_request.id
    assert body["approval_slack_notification_request_id"] == "approval-old"
    assert body["approval_slack_notified"] is False


def test_investigation_status_requires_live_kubernetes_rollback_evidence_for_execution_flag():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.tool_calls = [
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="infra.rollback_deployment",
            state=StateName.REMEDIATION,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=True,
        )
    ]
    state.evidence = [
        Evidence(
            source="infra.rollback_deployment",
            time_window="live",
            affected_service="payment-service",
            claim="Kubernetes adapter completed without provider-confirming rollback receipt",
            provenance="live_empty::infra.rollback_deployment",
        )
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["rollback_attempted"] is True
    assert body["rollback_executed"] is False
    assert body["live_provider_proofs"]["kubernetes"] == 0


def test_investigation_status_exposes_redacted_evidence_gaps_and_failed_tool_calls():
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    state.tool_calls = [
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="observe.fetch_service_logs",
            state=StateName.EVIDENCE_COLLECTION,
            duration_ms=12,
            input_hash="in",
            output_hash="out",
            success=False,
            error_kind="retryable",
            error_message="provider failure Authorization: Bearer dd-secret-token",
            subagent_context_id="subagent-payment",
        ),
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="repo.get_deploy_history",
            state=StateName.TRIAGE,
            duration_ms=7,
            input_hash="in",
            output_hash="out",
            success=True,
        ),
    ]
    state.evidence = [
        Evidence(
            source="observe.fetch_service_logs",
            time_window="now-30m",
            affected_service="payment-service",
            claim="evidence gap: observe.fetch_service_logs failed with retryable token=dd-secret-token",
            provenance="live:observe.fetch_service_logs:failure",
        ),
        Evidence(
            source="repo.get_deploy_history",
            time_window="live",
            affected_service="payment-service",
            claim="GitHub deployments returned ids",
            provenance="live::repo.get_deploy_history",
        ),
    ]
    app.state.store.save_state(state)

    response = TestClient(app).get(f"/investigations/{state.id}", headers=_api_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["evidence_gaps"] == [
        {
            "source": "observe.fetch_service_logs",
            "affected_service": "payment-service",
            "time_window": "now-30m",
            "claim": "evidence gap: observe.fetch_service_logs failed with retryable token=[redacted]",
            "provenance": "live:observe.fetch_service_logs:failure",
        }
    ]
    assert body["failed_tool_calls"] == [
        {
            "tool_name": "observe.fetch_service_logs",
            "state": "evidence_collection",
            "error_kind": "retryable",
            "error_message": "provider failure Authorization: [redacted]",
            "subagent_context_id": "subagent-payment",
        }
    ]


def test_received_investigation_creation_returns_existing_when_idempotency_reservation_loses_race():
    app = create_app(_stub_live_settings())
    existing = InvestigationState(
        id="inv-existing",
        incident_id="PD-LIVE-1",
        scenario_name="live",
        affected_services=["payment-service"],
        service_priority=["payment-service"],
    )
    app.state.store.save_state(existing)
    app.state.store.remember_idempotency_key(
        _webhook_idempotency_key("pagerduty", "PD-LIVE-1"),
        "webhook",
        existing.id,
    )

    state, created = _create_received_investigation(
        app.state.store,
        {"event": {"data": {"incident": {"id": "PD-LIVE-1"}}}},
        "PD-LIVE-1",
        ["payment-service"],
    )

    assert created is False
    assert state.id == existing.id
    assert app.state.store.count_rows("investigations") == 1
    assert app.state.store.count_rows("idempotency_keys") == 1


def test_approval_endpoint_resumes_waiting_investigation_without_freeform_slack(monkeypatch):
    captured = {}

    def no_live_network_resume(settings, investigation_id, approval_command, store=None):
        captured["approval_command"] = approval_command
        state = store.load_state(investigation_id)
        state.approval_command = approval_command
        state.status = InvestigationStatus.COMPLETED
        state.current_state = StateName.POST_MORTEM
        store.save_state(state)
        return state

    monkeypatch.setattr(
        "sentinel.webapp._resume_live_investigation_with_approval",
        no_live_network_resume,
    )
    settings = _stub_live_settings()
    app = create_app(settings)
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
        headers=_api_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["approval_request_id"] == state.approval_request.id
    assert body["approval_command_received"] is True
    assert body["approval_command_request_id"] == state.approval_request.id
    assert body["approval_command_approver_id"] == "eng-oncall"
    assert body["approval_command_decision"] == "approve"
    assert captured["approval_command"].request_id == state.approval_request.id
    assert captured["approval_command"].idempotency_key.startswith(
        f"{state.id}:approval-command:{state.approval_request.id}:eng-oncall:approve"
    )


def test_approval_endpoint_rejects_missing_operator_token_before_resume(monkeypatch):
    captured = []

    def no_live_network_resume(settings, investigation_id, approval_command, store=None):
        captured.append(approval_command)
        return store.load_state(investigation_id)

    monkeypatch.setattr(
        "sentinel.webapp._resume_live_investigation_with_approval",
        no_live_network_resume,
    )
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
    )

    assert response.status_code == 401
    assert captured == []
    assert app.state.store.load_state(state.id).status == InvestigationStatus.WAITING_FOR_APPROVAL


def test_approval_endpoint_rejects_unready_runtime_before_resume(monkeypatch):
    captured = []

    class UnreachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return False

    def no_live_network_resume(settings, investigation_id, approval_command, store=None):
        captured.append(approval_command)
        return store.load_state(investigation_id)

    monkeypatch.setattr("sentinel.webapp.RedisRateLimitBackend", UnreachableRedis)
    monkeypatch.setattr(
        "sentinel.webapp._resume_live_investigation_with_approval",
        no_live_network_resume,
    )
    settings = _stub_live_settings(redis_url="redis://localhost:6379/9")
    app = create_app(settings)
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
        headers=_api_headers(),
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["ready"] is False
    assert detail["redis_reachable"] is False
    assert app.state.store.load_state(state.id).status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert captured == []


def test_approval_endpoint_rejects_failed_provider_preflight_before_resume(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    captured = []

    monkeypatch.setattr(
        "sentinel.webapp.run_live_connectivity_checks",
        lambda settings, store: _failed_provider_preflight_report(),
    )
    monkeypatch.setattr(
        "sentinel.webapp._resume_live_investigation_with_approval",
        lambda *args, **kwargs: captured.append((args, kwargs)),
    )
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
        headers=_api_headers(),
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["provider_preflight_ready"] is False
    assert detail["checks"][0]["provider"] == "datadog"
    assert app.state.store.load_state(state.id).status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert captured == []


def test_approval_endpoint_allows_data_dependent_loki_trace_gap_before_resume(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    captured = []

    monkeypatch.setattr(
        "sentinel.webapp.run_live_connectivity_checks",
        lambda settings, store: ConnectivityReport(
            ready=False,
            missing_live_credentials=[],
            checks=[
                ConnectivityCheck(
                    name="loki.logs",
                    provider="loki",
                    passed=True,
                    duration_ms=12.0,
                    detail="ok",
                    sample={"events": {"count": 1}},
                ),
                ConnectivityCheck(
                    name="loki.apm_traces",
                    provider="loki",
                    passed=False,
                    duration_ms=12.0,
                    detail="response field 'events' must contain at least one provider record",
                ),
            ],
        ),
    )

    def resume_without_live_network(settings, investigation_id, approval_command, store=None):
        captured.append((investigation_id, approval_command))
        return store.load_state(investigation_id)

    monkeypatch.setattr("sentinel.webapp._resume_live_investigation_with_approval", resume_without_live_network)
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
        headers=_api_headers(),
    )

    assert response.status_code == 200
    assert captured


def test_approval_endpoint_preserves_stored_datadog_oauth_for_live_refresh(monkeypatch):
    captured = []

    def no_live_network_resume(settings, investigation_id, approval_command, store=None):
        captured.append(settings)
        return store.load_state(investigation_id)

    monkeypatch.setattr(
        "sentinel.webapp._resume_live_investigation_with_approval",
        no_live_network_resume,
    )
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id="dd-client",
        datadog_client_secret="dd-secret",
        datadog_redirect_uri="http://localhost:8000/oauth/datadog/callback",
    )
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh-token",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": "2000-01-01T00:00:00+00:00",
        },
    )
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
        headers=_api_headers(),
    )

    assert response.status_code == 200
    assert captured
    assert captured[0].datadog_oauth_token is None
    assert captured[0].datadog_api_key is None
    assert captured[0].datadog_app_key is None


def test_approval_endpoint_redacts_live_tool_failure(monkeypatch):
    def fail_resume(settings, investigation_id, approval_command, store=None):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Slack rejected Authorization: Bearer xoxb-secret-token client_secret=slack-secret-token",
            retryable=False,
        )

    monkeypatch.setattr(
        "sentinel.webapp._resume_live_investigation_with_approval",
        fail_resume,
    )
    app = create_app(_stub_live_settings())
    state = _waiting_approval_state()
    app.state.store.save_state(state)

    response = TestClient(app).post(
        f"/investigations/{state.id}/approval",
        json={
            "request_id": state.approval_request.id,
            "approver_id": "eng-oncall",
            "decision": "approve",
        },
        headers=_api_headers(),
    )

    assert response.status_code == 502
    rendered = json.dumps(response.json())
    assert "xoxb-secret-token" not in rendered
    assert "slack-secret-token" not in rendered
    assert "[redacted]" in rendered
    assert app.state.store.load_state(state.id).status == InvestigationStatus.WAITING_FOR_APPROVAL


def test_live_run_endpoint_redacts_live_tool_failure(monkeypatch):
    def fail_run(settings, payload, incident_id, services=None, investigation_id=None, store=None):
        raise ToolExecutionError(
            ToolErrorKind.RETRYABLE,
            "Datadog rejected Authorization: Bearer dd-secret-token api_key=dd-secret-key",
            retryable=True,
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation", fail_run)
    app = create_app(_stub_live_settings())

    response = TestClient(app).post(
        "/live/run/PD-LIVE-FAIL",
        headers=_api_headers(),
        json={"service": "payment-service"},
    )

    assert response.status_code == 503
    rendered = json.dumps(response.json())
    assert "dd-secret-token" not in rendered
    assert "dd-secret-key" not in rendered
    assert "[redacted]" in rendered


def test_live_run_endpoint_rejects_failed_provider_preflight_before_run(monkeypatch):
    _make_production_infra_reachable(monkeypatch)
    captured = []

    monkeypatch.setattr(
        "sentinel.webapp.run_live_connectivity_checks",
        lambda settings, store: _failed_provider_preflight_report(),
    )
    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation",
        lambda *args, **kwargs: captured.append((args, kwargs)),
    )
    settings = _stub_live_settings(
        environment="production",
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )
    app = create_app(settings)

    response = TestClient(app).post(
        "/live/run/PD-LIVE-PREFLIGHT",
        headers=_api_headers(),
        json={"service": "payment-service"},
    )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["provider_preflight_ready"] is False
    assert detail["checks"][0]["detail"] == "Datadog unavailable"
    assert captured == []


def test_live_run_endpoint_passes_explicit_affected_services(monkeypatch):
    captured = []

    def no_live_network_run(settings, payload, incident_id, services=None, investigation_id=None, store=None):
        captured.append({"payload": payload, "incident_id": incident_id, "services": services})
        state = InvestigationState(
            id="inv-live-run-services",
            incident_id=incident_id,
            scenario_name="live",
            affected_services=services or [],
        )
        state.evidence = [
            Evidence(
                source="repo.get_deploy_history",
                time_window="live",
                affected_service="checkout-service",
                claim="GitHub deployments returned ids",
                provenance="live::repo.get_deploy_history",
            )
        ]
        return state

    monkeypatch.setattr("sentinel.webapp._run_live_investigation", no_live_network_run)
    settings = _stub_live_settings(
        default_service="fallback-service",
        service_aliases={"Checkout PagerDuty Service": "checkout-service"},
    )

    response = TestClient(create_app(settings)).post(
        "/live/run/PD-LIVE-SERVICES",
        headers=_api_headers(),
        json={
            "affected_services": [
                "Checkout PagerDuty Service",
                {"summary": "billing-service"},
                "checkout-service",
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["investigation_id"] == "inv-live-run-services"
    assert body["incident_id"] == "PD-LIVE-SERVICES"
    assert body["live_provider_proofs"]["github"] == 1
    assert body["evidence_gaps"] == []
    assert body["failed_tool_calls"] == []
    assert captured == [
        {
            "payload": {
                "affected_services": [
                    "Checkout PagerDuty Service",
                    {"summary": "billing-service"},
                    "checkout-service",
                ]
            },
            "incident_id": "PD-LIVE-SERVICES",
            "services": ["checkout-service", "billing-service"],
        }
    ]


def test_live_run_endpoint_rejects_malformed_explicit_services(monkeypatch):
    captured = []
    monkeypatch.setattr(
        "sentinel.webapp._run_live_investigation",
        lambda *args, **kwargs: captured.append((args, kwargs)),
    )

    response = TestClient(create_app(_stub_live_settings())).post(
        "/live/run/PD-LIVE-BAD-SERVICES",
        headers=_api_headers(),
        json={"affected_services": "checkout-service"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "affected_services must be a non-empty list"
    assert captured == []


def test_live_run_endpoint_preserves_stored_datadog_oauth_for_live_refresh(monkeypatch):
    captured = []

    def no_live_network_run(settings, payload, incident_id, services=None, investigation_id=None, store=None):
        captured.append(settings)
        return InvestigationState(
            id="inv-live-run-oauth",
            incident_id=incident_id,
            scenario_name="live",
        )

    monkeypatch.setattr("sentinel.webapp._run_live_investigation", no_live_network_run)
    settings = _stub_live_settings(
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id="dd-client",
        datadog_client_secret="dd-secret",
        datadog_redirect_uri="http://localhost:8000/oauth/datadog/callback",
    )
    app = create_app(settings)
    app.state.store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh-token",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": "2000-01-01T00:00:00+00:00",
        },
    )

    response = TestClient(app).post(
        "/live/run/PD-LIVE-OAUTH",
        headers=_api_headers(),
        json={"service": "payment-service"},
    )

    assert response.status_code == 200
    assert captured
    assert captured[0].datadog_oauth_token is None
    assert captured[0].datadog_api_key is None
    assert captured[0].datadog_app_key is None


def test_pagerduty_v3_incident_payload_extracts_event_data_id_and_service():
    payload = {
        "event": {
            "event_type": "incident.triggered",
            "data": {
                "id": "PD-V3-INCIDENT",
                "type": "incident",
                "service": {"summary": "checkout-service"},
            },
        }
    }

    assert _extract_incident_id(payload) == "PD-V3-INCIDENT"
    assert _extract_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "checkout-service"
    ]


def test_settings_parse_service_aliases_from_json_env(monkeypatch):
    monkeypatch.setenv(
        "SENTINEL_SERVICE_ALIASES",
        json.dumps({"Checkout PagerDuty Service": "checkout-service", "PABC123": "checkout-service"}),
    )

    settings = SentinelSettings.from_env()

    assert settings.service_aliases == {
        "Checkout PagerDuty Service": "checkout-service",
        "PABC123": "checkout-service",
    }
    assert settings.resolve_service_alias("checkout pagerduty service") == "checkout-service"
    assert settings.resolve_service_alias("unknown-service") == "unknown-service"


def test_settings_parse_positive_runtime_limits_from_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_KUBECTL_TIMEOUT_SECONDS", "7.5")
    monkeypatch.setenv("SENTINEL_LIVE_MAX_PAGES", "9")

    settings = SentinelSettings.from_env()

    assert settings.kubectl_timeout_seconds == 7.5
    assert settings.live_max_pages == 9


def test_settings_github_write_enabled_requires_explicit_boolean_env(monkeypatch):
    settings = SentinelSettings.from_env()
    assert settings.github_write_enabled is False

    monkeypatch.setenv("SENTINEL_GITHUB_WRITE_ENABLED", "true")
    settings = SentinelSettings.from_env()
    assert settings.github_write_enabled is True

    monkeypatch.setenv("SENTINEL_GITHUB_WRITE_ENABLED", "0")
    settings = SentinelSettings.from_env()
    assert settings.github_write_enabled is False

    monkeypatch.setenv("SENTINEL_GITHUB_WRITE_ENABLED", "maybe")
    with pytest.raises(ValueError, match="SENTINEL_GITHUB_WRITE_ENABLED must be a boolean"):
        SentinelSettings.from_env()


def test_settings_runtime_limits_use_defaults_for_blank_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_KUBECTL_TIMEOUT_SECONDS", " ")
    monkeypatch.setenv("SENTINEL_LIVE_MAX_PAGES", "")

    settings = SentinelSettings.from_env()

    assert settings.kubectl_timeout_seconds == 20.0
    assert settings.live_max_pages == 25


def test_settings_normalize_runtime_environment_for_production_guards(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", " production ")

    settings = SentinelSettings.from_env()

    assert settings.runtime_environment == "production"
    assert settings.api_auth_required is True
    assert settings.webhook_signature_required is True
    assert settings.production_infrastructure_required is True
    missing = settings.missing_live_credentials()
    assert "SENTINEL_API_TOKEN" in missing
    assert "SENTINEL_APPROVER_ID" in missing
    assert "DATABASE_URL" in missing
    assert "REDIS_URL" in missing


def test_settings_blank_runtime_environment_defaults_to_production(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", " ")

    settings = SentinelSettings.from_env()

    assert settings.runtime_environment == "production"
    assert settings.api_auth_required is True
    assert "SENTINEL_API_TOKEN" in settings.missing_live_credentials()


def test_settings_normalize_development_environment(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", " Development ")

    settings = SentinelSettings.from_env()

    assert settings.runtime_environment == "development"
    assert settings.api_auth_required is False
    assert settings.webhook_signature_required is False
    assert settings.production_infrastructure_required is False


def test_settings_strip_env_text_and_treat_blank_secrets_as_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in [
        "DD_API_KEY",
        "DD_APP_KEY",
        "DATADOG_APP_KEY",
        "DD_OAUTH_TOKEN",
        "PROMETHEUS_URL",
        "LOKI_URL",
        "GITHUB_TOKEN",
        "GITHUB_OWNER",
        "GITHUB_REPO",
        "PAGERDUTY_API_KEY",
        "SLACK_BOT_TOKEN",
        "SLACK_CHANNEL_ID",
        "DISCORD_WEBHOOK_URL",
        "SENTINEL_API_TOKEN",
        "PAGERDUTY_WEBHOOK_SECRET",
        "SENTINEL_APPROVER_ID",
        "DATABASE_URL",
        "REDIS_URL",
        "KUBECONFIG",
    ]:
        monkeypatch.setenv(name, " ")
    monkeypatch.setenv("DD_SITE", " ")
    monkeypatch.setenv("KUBERNETES_NAMESPACE", " ")
    monkeypatch.setenv("SENTINEL_DEFAULT_SERVICE", " ")

    settings = SentinelSettings.from_env()

    assert settings.datadog_api_key is None
    assert settings.datadog_app_key is None
    assert settings.github_token is None
    assert settings.github_owner is None
    assert settings.github_repo is None
    assert settings.pagerduty_api_key is None
    assert settings.slack_bot_token is None
    assert settings.slack_channel_id is None
    assert settings.api_token is None
    assert settings.pagerduty_webhook_secret is None
    assert settings.database_url is None
    assert settings.redis_url is None
    assert settings.kubeconfig is None
    assert settings.datadog_site == "datadoghq.com"
    assert settings.kubernetes_namespace == "default"
    assert settings.default_service == "payment-service"
    missing = settings.missing_live_credentials()
    for name in [
        "DD_API_KEY",
        "DD_APP_KEY",
        "PROMETHEUS_URL",
        "LOKI_URL",
        "GITHUB_TOKEN",
        "GITHUB_OWNER",
        "GITHUB_REPO",
        "SENTINEL_APPROVER_ID",
        "SLACK_BOT_TOKEN",
        "DISCORD_WEBHOOK_URL",
        "SENTINEL_API_TOKEN",
        "DATABASE_URL",
        "REDIS_URL",
        "KUBECONFIG",
    ]:
        assert name in missing


def test_settings_strip_env_text_values(monkeypatch):
    monkeypatch.setenv("GITHUB_OWNER", " acme ")
    monkeypatch.setenv("GITHUB_REPO", " checkout ")
    monkeypatch.setenv("SENTINEL_API_TOKEN", " sentinel-token ")
    monkeypatch.setenv("DATABASE_URL", " postgresql://sentinel:sentinel@db/sentinel ")
    monkeypatch.setenv("REDIS_URL", " redis://redis:6379/0 ")

    settings = SentinelSettings.from_env()

    assert settings.github_owner == "acme"
    assert settings.github_repo == "checkout"
    assert settings.api_token == "sentinel-token"
    assert settings.database_url == "postgresql://sentinel:sentinel@db/sentinel"
    assert settings.redis_url == "redis://redis:6379/0"


def test_settings_reject_invalid_runtime_limits(monkeypatch):
    monkeypatch.setenv("SENTINEL_KUBECTL_TIMEOUT_SECONDS", "nan")

    try:
        SentinelSettings.from_env()
    except ValueError as exc:
        assert "SENTINEL_KUBECTL_TIMEOUT_SECONDS" in str(exc)
    else:
        raise AssertionError("expected invalid kubectl timeout to fail fast")

    monkeypatch.setenv("SENTINEL_KUBECTL_TIMEOUT_SECONDS", "20")
    monkeypatch.setenv("SENTINEL_LIVE_MAX_PAGES", "0")

    try:
        SentinelSettings.from_env()
    except ValueError as exc:
        assert "SENTINEL_LIVE_MAX_PAGES" in str(exc)
    else:
        raise AssertionError("expected invalid live page limit to fail fast")


def test_pagerduty_service_summary_alias_maps_to_operational_service():
    payload = {
        "event": {
            "event_type": "incident.triggered",
            "data": {
                "id": "PD-V3-ALIAS",
                "type": "incident",
                "service": {"summary": "Checkout PagerDuty Service"},
            },
        }
    }

    assert _extract_services(
        payload,
        _stub_live_settings(
            default_service="fallback-service",
            service_aliases={"Checkout PagerDuty Service": "checkout-service"},
        ),
    ) == ["checkout-service"]


def test_pagerduty_service_id_alias_maps_even_when_summary_is_human_facing():
    payload = {
        "event": {
            "event_type": "incident.triggered",
            "data": {
                "id": "PD-V3-ID-ALIAS",
                "type": "incident",
                "service": {
                    "id": "PABC123",
                    "summary": "Checkout PagerDuty Service",
                },
            },
        }
    }

    assert _extract_services(
        payload,
        _stub_live_settings(
            default_service="fallback-service",
            service_aliases={"PABC123": "checkout-service"},
        ),
    ) == ["checkout-service"]


def test_pagerduty_v3_event_array_extracts_bare_event_object():
    payload = {
        "events": [
            {
                "event_type": "incident.triggered",
                "resource_type": "incident",
                "data": {
                    "id": "PD-V3-EVENTS",
                    "status": "triggered",
                    "service": {"name": "checkout-api"},
                },
            }
        ]
    }

    assert _extract_incident_id(payload) == "PD-V3-EVENTS"
    assert _extract_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "checkout-api"
    ]


def test_pagerduty_v3_incident_payload_without_type_uses_incident_event_shape():
    payload = {
        "event": {
            "event_type": "incident.triggered",
            "data": {
                "id": "PD-V3-NO-TYPE",
                "status": "triggered",
                "title": "Checkout latency is high",
                "service": "checkout-service",
            },
        }
    }

    assert _extract_incident_id(payload) == "PD-V3-NO-TYPE"
    assert _extract_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "checkout-service"
    ]


def test_pagerduty_v3_nested_incident_payload_extracts_event_data_incident_id():
    payload = {
        "event": {
            "event_type": "incident.annotated",
            "data": {
                "id": "NOTE-1",
                "type": "incident_note",
                "incident": {
                    "id": "PD-V3-NESTED",
                    "service": {"summary": "payments-api"},
                },
            },
        }
    }

    assert _extract_incident_id(payload) == "PD-V3-NESTED"
    assert _extract_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "payments-api"
    ]


def test_pagerduty_service_resource_event_is_not_treated_as_incident():
    payload = {
        "event": {
            "event_type": "service.updated",
            "resource_type": "service",
            "data": {
                "id": "PD-SERVICE-1",
                "type": "service",
                "summary": "Checkout PagerDuty Service",
            },
        }
    }

    assert _extract_incident_id(payload) is None
    assert _extract_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "fallback-service"
    ]


def test_pagerduty_batched_messages_extract_incident_and_deduped_services():
    payload = {
        "messages": [
            {
                "incident": {
                    "id": "PD-V2-1",
                    "service": {"summary": "checkout-service"},
                }
            },
            {
                "incident": {
                    "id": "PD-V2-1",
                    "service": {"summary": "checkout-service"},
                }
            },
            {
                "incident": {
                    "id": "PD-V2-1",
                    "service": {"summary": "payment-service"},
                }
            },
        ]
    }

    assert _extract_incident_id(payload) == "PD-V2-1"
    assert _extract_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "checkout-service",
        "payment-service",
    ]


def test_generic_webhook_extracts_nested_alert_identity_and_services():
    payload = {
        "alert": {
            "fingerprint": "alert-fp-123",
            "labels": {
                "service": "payment-service",
                "app": "checkout-api",
            },
        },
        "services": ["payment-service", "checkout-api"],
    }

    assert _extract_generic_incident_id(payload) == "alert-fp-123"
    assert _extract_generic_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "payment-service",
        "checkout-api",
    ]


def test_generic_webhook_extracts_alertmanager_grouped_alert_identity_and_services():
    payload = {
        "receiver": "sentinel",
        "groupKey": "alertmanager-group-123",
        "commonLabels": {
            "service": "checkout-service",
            "severity": "critical",
        },
        "groupLabels": {
            "app": "payments-api",
        },
        "alerts": [
            {
                "fingerprint": "am-fp-1",
                "labels": {"service": "checkout-service"},
            },
            {
                "fingerprint": "am-fp-2",
                "labels": {"service": "billing-service"},
            },
        ],
    }

    assert _extract_generic_incident_id(payload) == "am-fp-1"
    assert _extract_generic_services(payload, _stub_live_settings(default_service="fallback-service")) == [
        "checkout-service",
        "payments-api",
        "billing-service",
    ]


def test_generic_webhook_request_schema_preserves_alert_payload_and_defaults_source():
    request = GenericWebhookRequest.model_validate(
        {
            "alert_id": "FREE-ALERT-1",
            "source": " ",
            "labels": {"service": "payment-service"},
            "custom": {"severity": "critical"},
        }
    )

    payload = request.normalized_payload()

    assert payload == {
        "alert_id": "FREE-ALERT-1",
        "source": "generic_webhook",
        "labels": {"service": "payment-service"},
        "custom": {"severity": "critical"},
    }
    assert GenericWebhookRequest.model_validate(
        {"incident_id": "FREE-ALERT-2", "source": " alertmanager "}
    ).normalized_payload()["source"] == "alertmanager"


def _stub_live_settings(**overrides):
    base = SentinelSettings.from_env()
    values = {
        "datadog_api_key": "dd-api",
        "datadog_app_key": "dd-app",
        "github_token": "gh-token",
        "github_owner": "owner",
        "github_repo": "repo",
        "pagerduty_api_key": "pd-api",
        "pagerduty_requester_email": "oncall@example.com",
        "api_token": "sentinel-api-token",
        "pagerduty_webhook_secret": "pd-secret",
        "slack_bot_token": "xoxb-token",
        "slack_channel_id": "C123",
        "kubeconfig": __file__,
        "database_url": None,
        "redis_url": None,
        "environment": "development",
        **overrides,
    }
    return replace(base, **values)


def _api_headers(token: str = "sentinel-api-token") -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _redirect_state(response) -> str:
    location = response.headers["location"]
    values = parse_qs(urlparse(location).query)
    state = values.get("state")
    assert state
    return state[0]


def _raw_webhook_body() -> bytes:
    payload = {
        "event": {
            "data": {
                "incident": {
                    "id": "PD-LIVE-1",
                    "service": {"summary": "payment-service"},
                }
            }
        }
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _signature(raw: bytes, secret: str) -> str:
    return pagerduty_signature_header(raw, secret)


class _ClosableRateLimitBackend:
    def __init__(self):
        self.close_count = 0

    def hit(self, key, *, limit, window_seconds):
        return True

    def close(self):
        self.close_count += 1


def _make_production_infra_reachable(monkeypatch):
    class ReachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return True

        def close(self):
            return None

    monkeypatch.setattr("sentinel.webapp.build_store", lambda database_url: SQLiteInvestigationStore())
    monkeypatch.setattr("sentinel.webapp.RedisRateLimitBackend", ReachableRedis)


def _failed_provider_preflight_report() -> ConnectivityReport:
    return ConnectivityReport(
        ready=False,
        missing_live_credentials=[],
        checks=[
            ConnectivityCheck(
                name="datadog.logs",
                provider="datadog",
                passed=False,
                duration_ms=12.0,
                detail="Datadog unavailable",
            )
        ],
    )


def _waiting_approval_state() -> InvestigationState:
    recommendation = Recommendation(
        remediation_type="rollback",
        affected_service="payment-service",
        command="rollback payment-service to v2.3.1",
        evidence_summary="Reconciled evidence points to a bad deploy.",
        risk="Requires human approval.",
        rollback_plan="Restore payment-service to v2.3.1.",
    )
    state = InvestigationState(
        id="inv-waiting-approval",
        incident_id="PD-LIVE-1",
        scenario_name="live",
        current_state=StateName.RESPONSE_PROPOSAL,
        status=InvestigationStatus.WAITING_FOR_APPROVAL,
        affected_services=["payment-service"],
        service_priority=["payment-service"],
        recommendation=recommendation,
    )
    state.approval_request = ApprovalRequest(
        incident_id=state.incident_id,
        remediation=recommendation,
        approver_ids=["eng-oncall"],
        approval_snapshot={"diagnosis": "Reconciled evidence points to a bad deploy."},
        idempotency_key=f"{state.id}:approval:rollback-payment-service",
    )
    return state
