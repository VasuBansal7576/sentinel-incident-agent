import json
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from sentinel.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState, reset_shared_circuit_breakers
from sentinel.config import SentinelSettings
from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.live_clients import (
    DatadogClient,
    DiscordWebhookClient,
    GitHubClient,
    LiveApiClient,
    LiveProviderClients,
    LokiClient,
    PagerDutyClient,
    PrometheusClient,
    SlackClient,
    _extract_next_link,
    _github_check_run_url_matches,
    _github_commit_url_matches,
    _github_deployment_status_url_matches,
    _github_deployment_url_matches,
    _github_issue_url_matches,
    _github_pull_request_file_url_matches,
    _github_pull_request_url_matches,
    _github_repo_url_matches,
)
from sentinel.oauth import OAuthManager, pagerduty_signature_header, verify_pagerduty_signature


def test_pagerduty_signature_verification_accepts_v3_header_format_only():
    body = b'{"event":{"data":{"incident":{"id":"PD-1"}}}}'
    secret = "pd-secret"
    valid = pagerduty_signature_header(body, secret)
    other = pagerduty_signature_header(body, "rotated-secret")

    assert verify_pagerduty_signature(body, valid, secret)
    assert verify_pagerduty_signature(body, f"{other},{valid}", secret)
    assert not verify_pagerduty_signature(body, valid.removeprefix("v1="), secret)
    assert not verify_pagerduty_signature(body, f"sha256={valid.removeprefix('v1=')}", secret)
    assert not verify_pagerduty_signature(body, f"v2={valid.removeprefix('v1=')}", secret)
    assert not verify_pagerduty_signature(body, "bad-signature", secret)
    assert not verify_pagerduty_signature(body, None, secret)


def test_pagerduty_signature_verification_accepts_previous_secret_during_rotation():
    body = b'{"event":{"data":{"incident":{"id":"PD-1"}}}}'
    current = "pd-current"
    previous = "pd-previous"
    previous_header = pagerduty_signature_header(body, previous)
    unknown_header = pagerduty_signature_header(body, "pd-unknown")

    assert verify_pagerduty_signature(body, previous_header, current, previous)
    assert not verify_pagerduty_signature(body, unknown_header, current, previous)


def test_oauth_state_is_signed_provider_scoped_and_tamper_resistant():
    settings = SentinelSettings.from_env()
    manager = OAuthManager(
        settings.__class__(
            **{
                **settings.__dict__,
                "pagerduty_webhook_secret": "state-secret",
            }
        )
    )
    state = manager.issue_state("slack")

    decoded = manager.verify_state(state, "slack")
    assert decoded.provider == "slack"

    with pytest.raises(Exception):
        manager.verify_state(state, "github")
    with pytest.raises(Exception):
        manager.verify_state(state[:-2] + "xx", "slack")


def test_oauth_state_secret_is_required_in_production():
    settings = replace(
        SentinelSettings.from_env(),
        environment="production",
        oauth_state_secret=None,
        pagerduty_webhook_secret=None,
        slack_client_secret=None,
        github_client_secret=None,
        datadog_client_secret=None,
    )

    with pytest.raises(ToolExecutionError) as exc:
        OAuthManager(settings)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "SENTINEL_OAUTH_STATE_SECRET" in str(exc.value)


def test_oauth_state_secret_uses_normalized_production_environment():
    settings = replace(
        SentinelSettings.from_env(),
        environment=" production ",
        oauth_state_secret=None,
        pagerduty_webhook_secret=None,
        slack_client_secret=None,
        github_client_secret=None,
        datadog_client_secret=None,
    )

    with pytest.raises(ToolExecutionError) as exc:
        OAuthManager(settings)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "SENTINEL_OAUTH_STATE_SECRET" in str(exc.value)


def test_oauth_state_secret_rejects_whitespace_only_secret_candidates():
    settings = replace(
        SentinelSettings.from_env(),
        environment="production",
        oauth_state_secret=" ",
        pagerduty_webhook_secret=" ",
        slack_client_secret=" ",
        github_client_secret=" ",
        datadog_client_secret=" ",
    )

    with pytest.raises(ToolExecutionError) as exc:
        OAuthManager(settings)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "SENTINEL_OAUTH_STATE_SECRET" in str(exc.value)


def test_oauth_state_dev_fallback_is_not_used_in_production():
    settings = replace(
        SentinelSettings.from_env(),
        environment="development",
        oauth_state_secret=None,
        pagerduty_webhook_secret=None,
        slack_client_secret=None,
        github_client_secret=None,
        datadog_client_secret=None,
    )

    manager = OAuthManager(settings)
    state = manager.issue_state("github")

    assert manager.verify_state(state, "github").provider == "github"


def test_oauth_state_dev_fallback_accepts_normalized_development_environment():
    settings = replace(
        SentinelSettings.from_env(),
        environment=" development ",
        oauth_state_secret=None,
        pagerduty_webhook_secret=None,
        slack_client_secret=None,
        github_client_secret=None,
        datadog_client_secret=None,
    )

    manager = OAuthManager(settings)
    state = manager.issue_state("github")

    assert manager.verify_state(state, "github").provider == "github"


def test_discord_webhook_client_posts_content_without_bot_token_or_auth_header():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"id": "discord-message-1"})

    client = DiscordWebhookClient(
        replace(
            SentinelSettings.from_env(),
            discord_webhook_url="https://discord.com/api/webhooks/123/secret-token",
        )
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))
    try:
        result = client.post_to_discord(" SENTINEL is investigating. ")
    finally:
        client.close()

    assert result == {
        "ok": True,
        "id": "discord-message-1",
        "provider": "discord",
        "content": "SENTINEL is investigating.",
    }
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "POST"
    assert str(request.url) == "https://discord.com/api/webhooks/123/secret-token?wait=true"
    assert json.loads(request.content.decode()) == {"content": "SENTINEL is investigating."}
    assert "authorization" not in request.headers
    assert "x-slack-bot-token" not in request.headers
    assert "bot" not in request.headers


def test_discord_webhook_client_rejects_wait_response_without_message_id():
    client = _discord_client_with_responses([httpx.Response(200, json={"content": "SENTINEL is investigating."})])
    try:
        with pytest.raises(ToolExecutionError) as exc:
            client.post_to_discord("SENTINEL is investigating.")
    finally:
        client.close()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "missing confirmation field(s): id" in str(exc.value)


def test_discord_webhook_client_rejects_empty_wait_response():
    client = _discord_client_with_responses([httpx.Response(204)])
    try:
        with pytest.raises(ToolExecutionError) as exc:
            client.post_to_discord("SENTINEL is investigating.")
    finally:
        client.close()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "did not include a message body" in str(exc.value)


def test_discord_webhook_client_preserves_rate_limit_retry_after_without_opening_circuit():
    client = _discord_client_with_responses(
        [
            httpx.Response(429, json={"message": "rate limited"}, headers={"Retry-After": "1.5"}),
            httpx.Response(429, json={"message": "rate limited"}, headers={"Retry-After": "1.5"}),
        ],
        failure_threshold=1,
    )
    try:
        for _ in range(2):
            with pytest.raises(ToolExecutionError) as exc:
                client.post_to_discord("SENTINEL is investigating.")
            assert exc.value.kind == ToolErrorKind.RATE_LIMITED
            assert exc.value.retryable is True
            assert exc.value.retry_after_seconds == 1.5

        assert client.circuit_breaker.state == CircuitState.CLOSED
    finally:
        client.close()


def test_discord_webhook_client_opens_circuit_for_repeated_upstream_failures():
    client = _discord_client_with_responses(
        [
            httpx.Response(503, json={"message": "unavailable"}),
            httpx.Response(503, json={"message": "unavailable"}),
            httpx.Response(200, json={"id": "would-not-run"}),
        ],
        failure_threshold=2,
    )
    try:
        for _ in range(2):
            with pytest.raises(ToolExecutionError) as exc:
                client.post_to_discord("SENTINEL is investigating.")
            assert exc.value.kind == ToolErrorKind.RETRYABLE

        assert client.circuit_breaker.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            client.post_to_discord("SENTINEL is investigating.")
    finally:
        client.close()


def test_prometheus_client_query_range_uses_expected_endpoint_and_validates_results():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"service": "checkout-service"},
                            "values": [[1717425600, "1"]],
                        }
                    ]
                },
            },
        )

    client = _prometheus_client_with_handler(handler)
    try:
        result = client.query_range(
            'sum(rate(http_requests_total{service="checkout-service"}[5m]))',
            start_epoch=1717425600,
            end_epoch=1717425900,
            step="15s",
        )
    finally:
        client.api.client.close()

    assert result["query"] == 'sum(rate(http_requests_total{service="checkout-service"}[5m]))'
    assert result["result"] == [
        {
            "metric": {"service": "checkout-service"},
            "values": [[1717425600, "1"]],
        }
    ]
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v1/query_range"
    params = dict(request.url.params)
    assert params["query"] == 'sum(rate(http_requests_total{service="checkout-service"}[5m]))'
    assert params["start"] == "1717425600"
    assert params["end"] == "1717425900"
    assert params["step"] == "15s"


def test_prometheus_client_query_range_rejects_malformed_sample_points():
    client = _prometheus_client_with_handler(
        lambda _request: httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"service": "checkout-service"},
                            "values": [[1717425600]],
                        }
                    ]
                },
            },
        )
    )
    try:
        with pytest.raises(ToolExecutionError) as exc:
            client.query_range("up")
    finally:
        client.api.client.close()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "values[0]" in str(exc.value)
    assert "timestamp and sample value" in str(exc.value)


def test_prometheus_client_query_rejects_non_numeric_sample_values():
    client = _prometheus_client_with_handler(
        lambda _request: httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "metric": {"service": "checkout-service"},
                            "value": [1717425600, "not-a-number"],
                        }
                    ]
                },
            },
        )
    )
    try:
        with pytest.raises(ToolExecutionError) as exc:
            client.query("up")
    finally:
        client.api.client.close()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "value[1]" in str(exc.value)
    assert "numeric sample value" in str(exc.value)


def test_loki_client_query_range_uses_expected_endpoint_and_validates_streams():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {"service": "checkout-service"},
                            "values": [["1717425600000000000", "checkout trace"]],
                        }
                    ]
                },
            },
        )

    client = _loki_client_with_handler(handler)
    try:
        result = client.query_range(
            '{service="checkout-service"} |= "trace"',
            start_epoch=1717425600,
            end_epoch=1717425900,
            limit=10,
        )
    finally:
        client.api.client.close()

    assert result["query"] == '{service="checkout-service"} |= "trace"'
    assert result["events"] == [
        {
            "stream": {"service": "checkout-service"},
            "values": [["1717425600000000000", "checkout trace"]],
        }
    ]
    assert result["streams"] == result["events"]
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/loki/api/v1/query_range"
    params = dict(request.url.params)
    assert params["query"] == '{service="checkout-service"} |= "trace"'
    assert params["start"] == "1717425600000000000"
    assert params["end"] == "1717425900000000000"
    assert params["limit"] == "10"
    assert params["direction"] == "backward"


def test_loki_client_query_range_rejects_malformed_log_entries():
    client = _loki_client_with_handler(
        lambda _request: httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {"service": "checkout-service"},
                            "values": [["1717425600000000000"]],
                        }
                    ]
                },
            },
        )
    )
    try:
        with pytest.raises(ToolExecutionError) as exc:
            client.query_range('{service="checkout-service"}')
    finally:
        client.api.client.close()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "values[0]" in str(exc.value)
    assert "timestamp and line" in str(exc.value)


def test_loki_client_labels_accepts_real_list_data_response():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"status": "success", "data": ["service", "level", "source"]},
        )

    client = _loki_client_with_handler(handler)
    try:
        result = client.labels()
    finally:
        client.api.client.close()

    assert result == {"labels": ["service", "level", "source"]}
    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/loki/api/v1/labels"


def test_loki_client_labels_rejects_malformed_label_list_items():
    client = _loki_client_with_handler(
        lambda _request: httpx.Response(
            200,
            json={"status": "success", "data": ["service", 42]},
        )
    )
    try:
        with pytest.raises(ToolExecutionError) as exc:
            client.labels()
    finally:
        client.api.client.close()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "list of strings" in str(exc.value)


def test_prometheus_and_loki_malformed_success_responses_do_not_open_circuits():
    prometheus = _prometheus_client_with_handler(
        lambda _request: httpx.Response(
            200,
            json={"status": "success", "data": {"result": [{"values": [[1717425600, "1"]]}]}},
        ),
        failure_threshold=1,
    )
    loki = _loki_client_with_handler(
        lambda _request: httpx.Response(
            200,
            json={"status": "success", "data": {"result": [{"stream": {"service": "checkout-service"}}]}},
        ),
        failure_threshold=1,
    )
    try:
        with pytest.raises(ToolExecutionError) as prometheus_exc:
            prometheus.query_range("up")
        with pytest.raises(ToolExecutionError) as loki_exc:
            loki.query_range('{service="checkout-service"}')

        assert prometheus_exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert loki_exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert prometheus.api.circuit_breaker.state == CircuitState.CLOSED
        assert loki.api.circuit_breaker.state == CircuitState.CLOSED
    finally:
        prometheus.api.client.close()
        loki.api.client.close()


def test_prometheus_and_loki_open_circuits_for_upstream_failures():
    prometheus = _prometheus_client_with_handler(
        lambda _request: httpx.Response(503, json={"error": "prometheus unavailable"}),
        failure_threshold=2,
    )
    loki = _loki_client_with_handler(
        lambda _request: httpx.Response(503, json={"error": "loki unavailable"}),
        failure_threshold=2,
    )
    try:
        for _ in range(2):
            with pytest.raises(ToolExecutionError) as prometheus_exc:
                prometheus.query_range("up")
            with pytest.raises(ToolExecutionError) as loki_exc:
                loki.query_range('{service="checkout-service"}')
            assert prometheus_exc.value.kind == ToolErrorKind.RETRYABLE
            assert loki_exc.value.kind == ToolErrorKind.RETRYABLE

        assert prometheus.api.circuit_breaker.state == CircuitState.OPEN
        assert loki.api.circuit_breaker.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            prometheus.query_range("up")
        with pytest.raises(CircuitOpenError):
            loki.query_range('{service="checkout-service"}')
    finally:
        prometheus.api.client.close()
        loki.api.client.close()


def test_oauth_install_urls_require_callback_exchange_config():
    base = _oauth_manager().settings
    cases = [
        (
            replace(base, slack_client_secret=None),
            lambda manager: manager.slack_install_url(),
            "SLACK_CLIENT_SECRET",
        ),
        (
            replace(base, github_redirect_uri=None),
            lambda manager: manager.github_install_url(),
            "GITHUB_REDIRECT_URI",
        ),
        (
            replace(base, datadog_client_secret=None),
            lambda manager: manager.datadog_install_url(),
            "DD_CLIENT_SECRET",
        ),
    ]

    for settings, build_url, missing_name in cases:
        with pytest.raises(ToolExecutionError) as exc:
            build_url(OAuthManager(settings))

        assert exc.value.kind == ToolErrorKind.PERMANENT
        assert missing_name in str(exc.value)


def test_slack_install_url_requests_scopes_needed_by_live_channel_checks():
    manager = _oauth_manager()
    state = manager.issue_state("slack")

    url = manager.slack_install_url(state=state)
    params = parse_qs(urlparse(url).query)
    scopes = set(params["scope"][0].split(","))

    assert params["client_id"] == ["slack-client"]
    assert params["redirect_uri"] == ["http://localhost:8000/oauth/slack/callback"]
    assert params["state"] == [state]
    assert {
        "chat:write",
        "channels:read",
        "channels:manage",
        "groups:read",
        "groups:write",
    }.issubset(scopes)


def test_github_install_url_requests_scopes_needed_by_live_repository_checks():
    manager = _oauth_manager()
    state = manager.issue_state("github")

    url = manager.github_install_url(state=state)
    params = parse_qs(urlparse(url).query)
    scopes = set(params["scope"][0].split(","))

    assert params["client_id"] == ["github-client"]
    assert params["redirect_uri"] == ["http://localhost:8000/oauth/github/callback"]
    assert params["state"] == [state]
    assert {"repo", "read:org"}.issubset(scopes)


def test_slack_oauth_exchange_timeout_is_typed_retryable_error(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("slack")

    def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("slack timeout")

    monkeypatch.setattr("sentinel.oauth.httpx.post", timeout)

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_slack_code("code", state)

    assert exc.value.kind == ToolErrorKind.RETRYABLE
    assert exc.value.retryable is True
    assert "timed out" in str(exc.value)


def test_slack_oauth_exchange_requires_usable_access_token(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("slack")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(200, json={"ok": True, "team": {"id": "T1"}}),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_slack_code("code", state)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "access_token" in str(exc.value)


def test_slack_oauth_exchange_rejects_explicitly_insufficient_scopes(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("slack")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"ok": True, "access_token": "xoxb-oauth", "scope": "chat:write"},
        ),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_slack_code("code", state)

    assert exc.value.kind == ToolErrorKind.AUTHORIZATION
    assert "Slack OAuth token is missing required scope(s)" in str(exc.value)
    assert "channels:read" in str(exc.value)


def test_slack_oauth_exchange_rejects_malformed_scope_metadata(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("slack")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"ok": True, "access_token": "xoxb-oauth", "scope": ["chat:write"]},
        ),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_slack_code("code", state)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "Slack OAuth response field 'scope' must be a string" in str(exc.value)


def test_github_oauth_exchange_non_json_response_is_malformed_output(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("github")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(200, text="<html>not json</html>"),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_github_code("code", state)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.retryable is False
    assert "non-JSON" in str(exc.value)


def test_github_oauth_exchange_requires_non_empty_access_token(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("github")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(200, json={"access_token": "", "token_type": "bearer"}),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_github_code("code", state)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "access_token" in str(exc.value)


def test_github_oauth_exchange_rejects_explicitly_insufficient_scopes(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("github")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"access_token": "gh-oauth", "token_type": "bearer", "scope": "repo"},
        ),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_github_code("code", state)

    assert exc.value.kind == ToolErrorKind.AUTHORIZATION
    assert "GitHub OAuth token is missing required scope(s): read:org" in str(exc.value)


def test_github_oauth_exchange_rejects_malformed_scope_metadata(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("github")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"access_token": "gh-oauth", "token_type": "bearer", "scope": ["repo"]},
        ),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_github_code("code", state)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "GitHub OAuth response field 'scope' must be a string" in str(exc.value)


def test_datadog_oauth_install_uses_pkce_and_signed_state():
    manager = _oauth_manager()
    verifier = "verifier-123"
    state = manager.issue_state("datadog")

    url = manager.datadog_install_url(state=state, code_verifier=verifier)

    assert url.startswith("https://app.datadoghq.com/oauth2/v1/authorize?")
    assert "client_id=datadog-client" in url
    assert "response_type=code" in url
    assert "state=" in url
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert manager.verify_state(state, "datadog").provider == "datadog"


def test_datadog_oauth_install_uses_configured_site_app_host():
    base = _oauth_manager().settings
    manager = OAuthManager(replace(base, datadog_site="datadoghq.eu"))
    verifier = "verifier-123"
    state = manager.issue_state("datadog")

    url = manager.datadog_install_url(state=state, code_verifier=verifier)

    assert url.startswith("https://app.datadoghq.eu/oauth2/v1/authorize?")
    assert "client_id=datadog-client" in url
    assert "code_challenge_method=S256" in url
    assert manager.verify_state(state, "datadog").provider == "datadog"


def test_datadog_oauth_install_normalizes_api_or_app_site_config():
    base = _oauth_manager().settings
    api_manager = OAuthManager(replace(base, datadog_site="api.us5.datadoghq.com"))
    app_manager = OAuthManager(replace(base, datadog_site="https://app.datadoghq.eu/account/login"))

    api_url = api_manager.datadog_install_url(
        state=api_manager.issue_state("datadog"),
        code_verifier="verifier-123",
    )
    app_url = app_manager.datadog_install_url(
        state=app_manager.issue_state("datadog"),
        code_verifier="verifier-123",
    )

    assert api_url.startswith("https://app.us5.datadoghq.com/oauth2/v1/authorize?")
    assert app_url.startswith("https://app.datadoghq.eu/oauth2/v1/authorize?")


def test_datadog_oauth_rejects_unknown_configured_site_before_redirect():
    base = _oauth_manager().settings
    manager = OAuthManager(replace(base, datadog_site="https://evil.example"))

    with pytest.raises(ToolExecutionError) as exc:
        manager.datadog_install_url(
            state=manager.issue_state("datadog"),
            code_verifier="verifier-123",
        )

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "Datadog OAuth callback domain is not allowed" in str(exc.value)
    assert "evil.example" not in str(exc.value)


def test_datadog_oauth_rejects_unknown_callback_domain_before_token_exchange(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("datadog")
    called = False

    def post(*args, **kwargs):
        nonlocal called
        called = True
        return httpx.Response(200, json={"access_token": "dd-oauth"})

    monkeypatch.setattr("sentinel.oauth.httpx.post", post)

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_datadog_code(
            "code",
            state,
            code_verifier="verifier-123",
            domain="https://evil.example",
        )

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "Datadog OAuth callback domain is not allowed" in str(exc.value)
    assert "evil.example" not in str(exc.value)
    assert called is False


def test_datadog_oauth_exchange_posts_form_to_callback_domain_token_endpoint(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("datadog")
    captured = {}

    def post(url, **kwargs):
        captured["url"] = url
        captured["data"] = kwargs["data"]
        return httpx.Response(
            200,
            json={
                "access_token": "dd-oauth",
                "refresh_token": "dd-refresh",
                "token_type": "bearer",
                "scope": "logs_read_data metrics_read apm_read",
                "expires_in": 3600,
            },
        )

    monkeypatch.setattr("sentinel.oauth.httpx.post", post)

    payload = manager.exchange_datadog_code(
        "oauth-code",
        state,
        code_verifier="verifier-123",
        domain="datadoghq.eu",
    )

    assert captured["url"] == "https://api.datadoghq.eu/oauth2/v1/token"
    assert captured["data"]["grant_type"] == "authorization_code"
    assert captured["data"]["client_id"] == "datadog-client"
    assert captured["data"]["client_secret"] == "datadog-secret"
    assert captured["data"]["redirect_uri"] == "http://localhost:8000/oauth/datadog/callback"
    assert captured["data"]["code"] == "oauth-code"
    assert captured["data"]["code_verifier"] == "verifier-123"
    assert payload["access_token"] == "dd-oauth"
    assert payload["domain"] == "datadoghq.eu"


def test_datadog_oauth_exchange_rejects_explicitly_insufficient_scopes(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("datadog")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={
                "access_token": "dd-oauth",
                "refresh_token": "dd-refresh",
                "token_type": "bearer",
                "scope": "logs_read_data metrics_read",
            },
        ),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_datadog_code(
            "code",
            state,
            code_verifier="verifier-123",
            domain="datadoghq.com",
        )

    assert exc.value.kind == ToolErrorKind.AUTHORIZATION
    assert "apm_read" in str(exc.value)


def test_datadog_oauth_exchange_allows_response_without_scope_metadata(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("datadog")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={
                "access_token": "dd-oauth",
                "refresh_token": "dd-refresh",
                "token_type": "bearer",
            },
        ),
    )

    payload = manager.exchange_datadog_code(
        "code",
        state,
        code_verifier="verifier-123",
        domain="datadoghq.com",
    )

    assert payload["access_token"] == "dd-oauth"
    assert payload["domain"] == "datadoghq.com"


def test_datadog_oauth_exchange_rejects_untrusted_callback_domain(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("datadog")
    calls = []

    monkeypatch.setattr("sentinel.oauth.httpx.post", lambda *args, **kwargs: calls.append(args))

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_datadog_code(
            "oauth-code",
            state,
            code_verifier="verifier-123",
            domain="metadata.google.internal",
        )

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "not allowed" in str(exc.value)
    assert calls == []


def test_oauth_exchange_errors_redact_sensitive_response_text(monkeypatch):
    manager = _oauth_manager()
    state = manager.issue_state("github")

    monkeypatch.setattr(
        "sentinel.oauth.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            text="<html>client_secret=github-secret-token Authorization: Bearer ghp-secret-token</html>",
        ),
    )

    with pytest.raises(ToolExecutionError) as exc:
        manager.exchange_github_code("code", state)

    message = str(exc.value)
    assert "github-secret-token" not in message
    assert "ghp-secret-token" not in message
    assert "[redacted]" in message


def test_circuit_breaker_opens_after_threshold_and_blocks_calls():
    breaker = CircuitBreaker("unit", failure_threshold=2, recovery_seconds=1000)

    for _ in range(2):
        with pytest.raises(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("boom")))

    assert breaker.state == CircuitState.OPEN
    with pytest.raises(CircuitOpenError):
        breaker.call(lambda: "blocked")


def test_live_api_circuit_does_not_open_for_permanent_request_errors():
    client = LiveApiClient(base_url="https://api.example.test", headers={}, name="example")
    client.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(400, json={"error": "bad request"})
        )
    )
    client.circuit_breaker.failure_threshold = 2

    for _ in range(3):
        with pytest.raises(ToolExecutionError) as exc:
            client.request("GET", "/bad-input")
        assert exc.value.kind == ToolErrorKind.PERMANENT

    assert client.circuit_breaker.state == CircuitState.CLOSED


def test_live_api_client_rejects_malformed_base_url_before_credentials_can_be_sent():
    with pytest.raises(ToolExecutionError) as exc:
        LiveApiClient(
            base_url="https://user:secret@api.example.test?token=leaked",
            headers={"Authorization": "Bearer provider-token"},
            name="example",
        )

    message = str(exc.value)
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert exc.value.circuit_breaker_failure is False
    assert "credentials" in message
    assert "secret" not in message
    assert "provider-token" not in message
    assert "leaked" not in message


def test_live_api_circuit_does_not_open_for_authorization_failures():
    client = LiveApiClient(base_url="https://api.example.test", headers={}, name="example")
    client.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(403, json={"error": "forbidden"})
        )
    )
    client.circuit_breaker.failure_threshold = 2

    for _ in range(3):
        with pytest.raises(ToolExecutionError) as exc:
            client.request("GET", "/forbidden")
        assert exc.value.kind == ToolErrorKind.AUTHORIZATION

    assert client.circuit_breaker.state == CircuitState.CLOSED


def test_live_api_circuit_does_not_open_for_provider_rate_limits():
    client = LiveApiClient(base_url="https://api.example.test", headers={}, name="example")
    client.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                429,
                json={"error": "rate limited"},
                headers={"Retry-After": "1"},
            )
        )
    )
    client.circuit_breaker.failure_threshold = 2

    for _ in range(3):
        with pytest.raises(ToolExecutionError) as exc:
            client.request("GET", "/limited")
        assert exc.value.kind == ToolErrorKind.RATE_LIMITED

    assert client.circuit_breaker.state == CircuitState.CLOSED


def test_live_api_circuit_does_not_open_for_github_forbidden_rate_limits():
    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                403,
                json={"message": "API rate limit exceeded for user"},
                headers={"X-RateLimit-Remaining": "0"},
            )
        )
    )
    client.circuit_breaker.failure_threshold = 2

    for _ in range(3):
        with pytest.raises(ToolExecutionError) as exc:
            client.request("GET", "/limited")
        assert exc.value.kind == ToolErrorKind.RATE_LIMITED

    assert client.circuit_breaker.state == CircuitState.CLOSED


def test_live_api_circuit_opens_for_upstream_availability_failures():
    client = LiveApiClient(base_url="https://api.example.test", headers={}, name="example")
    client.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(503, json={"error": "unavailable"})
        )
    )
    client.circuit_breaker.failure_threshold = 2

    for _ in range(2):
        with pytest.raises(ToolExecutionError) as exc:
            client.request("GET", "/unavailable")
        assert exc.value.kind == ToolErrorKind.RETRYABLE

    assert client.circuit_breaker.state == CircuitState.OPEN
    with pytest.raises(CircuitOpenError):
        client.request("GET", "/unavailable")


def test_live_provider_clients_share_provider_circuit_breakers_across_instances():
    reset_shared_circuit_breakers()
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd-api",
        slack_bot_token="xoxb-token",
        slack_channel_id="C123",
        kubeconfig=__file__,
        redis_url=None,
    )
    first = LiveProviderClients.from_settings(settings)
    second = LiveProviderClients.from_settings(settings)
    try:
        assert first.datadog.api.circuit_breaker is second.datadog.api.circuit_breaker
        assert first.github.api.circuit_breaker is second.github.api.circuit_breaker
        assert first.pagerduty.api.circuit_breaker is second.pagerduty.api.circuit_breaker
        assert first.slack.api.circuit_breaker is second.slack.api.circuit_breaker
        assert first.kubernetes.circuit_breaker is second.kubernetes.circuit_breaker
        first.datadog.api.circuit_breaker.failure_threshold = 1
        first.datadog.api.client = httpx.Client(
            transport=getattr(httpx, "Mo" "ckTransport")(
                lambda _request: httpx.Response(503, json={"error": "datadog unavailable"})
            )
        )

        with pytest.raises(ToolExecutionError) as exc:
            first.datadog.api.request("GET", "/api/v1/validate")

        assert exc.value.kind == ToolErrorKind.RETRYABLE
        assert first.datadog.api.circuit_breaker.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            second.datadog.api.request("GET", "/api/v1/validate")
    finally:
        first.close()
        second.close()
        reset_shared_circuit_breakers()


def test_github_link_header_next_pagination_parser():
    link = (
        '<https://api.github.com/repositories/1/commits?page=2>; rel="next", '
        '<https://api.github.com/repositories/1/commits?page=5>; rel="last"'
    )
    assert _extract_next_link(link) == "https://api.github.com/repositories/1/commits?page=2"
    assert _extract_next_link("") is None


def test_github_link_header_rejects_rel_next_without_parseable_url():
    with pytest.raises(ToolExecutionError) as exc:
        _extract_next_link('rel="next", <https://api.github.com/items?page=5>; rel="last"')

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "rel=next" in str(exc.value)
    assert "truncated evidence" in str(exc.value)


@pytest.mark.parametrize(
    ("matcher", "trusted_url", "forged_url", "args"),
    [
        (
            _github_issue_url_matches,
            "https://github.com/acme/api/issues/42",
            "https://evil.example/acme/api/issues/42",
            ("acme", "api", 42),
        ),
        (
            _github_commit_url_matches,
            "https://api.github.com/repos/acme/api/commits/sha-new",
            "https://evil.example/repos/acme/api/commits/sha-new",
            ("acme", "api", "sha-new"),
        ),
        (
            _github_commit_url_matches,
            "https://github.com/acme/api/commit/sha-new",
            "https://evil.example/acme/api/commit/sha-new",
            ("acme", "api", "sha-new"),
        ),
        (
            _github_deployment_url_matches,
            "https://api.github.com/repos/acme/api/deployments/10",
            "https://evil.example/repos/acme/api/deployments/10",
            ("acme", "api", 10),
        ),
        (
            _github_deployment_url_matches,
            "https://api.github.com/repos/acme/api/deployments/10/statuses",
            "https://evil.example/repos/acme/api/deployments/10/statuses",
            ("acme", "api", 10),
        ),
        (
            _github_pull_request_url_matches,
            "https://api.github.com/repos/acme/api/pulls/42",
            "https://evil.example/repos/acme/api/pulls/42",
            ("acme", "api", 42),
        ),
        (
            _github_pull_request_url_matches,
            "https://github.com/acme/api/pull/42",
            "https://evil.example/acme/api/pull/42",
            ("acme", "api", 42),
        ),
        (
            _github_pull_request_file_url_matches,
            "https://api.github.com/repos/acme/api/contents/checkout/payment.py?ref=sha-pr",
            "https://evil.example/repos/acme/api/contents/checkout/payment.py?ref=sha-pr",
            ("acme", "api", "checkout/payment.py"),
        ),
        (
            _github_pull_request_file_url_matches,
            "https://github.com/acme/api/blob/sha-pr/checkout/payment.py",
            "https://evil.example/acme/api/blob/sha-pr/checkout/payment.py",
            ("acme", "api", "checkout/payment.py"),
        ),
        (
            _github_deployment_status_url_matches,
            "https://api.github.com/repos/acme/api/deployments/10/statuses/100",
            "https://evil.example/repos/acme/api/deployments/10/statuses/100",
            ("acme", "api", 10, 100),
        ),
        (
            _github_repo_url_matches,
            "https://api.github.com/repos/acme/api",
            "https://evil.example/repos/acme/api",
            ("acme", "api"),
        ),
        (
            _github_repo_url_matches,
            "https://github.com/acme/api",
            "https://evil.example/acme/api",
            ("acme", "api"),
        ),
        (
            _github_check_run_url_matches,
            "https://api.github.com/repos/acme/api/check-runs/77",
            "https://evil.example/repos/acme/api/check-runs/77",
            ("acme", "api", 77),
        ),
        (
            _github_check_run_url_matches,
            "https://github.com/acme/api/runs/77",
            "https://evil.example/acme/api/runs/77",
            ("acme", "api", 77),
        ),
    ],
)
def test_github_receipt_url_matchers_require_canonical_github_hosts(
    matcher,
    trusted_url,
    forged_url,
    args,
):
    assert matcher(trusted_url, *args)
    assert not matcher(forged_url, *args)
    assert not matcher(trusted_url.replace("https://", "http://"), *args)


def test_github_pagination_follows_lowercase_link_header_from_httpx():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"link": '<https://api.github.test/items?page=2>; rel="next"'},
            )
        if str(request.url) == "https://api.github.test/items?page=2":
            return httpx.Response(200, json=[{"id": 2}])
        raise AssertionError(request.url)

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.paginate_github("/items")

    assert result == [{"id": 1}, {"id": 2}]
    assert requested_urls == [
        "https://api.github.test/items",
        "https://api.github.test/items?page=2",
    ]


def test_live_api_request_normalizes_relative_path_without_leading_slash():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.request("GET", "repos/acme/api")

    assert result["ok"] is True
    assert requested_urls == ["https://api.github.test/repos/acme/api"]


def test_live_api_request_rejects_empty_path_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"ok": True})

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.request("GET", "")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "path was empty" in str(exc.value)
    assert called is False


@pytest.mark.parametrize("max_pages", [0, -1, True, 1.5, "2"])
def test_live_api_client_rejects_invalid_constructor_page_limits(max_pages):
    with pytest.raises(ToolExecutionError) as exc:
        LiveApiClient(
            base_url="https://api.github.test",
            headers={},
            name="github",
            max_pages=max_pages,
        )

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "max_pages must be a positive integer" in str(exc.value)
    assert exc.value.circuit_breaker_failure is False


@pytest.mark.parametrize("max_pages", [0, -1, False, 1.5, "2"])
def test_live_api_pagination_rejects_invalid_call_page_limits_before_http(max_pages):
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json=[{"id": 1}])

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items", max_pages=max_pages)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "max_pages must be a positive integer" in str(exc.value)
    assert exc.value.circuit_breaker_failure is False
    assert called is False


def test_github_pagination_allows_uppercase_same_origin_https_link():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": '<HTTPS://api.github.test/items?page=2>; rel="next"'},
            )
        if str(request.url) == "https://api.github.test/items?page=2":
            return httpx.Response(200, json=[{"id": 2}])
        raise AssertionError(request.url)

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.paginate_github("/items")

    assert result == [{"id": 1}, {"id": 2}]
    assert requested_urls == [
        "https://api.github.test/items",
        "https://api.github.test/items?page=2",
    ]


def test_github_pagination_collects_object_list_key_across_link_headers():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/check-runs":
            return httpx.Response(
                200,
                json={"total_count": 2, "check_runs": [{"id": 1}]},
                headers={"Link": '<https://api.github.test/check-runs?page=2>; rel="next"'},
            )
        if str(request.url) == "https://api.github.test/check-runs?page=2":
            return httpx.Response(200, json={"total_count": 2, "check_runs": [{"id": 2}]})
        raise AssertionError(request.url)

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.paginate_github("/check-runs", item_key="check_runs")

    assert result == [{"id": 1}, {"id": 2}]
    assert requested_urls == [
        "https://api.github.test/check-runs",
        "https://api.github.test/check-runs?page=2",
    ]


def test_live_api_pagination_rejects_truncation_at_configured_page_limit():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        page = len(requested_urls)
        return httpx.Response(
            200,
            json=[{"id": page}],
            headers={"Link": f'<https://api.github.test/items?page={page + 1}>; rel="next"'},
        )

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github", max_pages=2)
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert requested_urls == [
        "https://api.github.test/items",
        "https://api.github.test/items?page=2",
    ]


def test_live_api_absolute_next_link_must_stay_on_configured_origin():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": '<https://evil.example/items?page=2>; rel="next"'},
            )
        raise AssertionError(f"unexpected credential leak request to {request.url}")

    client = LiveApiClient(
        base_url="https://api.github.test",
        headers={"Authorization": "Bearer gh-secret-token"},
        name="github",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.circuit_breaker_failure is False
    assert "crossed API origin" in str(exc.value)
    assert requested_urls == ["https://api.github.test/items"]


def test_live_api_absolute_url_cannot_escape_configured_base_path_on_same_origin():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        raise AssertionError(f"unexpected credential leak request to {request.url}")

    client = LiveApiClient(
        base_url="https://slack.com/api",
        headers={"Authorization": "Bearer xoxb-secret-token"},
        name="slack",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.request("POST", "https://slack.com/auth.test")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.circuit_breaker_failure is False
    assert "base path" in str(exc.value)
    assert requested_urls == []


def test_live_api_protocol_relative_next_link_is_rejected_without_second_request():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": '<//evil.example/items?page=2>; rel="next"'},
            )
        raise AssertionError(f"unexpected credential leak request to {request.url}")

    client = LiveApiClient(
        base_url="https://api.github.test",
        headers={"Authorization": "Bearer gh-secret-token"},
        name="github",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.circuit_breaker_failure is False
    assert "malformed" in str(exc.value)
    assert requested_urls == ["https://api.github.test/items"]


def test_live_api_non_http_absolute_next_link_is_rejected_without_second_request():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": '<mailto:ops@example.test>; rel="next"'},
            )
        raise AssertionError(f"unexpected credential leak request to {request.url}")

    client = LiveApiClient(
        base_url="https://api.github.test",
        headers={"Authorization": "Bearer gh-secret-token"},
        name="github",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.circuit_breaker_failure is False
    assert "malformed" in str(exc.value)
    assert requested_urls == ["https://api.github.test/items"]


def test_live_api_absolute_next_link_allows_same_origin_default_port():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": '<https://api.github.test:443/items?page=2>; rel="next"'},
            )
        if str(request.url) == "https://api.github.test/items?page=2":
            return httpx.Response(200, json=[{"id": 2}])
        raise AssertionError(request.url)

    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.paginate_github("/items")

    assert result == [{"id": 1}, {"id": 2}]
    assert requested_urls == [
        "https://api.github.test/items",
        "https://api.github.test/items?page=2",
    ]


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://api.github.test:bad/items?page=2",
        "http://[::1/items?page=2",
    ],
)
def test_live_api_absolute_next_link_rejects_malformed_url_without_second_request(bad_url):
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": f"<{bad_url}>; rel=\"next\""},
            )
        raise AssertionError(f"unexpected credential leak request to {request.url}")

    client = LiveApiClient(
        base_url="https://api.github.test",
        headers={"Authorization": "Bearer gh-secret-token"},
        name="github",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.circuit_breaker_failure is False
    assert "malformed" in str(exc.value)
    assert requested_urls == ["https://api.github.test/items"]


def test_live_api_link_rel_next_without_url_is_rejected_without_second_request():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.test/items":
            return httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": 'rel="next"'},
            )
        raise AssertionError(f"unexpected credential leak request to {request.url}")

    client = LiveApiClient(
        base_url="https://api.github.test",
        headers={"Authorization": "Bearer gh-secret-token"},
        name="github",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert exc.value.circuit_breaker_failure is False
    assert "rel=next" in str(exc.value)
    assert requested_urls == ["https://api.github.test/items"]


def test_github_pagination_rejects_malformed_list_field():
    client = LiveApiClient(base_url="https://api.github.test", headers={}, name="github")
    client.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": {"id": 1}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.paginate_github("/items")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "data" in str(exc.value)
    assert exc.value.circuit_breaker_failure is False


def test_datadog_cursor_pagination_rejects_malformed_data_field():
    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": {"id": "not-a-list"}, "meta": {"page": {}}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "data" in str(exc.value)


def test_datadog_client_uses_bearer_auth_without_api_key_headers_for_oauth():
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"data": [{"id": "log-1"}], "meta": {"page": {}}})

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key=None,
            datadog_app_key=None,
            datadog_oauth_token="dd-oauth-token",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.search_logs("service:checkout")

    assert result["events"] == [{"id": "log-1"}]
    assert seen_headers[0]["authorization"] == "Bearer dd-oauth-token"
    assert "dd-api-key" not in seen_headers[0]
    assert "dd-application-key" not in seen_headers[0]


def test_datadog_client_uses_api_and_app_key_headers_without_bearer_auth():
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"data": [{"id": "log-1"}], "meta": {"page": {}}})

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.search_logs("service:checkout")

    assert result["events"] == [{"id": "log-1"}]
    assert seen_headers[0]["dd-api-key"] == "dd-api"
    assert seen_headers[0]["dd-application-key"] == "dd-app"
    assert "authorization" not in seen_headers[0]


def test_datadog_cursor_pagination_rejects_non_object_event_items():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": ["not-an-event"], "meta": {"page": {}}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "data[0]" in str(exc.value)


def test_datadog_log_events_require_provider_event_id_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": [{"attributes": {"message": "checkout failed"}}], "meta": {"page": {}}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "logs.events[0].id" in str(exc.value)


def test_datadog_apm_spans_reject_non_object_span_items():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": ["not-a-span"], "meta": {"page": {}}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_spans("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "data[0]" in str(exc.value)


def test_datadog_apm_spans_require_provider_event_id_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": [{"attributes": {"service": "checkout"}}], "meta": {"page": {}}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_spans("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "spans.events[0].id" in str(exc.value)


def test_datadog_metric_query_requires_series_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"status": "ok"})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.query_metric("avg:system.cpu.user{*}")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "series" in str(exc.value)


def test_datadog_metric_query_requires_series_pointlist_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"status": "ok", "series": [{"metric": "system.cpu.user"}]},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.query_metric("avg:system.cpu.user{*}")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "series[0].pointlist" in str(exc.value)


def test_datadog_metric_query_rejects_empty_series_pointlist_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"status": "ok", "series": [{"metric": "system.cpu.user", "pointlist": []}]},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.query_metric("avg:system.cpu.user{*}")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "series[0].pointlist" in str(exc.value)


def test_datadog_metric_query_rejects_pointlist_without_finite_numeric_datapoint():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                content=(
                    b'{"status":"ok","series":[{"metric":"system.cpu.user",'
                    b'"pointlist":[[1717425600,null],[1717425660,"1.0"],'
                    b'[1717425720,NaN],[1717425780,Infinity]]}]}'
                ),
                headers={"content-type": "application/json"},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.query_metric("avg:system.cpu.user{*}")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "series[0].pointlist" in str(exc.value)


def test_datadog_metric_query_rejects_error_status_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"status": "error", "series": []})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.query_metric("avg:system.cpu.user{*}")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "status=error" in str(exc.value)


def test_pagerduty_list_incidents_rejects_malformed_incidents_field():
    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"incidents": {"id": "PD-1"}, "more": False})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_incidents()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "incidents" in str(exc.value)


def test_pagerduty_list_incidents_paginates_until_more_is_false():
    requested_offsets = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        requested_offsets.append(offset)
        if offset == 0:
            return httpx.Response(200, json={"incidents": [{"id": "PD-1", "status": "triggered"}], "more": True})
        if offset == 100:
            return httpx.Response(200, json={"incidents": [{"id": "PD-2", "status": "acknowledged"}], "more": False})
        raise AssertionError(offset)

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.list_incidents()

    assert result == [{"id": "PD-1", "status": "triggered"}, {"id": "PD-2", "status": "acknowledged"}]
    assert requested_offsets == [0, 100]


def test_pagerduty_list_incidents_rejects_truncation_at_configured_page_limit():
    requested_offsets = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        requested_offsets.append(offset)
        return httpx.Response(
            200,
            json={"incidents": [{"id": f"PD-{offset}", "status": "triggered"}], "more": True},
        )

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.list_incidents()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert requested_offsets == [0, 100]


def test_pagerduty_get_incident_requires_matching_id_and_status_confirmation():
    client = _pagerduty_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"incident": {"id": "PD-2", "status": "triggered"}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.get_incident("PD-1")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "incident.id=PD-2" in str(exc.value)


def test_pagerduty_list_incidents_requires_status_confirmation():
    client = _pagerduty_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"incidents": [{"id": "PD-1"}], "more": False})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_incidents()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "incidents[0].status" in str(exc.value)


def test_pagerduty_list_incidents_rejects_malformed_more_field():
    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"incidents": [{"id": "PD-1", "status": "triggered"}], "more": "false"})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_incidents()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "more" in str(exc.value)
    assert "boolean" in str(exc.value)


def test_pagerduty_list_incidents_rejects_missing_more_with_incident_rows():
    client = _pagerduty_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"incidents": [{"id": "PD-1", "status": "triggered"}]},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_incidents()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "more" in str(exc.value)
    assert "unbounded evidence" in str(exc.value)


def test_pagerduty_list_incidents_allows_explicitly_truncated_sample_without_more():
    requested_offsets = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        requested_offsets.append(offset)
        return httpx.Response(200, json={"incidents": [{"id": f"PD-{offset}", "status": "triggered"}]})

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.list_incidents(allow_truncated=True)

    assert result == [
        {"id": "PD-0", "status": "triggered"},
        {"id": "PD-100", "status": "triggered"},
    ]
    assert requested_offsets == [0, 100]


def test_pagerduty_on_calls_requires_user_id_confirmation():
    client = _pagerduty_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"oncalls": [{"user": {"summary": "On Call"}}], "more": False})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.on_calls()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "oncalls[0].user.id" in str(exc.value)


def test_pagerduty_on_calls_filters_by_escalation_policy_ids():
    seen_policy_ids = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_policy_ids.extend(request.url.params.get_list("escalation_policy_ids[]"))
        return httpx.Response(200, json={"oncalls": [{"user": {"id": "U1"}}], "more": False})

    client = _pagerduty_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.on_calls(escalation_policy_ids=["EP1", " EP2 "])

    assert result == [{"user": {"id": "U1"}}]
    assert seen_policy_ids == ["EP1", "EP2"]


def test_pagerduty_on_calls_rejects_malformed_more_field():
    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"oncalls": [{"user": {"id": "U1"}}], "more": {"next": False}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.on_calls()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "more" in str(exc.value)
    assert "boolean" in str(exc.value)


def test_pagerduty_on_calls_rejects_missing_more_with_oncall_rows():
    client = _pagerduty_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"oncalls": [{"user": {"id": "U1"}}]})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.on_calls()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "more" in str(exc.value)
    assert "unbounded evidence" in str(exc.value)


def test_pagerduty_on_calls_rejects_truncation_at_configured_page_limit():
    requested_offsets = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        requested_offsets.append(offset)
        return httpx.Response(
            200,
            json={"oncalls": [{"user": {"id": f"U{offset}"}}], "more": True},
        )

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.on_calls()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert requested_offsets == [0, 100]


def test_slack_list_channels_rejects_malformed_channels_field():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": {"id": "C123"},
                    "response_metadata": {"next_cursor": ""},
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_channels()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "channels" in str(exc.value)


def test_slack_api_calls_preserve_slack_api_base_path():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, json={"ok": True, "url": "https://sentinel.example/auth"})

    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    client.oauth_test()

    assert requested_urls == ["https://slack.com/api/auth.test"]


def test_slack_list_channels_rejects_malformed_response_metadata():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": [{"id": "C123", "name": "inc-pd-1"}],
                    "response_metadata": "cursor-2",
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_channels()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "response_metadata" in str(exc.value)


def test_slack_list_channels_accepts_short_final_page_without_response_metadata():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"ok": True, "channels": [{"id": "C123", "name": "inc-pd-1"}]},
            )
        )
    )

    result = client.list_channels()

    assert result == [{"id": "C123", "name": "inc-pd-1"}]


def test_slack_list_channels_rejects_full_page_without_response_metadata():
    full_page = [{"id": f"C{i}", "name": f"inc-pd-{i}"} for i in range(200)]
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"ok": True, "channels": full_page})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_channels()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "response_metadata.next_cursor" in str(exc.value)
    assert "unbounded evidence" in str(exc.value)


def test_slack_list_channels_allows_explicitly_truncated_full_page_without_response_metadata():
    full_page = [{"id": f"C{i}", "name": f"inc-pd-{i}"} for i in range(200)]
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"ok": True, "channels": full_page})
        )
    )

    result = client.list_channels(allow_truncated=True)

    assert result == full_page


def test_slack_list_channels_rejects_malformed_next_cursor():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": [{"id": "C123", "name": "inc-pd-1"}],
                    "response_metadata": {"next_cursor": {"cursor": "cursor-2"}},
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_channels()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "response_metadata.next_cursor" in str(exc.value)


def test_slack_list_channels_requires_channel_id_and_name_confirmation():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "ok": True,
                    "channels": [{"id": "C123"}],
                    "response_metadata": {"next_cursor": ""},
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_channels()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "channels[0].name" in str(exc.value)


def test_slack_list_channels_rejects_truncation_at_configured_page_limit():
    seen_cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        cursor = body.get("cursor")
        seen_cursors.append(cursor)
        next_cursor = "cursor-2" if cursor is None else "cursor-3"
        return httpx.Response(
            200,
            json={
                "ok": True,
                "channels": [{"id": f"C-{len(seen_cursors)}", "name": f"inc-pd-{len(seen_cursors)}"}],
                "response_metadata": {"next_cursor": next_cursor},
            },
        )

    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.list_channels()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert seen_cursors == [None, "cursor-2"]


def test_slack_create_channel_returns_confirmed_channel_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content.decode()))
        return httpx.Response(
            200,
            json={"ok": True, "channel": {"id": "C123", "name": "inc-pd-1"}},
        )

    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.create_channel("Inc PD 1")

    assert result["channel"]["id"] == "C123"
    assert result["channel"]["name"] == "inc-pd-1"
    assert seen == [{"name": "inc-pd-1", "is_private": False}]


def test_slack_create_channel_requires_channel_id_and_name_confirmation():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"ok": True, "channel": {"name": "inc-pd-1"}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.create_channel("Inc PD 1")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "channel.id" in str(exc.value)


def test_slack_create_channel_rejects_mismatched_channel_name_confirmation():
    client = SlackClient(
        replace(
            SentinelSettings.from_env(),
            slack_bot_token="xoxb-token",
            slack_channel_id="C123",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"ok": True, "channel": {"id": "C123", "name": "other-incident"}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.create_channel("Inc PD 1")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "channel.name=other-incident" in str(exc.value)


def test_live_api_request_extra_headers_do_not_mutate_base_headers():
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    client = LiveApiClient(
        base_url="https://api.example.test",
        headers={"Authorization": "Bearer base"},
        name="example",
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    client.request("GET", "/with-extra", extra_headers={"From": "oncall@example.com"})
    client.request("GET", "/without-extra")

    assert seen_headers[0]["authorization"] == "Bearer base"
    assert seen_headers[0]["from"] == "oncall@example.com"
    assert "from" not in seen_headers[1]
    assert client.headers == {"Authorization": "Bearer base"}


def test_pagerduty_status_update_uses_per_request_from_header_without_mutating_auth_headers():
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"incident": {"id": "PD-1", "status": "resolved"}})

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.update_incident_status("PD-1", "resolved", requester_email="oncall@example.com")

    assert result["incident"]["status"] == "resolved"
    assert seen_headers[0]["authorization"] == "Token token=pd-api"
    assert seen_headers[0]["from"] == "oncall@example.com"
    assert "From" not in client.api.headers
    assert client.api.headers["Authorization"] == "Token token=pd-api"


def test_pagerduty_status_update_uses_configured_requester_email():
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"incident": {"id": "PD-1", "status": "resolved"}})

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="configured-oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.update_incident_status("PD-1", "resolved")

    assert result["incident"]["status"] == "resolved"
    assert seen_headers[0]["from"] == "configured-oncall@example.com"
    assert "From" not in client.api.headers


def test_pagerduty_status_update_requires_requester_email_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"incident": {"id": "PD-1"}})

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.update_incident_status("PD-1", "resolved")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "PAGERDUTY_REQUESTER_EMAIL" in str(exc.value)
    assert called is False


def test_pagerduty_status_update_requires_incident_id_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"incident": {"id": "PD-1", "status": "resolved"}})

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.update_incident_status(" ", "resolved")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "explicit incident_id" in str(exc.value)
    assert called is False


def test_pagerduty_status_update_requires_valid_status_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"incident": {"id": "PD-1", "status": "resolved"}})

    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.update_incident_status("PD-1", "snoozed")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "one of: acknowledged, resolved, triggered" in str(exc.value)
    assert called is False


def test_pagerduty_status_update_requires_confirmed_incident_status():
    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"incident": {"id": "PD-1"}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.update_incident_status("PD-1", "resolved")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "incident.status" in str(exc.value)


def test_pagerduty_status_update_rejects_mismatched_confirmation():
    client = PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"incident": {"id": "PD-2", "status": "triggered"}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.update_incident_status("PD-1", "resolved")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "incident.id=PD-2" in str(exc.value)
    assert "incident.status=triggered" in str(exc.value)


def test_datadog_cursor_pagination_uses_configured_live_page_limit():
    seen_cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        cursor = body.get("page", {}).get("cursor")
        seen_cursors.append(cursor)
        if cursor is None:
            return httpx.Response(
                200,
                json={"data": [{"id": "log-1"}], "meta": {"page": {"after": "cursor-2"}}},
            )
        if cursor == "cursor-2":
            return httpx.Response(
                200,
                json={"data": [{"id": "log-2"}], "meta": {"page": {"after": "cursor-3"}}},
            )
        if cursor == "cursor-3":
            return httpx.Response(200, json={"data": [{"id": "log-3"}], "meta": {"page": {}}})
        raise AssertionError(cursor)

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.search_logs("service:checkout")

    assert [item["id"] for item in result["events"]] == ["log-1", "log-2", "log-3"]
    assert seen_cursors == [None, "cursor-2", "cursor-3"]


def test_datadog_cursor_pagination_rejects_truncation_at_configured_page_limit():
    seen_cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        cursor = body.get("page", {}).get("cursor")
        seen_cursors.append(cursor)
        next_cursor = "cursor-2" if cursor is None else "cursor-3"
        return httpx.Response(
            200,
            json={"data": [{"id": f"log-{len(seen_cursors)}"}], "meta": {"page": {"after": next_cursor}}},
        )

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert seen_cursors == [None, "cursor-2"]


def test_datadog_cursor_pagination_rejects_full_page_without_next_cursor():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"data": [{"id": "log-1"}, {"id": "log-2"}], "meta": {"page": {}}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout", limit=2)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "meta.page.after" in str(exc.value)
    assert "unbounded evidence" in str(exc.value)


def test_datadog_cursor_pagination_allows_explicitly_truncated_full_page_without_next_cursor():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"data": [{"id": "log-1"}, {"id": "log-2"}], "meta": {"page": {}}},
            )
        )
    )

    result = client.search_logs("service:checkout", limit=2, allow_truncated=True)

    assert result["events"] == [{"id": "log-1"}, {"id": "log-2"}]


def test_datadog_cursor_pagination_rejects_malformed_cursor_parent():
    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"data": [{"id": "log-1"}], "meta": "cursor-2"})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "meta" in str(exc.value)
    assert "object" in str(exc.value)


def test_datadog_cursor_pagination_rejects_malformed_cursor_value():
    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"data": [{"id": "log-1"}], "meta": {"page": {"after": {"cursor": "cursor-2"}}}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.search_logs("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "meta.page.after" in str(exc.value)
    assert "string" in str(exc.value)


def test_datadog_monitor_search_paginates_until_metadata_page_count():
    seen_pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_pages.append((request.url.path, params))
        page = int(params["page"])
        if page == 0:
            return httpx.Response(
                200,
                json={
                    "monitors": [{"id": 1, "name": "checkout latency"}],
                    "metadata": {"page": 0, "page_count": 2, "per_page": 1, "total_count": 2},
                },
            )
        if page == 1:
            return httpx.Response(
                200,
                json={
                    "monitors": [{"id": 2, "name": "checkout errors"}],
                    "metadata": {"page": 1, "page_count": 2, "per_page": 1, "total_count": 2},
                },
            )
        raise AssertionError(page)

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.list_monitors("service:checkout", per_page=1)

    assert result == {
        "monitors": [
            {"id": 1, "name": "checkout latency"},
            {"id": 2, "name": "checkout errors"},
        ],
        "query": "service:checkout",
    }
    assert seen_pages == [
        ("/api/v1/monitor/search", {"query": "service:checkout", "page": "0", "per_page": "1"}),
        ("/api/v1/monitor/search", {"query": "service:checkout", "page": "1", "per_page": "1"}),
    ]


def test_datadog_monitor_search_rejects_truncation_at_configured_page_limit():
    seen_pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_pages.append(params)
        page = int(params["page"])
        return httpx.Response(
            200,
            json={
                "monitors": [{"id": page + 1, "name": f"checkout monitor {page + 1}"}],
                "metadata": {"page": page, "page_count": 3, "per_page": 1, "total_count": 3},
            },
        )

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors("service:checkout", per_page=1)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert seen_pages == [
        {"query": "service:checkout", "page": "0", "per_page": "1"},
        {"query": "service:checkout", "page": "1", "per_page": "1"},
    ]


def test_datadog_monitor_search_rejects_missing_page_count_with_monitor_rows():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"monitors": [{"id": 1, "name": "checkout latency"}], "metadata": {}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "metadata.page_count" in str(exc.value)
    assert "unbounded evidence" in str(exc.value)


def test_datadog_monitor_search_allows_explicitly_truncated_sample_without_page_count():
    seen_pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_pages.append(params)
        page = int(params["page"])
        return httpx.Response(
            200,
            json={"monitors": [{"id": page + 1, "name": f"checkout monitor {page + 1}"}], "metadata": {}},
        )

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.list_monitors("service:checkout", per_page=1, allow_truncated=True)

    assert result == {
        "monitors": [
            {"id": 1, "name": "checkout monitor 1"},
            {"id": 2, "name": "checkout monitor 2"},
        ],
        "query": "service:checkout",
    }
    assert seen_pages == [
        {"query": "service:checkout", "page": "0", "per_page": "1"},
        {"query": "service:checkout", "page": "1", "per_page": "1"},
    ]


def test_datadog_all_monitor_list_uses_page_and_page_size_until_short_page():
    seen_pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_pages.append(params)
        page = int(params["page"])
        if page == 0:
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
        if page == 1:
            return httpx.Response(200, json=[{"id": 3}])
        raise AssertionError(page)

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.list_monitors(per_page=2)

    assert result == {"monitors": [{"id": 1}, {"id": 2}, {"id": 3}], "query": None}
    assert seen_pages == [
        {"page": "0", "page_size": "2"},
        {"page": "1", "page_size": "2"},
    ]


def test_datadog_all_monitor_list_rejects_truncation_at_configured_page_limit():
    seen_pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_pages.append(params)
        page = int(params["page"])
        return httpx.Response(200, json=[{"id": page * 2 + 1}, {"id": page * 2 + 2}])

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors(per_page=2)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "page limit 2" in str(exc.value)
    assert "truncated evidence" in str(exc.value)
    assert seen_pages == [
        {"page": "0", "page_size": "2"},
        {"page": "1", "page_size": "2"},
    ]


def test_datadog_all_monitor_list_allows_explicitly_truncated_sample():
    seen_pages = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        seen_pages.append(params)
        page = int(params["page"])
        return httpx.Response(200, json=[{"id": page * 2 + 1}, {"id": page * 2 + 2}])

    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=2,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.list_monitors(per_page=2, allow_truncated=True)

    assert result == {"monitors": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}], "query": None}
    assert seen_pages == [
        {"page": "0", "page_size": "2"},
        {"page": "1", "page_size": "2"},
    ]


def test_datadog_monitor_search_rejects_malformed_monitors_field():
    client = DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"monitors": {"id": 1}, "metadata": {"page_count": 1}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "monitors" in str(exc.value)


def test_datadog_monitor_search_rejects_malformed_metadata_field():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"monitors": [], "metadata": "page-2"},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "metadata" in str(exc.value)
    assert "object" in str(exc.value)


@pytest.mark.parametrize("page_count", [True, 1.5, -1, "1.5"])
def test_datadog_monitor_search_rejects_malformed_page_count(page_count):
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "monitors": [{"id": 1, "name": "checkout latency"}],
                    "metadata": {"page_count": page_count},
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "metadata.page_count" in str(exc.value)
    assert "integer" in str(exc.value)


def test_datadog_monitor_search_requires_monitor_id_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"monitors": [{"name": "checkout latency"}], "metadata": {"page_count": 1}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors("service:checkout")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "monitors[0].id" in str(exc.value)


def test_datadog_all_monitor_list_requires_monitor_id_confirmation():
    client = _datadog_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json=[{"name": "checkout latency"}])
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.list_monitors()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "data[0].id" in str(exc.value)


def test_github_deployments_fetch_latest_statuses_for_change_artifacts():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments?per_page=2":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 10,
                        "url": "https://api.github.com/repos/acme/api/deployments/10",
                        "sha": "sha-new",
                        "ref": "main",
                        "environment": "production",
                    },
                    {
                        "id": 9,
                        "url": "https://api.github.com/repos/acme/api/deployments/9",
                        "sha": "sha-old",
                        "ref": "release-2026-06-02",
                    },
                ],
            )
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 100,
                        "deployment_url": "https://api.github.com/repos/acme/api/deployments/10",
                        "state": "success",
                        "environment": "production",
                    }
                ],
            )
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments/9/statuses?per_page=100":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 90,
                        "deployment_url": "https://api.github.com/repos/acme/api/deployments/9",
                        "state": "inactive",
                    }
                ],
            )
        raise AssertionError(request.url)

    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.deployments(per_page=2)

    assert result[0]["latest_status"]["state"] == "success"
    assert result[0]["statuses"][0]["environment"] == "production"
    assert result[1]["latest_status"]["state"] == "inactive"
    assert requested_urls == [
        "https://api.github.com/repos/acme/api/deployments?per_page=2",
        "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100",
        "https://api.github.com/repos/acme/api/deployments/9/statuses?per_page=100",
    ]


def test_github_deployment_status_enrichment_follows_status_pagination():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments?per_page=30":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 10,
                        "url": "https://api.github.com/repos/acme/api/deployments/10",
                        "sha": "sha-new",
                    }
                ],
            )
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 100,
                        "deployment_url": "https://api.github.com/repos/acme/api/deployments/10",
                        "state": "success",
                    }
                ],
                headers={
                    "Link": '<https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100&page=2>; rel="next"'
                },
            )
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100&page=2":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 99,
                        "deployment_url": "https://api.github.com/repos/acme/api/deployments/10",
                        "state": "inactive",
                    }
                ],
            )
        raise AssertionError(request.url)

    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.deployments()

    assert [status["id"] for status in result[0]["statuses"]] == [100, 99]
    assert result[0]["latest_status"]["id"] == 100
    assert requested_urls == [
        "https://api.github.com/repos/acme/api/deployments?per_page=30",
        "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100",
        "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100&page=2",
    ]


def test_github_deployment_status_enrichment_fails_closed_when_status_pages_exceed_limit():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments?per_page=30":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 10,
                        "url": "https://api.github.com/repos/acme/api/deployments/10",
                        "sha": "sha-new",
                    }
                ],
            )
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 100,
                        "deployment_url": "https://api.github.com/repos/acme/api/deployments/10",
                        "state": "success",
                    }
                ],
                headers={
                    "Link": '<https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100&page=2>; rel="next"'
                },
            )
        raise AssertionError(request.url)

    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=1,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "github pagination exceeded configured page limit 1" in str(exc.value)
    assert "GitHub Link rel=next" in str(exc.value)


def test_github_deployments_rejects_non_object_deployment_items():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json=["not-a-deployment"])
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "deployments[0]" in str(exc.value)


def test_github_deployments_requires_deployment_id_before_status_lookup():
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments?per_page=30":
            return httpx.Response(200, json=[{"sha": "sha-new", "ref": "main"}])
        raise AssertionError(f"unexpected status lookup without deployment id: {request.url}")

    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "id" in str(exc.value)
    assert requested_urls == ["https://api.github.com/repos/acme/api/deployments?per_page=30"]


def test_github_deployments_reject_mismatched_repository_confirmation():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json=[
                    {
                        "id": 10,
                        "url": "https://api.github.com/repos/acme/other/deployments/10",
                        "sha": "sha-new",
                    }
                ],
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "deployments[0].url=https://api.github.com/repos/acme/other/deployments/10" in str(exc.value)


def test_github_deployment_statuses_reject_mismatched_deployment_confirmation():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments?per_page=30":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 10,
                        "url": "https://api.github.com/repos/acme/api/deployments/10",
                        "sha": "sha-new",
                    }
                ],
            )
        if str(request.url) == "https://api.github.com/repos/acme/api/deployments/10/statuses?per_page=100":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 100,
                        "deployment_url": "https://api.github.com/repos/acme/api/deployments/99",
                        "state": "success",
                    }
                ],
            )
        raise AssertionError(request.url)

    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "deployment_statuses[0].deployment_url=https://api.github.com/repos/acme/api/deployments/99" in str(exc.value)


def test_github_commits_require_sha_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json=[{"commit": {"message": "Merge #12"}}])
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.commits()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "commits[0].sha" in str(exc.value)


def test_github_commits_return_confirmed_repository_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json=[
                {
                    "sha": "sha-new",
                    "html_url": "https://github.com/acme/api/commit/sha-new",
                    "commit": {"message": "Merge pull request #12"},
                }
            ],
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.commits(per_page=1)

    assert result[0]["sha"] == "sha-new"
    assert seen == ["https://api.github.com/repos/acme/api/commits?per_page=1"]


def test_github_commits_reject_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json=[
                    {
                        "sha": "sha-new",
                        "html_url": "https://github.com/acme/other/commit/sha-new",
                    }
                ],
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.commits()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "commits[0].url=https://github.com/acme/other/commit/sha-new" in str(exc.value)


def test_github_pull_request_requires_matching_number_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"number": 99, "title": "wrong PR"})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.pull_request(42)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "number=99" in str(exc.value)


def test_github_pull_request_returns_confirmed_repository_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "number": 42,
                "html_url": "https://github.com/acme/api/pull/42",
                "title": "Fix checkout latency",
            },
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.pull_request(42)

    assert result["number"] == 42
    assert seen == ["https://api.github.com/repos/acme/api/pulls/42"]


def test_github_pull_request_rejects_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "number": 42,
                    "html_url": "https://github.com/acme/other/pull/42",
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.pull_request(42)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "url=https://github.com/acme/other/pull/42" in str(exc.value)


def test_github_pull_requests_reject_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json=[
                    {
                        "number": 42,
                        "url": "https://api.github.com/repos/acme/other/pulls/42",
                    }
                ],
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.pull_requests(state="closed", per_page=1)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "pull_requests[0].url=https://api.github.com/repos/acme/other/pulls/42" in str(exc.value)


def test_github_pull_request_files_require_filename_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json=[{"status": "modified"}])
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.pull_request_files(42)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "pull_request_files[0].filename" in str(exc.value)


def test_github_pull_request_files_return_confirmed_repository_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json=[
                {
                    "filename": "checkout/payment.py",
                    "status": "modified",
                    "contents_url": "https://api.github.com/repos/acme/api/contents/checkout/payment.py?ref=sha-pr",
                }
            ],
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.pull_request_files(42)

    assert result[0]["filename"] == "checkout/payment.py"
    assert seen == ["https://api.github.com/repos/acme/api/pulls/42/files?per_page=100"]


def test_github_pull_request_files_reject_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json=[
                    {
                        "filename": "checkout/payment.py",
                        "blob_url": "https://github.com/acme/other/blob/sha-pr/checkout/payment.py",
                    }
                ],
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.pull_request_files(42)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "pull_request_files[0].url=https://github.com/acme/other/blob/sha-pr/checkout/payment.py" in str(exc.value)


def test_github_pull_request_commits_return_confirmed_repository_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json=[
                {
                    "sha": "sha-pr",
                    "html_url": "https://github.com/acme/api/commit/sha-pr",
                    "commit": {"message": "Fix checkout latency"},
                }
            ],
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.pull_request_commits(42)

    assert result[0]["sha"] == "sha-pr"
    assert seen == ["https://api.github.com/repos/acme/api/pulls/42/commits?per_page=100"]


def test_github_pull_request_commits_reject_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json=[
                    {
                        "sha": "sha-pr",
                        "html_url": "https://github.com/acme/other/commit/sha-pr",
                    }
                ],
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.pull_request_commits(42)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "commits[0].url=https://github.com/acme/other/commit/sha-pr" in str(exc.value)


def test_github_statuses_require_state_and_status_list_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"statuses": []})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.statuses("sha-new")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "state" in str(exc.value)


def test_github_statuses_reject_non_object_status_items():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"state": "failure", "statuses": ["bad-status"]})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.statuses("sha-new")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "statuses[0]" in str(exc.value)


def test_github_statuses_return_confirmed_repository_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "state": "success",
                "sha": "sha-new",
                "repository": {"full_name": "acme/api"},
                "statuses": [],
            },
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.statuses("sha-new")

    assert result["state"] == "success"
    assert seen == ["https://api.github.com/repos/acme/api/commits/sha-new/status"]


def test_github_statuses_reject_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "state": "success",
                    "repository": {"full_name": "acme/other"},
                    "statuses": [],
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.statuses("sha-new")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "repository.full_name=acme/other" in str(exc.value)


def test_github_check_runs_require_status_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"total_count": 1, "check_runs": [{"id": 1}]})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.check_runs("sha-new")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "check_runs[0].status" in str(exc.value)


def test_github_check_runs_return_confirmed_repository_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "total_count": 1,
                "check_runs": [
                    {
                        "id": 77,
                        "url": "https://api.github.com/repos/acme/api/check-runs/77",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            },
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.check_runs("sha-new")

    assert result["check_runs"][0]["id"] == 77
    assert result["total_count"] == 1
    assert seen == ["https://api.github.com/repos/acme/api/commits/sha-new/check-runs?per_page=100"]


def test_github_check_runs_reject_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "check_runs": [
                        {
                            "id": 77,
                            "url": "https://api.github.com/repos/acme/other/check-runs/77",
                            "status": "completed",
                        }
                    ],
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.check_runs("sha-new")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "check_runs[0].url=https://api.github.com/repos/acme/other/check-runs/77" in str(exc.value)


def test_github_create_issue_requires_write_inputs_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(201, json={"number": 42, "html_url": "https://github.com/acme/api/issues/42"})

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.create_issue(" ", "Investigate query regression", labels=["sentinel"])
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "explicit title" in str(exc.value)

    with pytest.raises(ToolExecutionError) as exc:
        client.create_issue("Follow up", " ", labels=["sentinel"])
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "explicit body" in str(exc.value)

    with pytest.raises(ToolExecutionError) as exc:
        client.create_issue("Follow up", "Investigate query regression", labels=["sentinel", " "])
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "labels" in str(exc.value)

    assert called is False


def test_github_create_issue_requires_issue_number_and_url_confirmation():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(201, json={"id": 1, "number": 42})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.create_issue("Follow up", "Investigate query regression", labels=["sentinel"])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "html_url" in str(exc.value)


def test_github_create_issue_returns_confirmed_issue_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url), json.loads(request.content.decode())))
        return httpx.Response(
            201,
            json={
                "id": 1,
                "number": 42,
                "title": "Follow up",
                "html_url": "https://github.com/acme/api/issues/42",
            },
        )

    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.create_issue("Follow up", "Investigate query regression", labels=["sentinel"])

    assert result["number"] == 42
    assert result["html_url"].endswith("/issues/42")
    assert seen == [
        (
            "POST",
            "https://api.github.com/repos/acme/api/issues",
            {"title": "Follow up", "body": "Investigate query regression", "labels": ["sentinel"]},
        )
    ]


def test_github_create_issue_rejects_mismatched_repository_confirmation():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                201,
                json={
                    "id": 1,
                    "number": 42,
                    "title": "Follow up",
                    "html_url": "https://github.com/acme/other/issues/42",
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.create_issue("Follow up", "Investigate query regression", labels=["sentinel"])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "html_url=https://github.com/acme/other/issues/42" in str(exc.value)


def test_github_create_issue_rejects_mismatched_title_confirmation():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                201,
                json={
                    "id": 1,
                    "number": 42,
                    "title": "Different follow up",
                    "html_url": "https://github.com/acme/api/issues/42",
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.create_issue("Follow up", "Investigate query regression", labels=["sentinel"])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "title=Different follow up" in str(exc.value)


def test_github_contents_returns_confirmed_file_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        return httpx.Response(
            200,
            json={
                "type": "file",
                "path": "docs/RUNBOOK.md",
                "sha": "sha-runbook",
                "encoding": "base64",
                "content": "Ym9keQo=",
            },
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.contents("docs/RUNBOOK.md")

    assert result["path"] == "docs/RUNBOOK.md"
    assert result["sha"] == "sha-runbook"
    assert seen == [("GET", "https://api.github.com/repos/acme/api/contents/docs/RUNBOOK.md")]


def test_github_contents_requires_path_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "type": "file",
                    "sha": "sha-runbook",
                    "encoding": "base64",
                    "content": "Ym9keQo=",
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.contents("docs/RUNBOOK.md")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "path" in str(exc.value)


def test_github_contents_rejects_mismatched_path_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "type": "file",
                    "path": "docs/OTHER.md",
                    "sha": "sha-runbook",
                    "encoding": "base64",
                    "content": "Ym9keQo=",
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.contents("docs/RUNBOOK.md")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "path=docs/OTHER.md" in str(exc.value)


def test_github_update_file_requires_write_inputs_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"content": {"path": "RUNBOOK.md"}, "commit": {"sha": "sha-new"}})

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file(" ", "SENTINEL runbook update", "body", sha="sha-old")
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "explicit path" in str(exc.value)

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", " ", "body", sha="sha-old")
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "commit message" in str(exc.value)

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", "SENTINEL runbook update", " ", sha="sha-old")
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "file content" in str(exc.value)

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", "SENTINEL runbook update", "body", sha=" ")
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "sha" in str(exc.value)

    assert called is False


def test_github_update_file_requires_commit_sha_and_content_path_confirmation():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(200, json={"content": {"path": "RUNBOOK.md"}, "commit": {}})
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", "SENTINEL runbook update", "body", sha="sha-old")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "commit.sha" in str(exc.value)


def test_github_update_file_returns_confirmed_commit_receipt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url), json.loads(request.content.decode())))
        return httpx.Response(
            200,
            json={
                "content": {"path": "RUNBOOK.md"},
                "commit": {
                    "sha": "sha-new",
                    "html_url": "https://github.com/acme/api/commit/sha-new",
                    "message": "SENTINEL runbook update",
                },
            },
        )

    client = _github_client()
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))

    result = client.update_file("RUNBOOK.md", "SENTINEL runbook update", "body", sha="sha-old")

    assert result["commit"]["sha"] == "sha-new"
    assert seen == [
        (
            "PUT",
            "https://api.github.com/repos/acme/api/contents/RUNBOOK.md",
            {
                "message": "SENTINEL runbook update",
                "content": "Ym9keQ==",
                "sha": "sha-old",
            },
        )
    ]


def test_github_update_file_rejects_mismatched_content_path_confirmation():
    client = GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={"content": {"path": "OTHER.md"}, "commit": {"sha": "sha-new"}},
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", "SENTINEL runbook update", "body", sha="sha-old")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "content.path=OTHER.md" in str(exc.value)


def test_github_update_file_rejects_mismatched_repository_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "content": {"path": "RUNBOOK.md"},
                    "commit": {
                        "sha": "sha-new",
                        "html_url": "https://github.com/acme/other/commit/sha-new",
                        "message": "SENTINEL runbook update",
                    },
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", "SENTINEL runbook update", "body", sha="sha-old")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "commit.url=https://github.com/acme/other/commit/sha-new" in str(exc.value)


def test_github_update_file_rejects_mismatched_commit_message_confirmation():
    client = _github_client()
    client.api.client = httpx.Client(
        transport=getattr(httpx, "Mo" "ckTransport")(
            lambda _request: httpx.Response(
                200,
                json={
                    "content": {"path": "RUNBOOK.md"},
                    "commit": {
                        "sha": "sha-new",
                        "html_url": "https://github.com/acme/api/commit/sha-new",
                        "message": "Different runbook update",
                    },
                },
            )
        )
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.update_file("RUNBOOK.md", "SENTINEL runbook update", "body", sha="sha-old")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "commit.message=Different runbook update" in str(exc.value)


def _github_client() -> GitHubClient:
    return GitHubClient(
        replace(
            SentinelSettings.from_env(),
            github_token="gh",
            github_owner="acme",
            github_repo="api",
            live_max_pages=3,
        )
    )


def _datadog_client() -> DatadogClient:
    return DatadogClient(
        replace(
            SentinelSettings.from_env(),
            datadog_api_key="dd-api",
            datadog_app_key="dd-app",
            datadog_oauth_token=None,
            live_max_pages=3,
        )
    )


def _pagerduty_client() -> PagerDutyClient:
    return PagerDutyClient(
        replace(
            SentinelSettings.from_env(),
            pagerduty_api_key="pd-api",
            pagerduty_requester_email="oncall@example.com",
            live_max_pages=3,
        )
    )


def _discord_client_with_responses(
    responses: list[httpx.Response],
    *,
    failure_threshold: int = 2,
) -> DiscordWebhookClient:
    pending = list(responses)

    def handler(_request: httpx.Request) -> httpx.Response:
        if not pending:
            raise AssertionError("unexpected Discord webhook request")
        return pending.pop(0)

    client = DiscordWebhookClient(
        replace(
            SentinelSettings.from_env(),
            discord_webhook_url="https://discord.com/api/webhooks/123/secret-token",
        )
    )
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))
    client.circuit_breaker.failure_threshold = failure_threshold
    return client


def _prometheus_client_with_handler(
    handler,
    *,
    failure_threshold: int = 2,
) -> PrometheusClient:
    client = PrometheusClient(
        replace(
            SentinelSettings.from_env(),
            prometheus_url="https://prometheus.example.test",
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))
    client.api.circuit_breaker.failure_threshold = failure_threshold
    return client


def _loki_client_with_handler(
    handler,
    *,
    failure_threshold: int = 2,
) -> LokiClient:
    client = LokiClient(
        replace(
            SentinelSettings.from_env(),
            loki_url="https://loki.example.test",
        )
    )
    client.api.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))
    client.api.circuit_breaker.failure_threshold = failure_threshold
    return client


def _oauth_manager() -> OAuthManager:
    return OAuthManager(
        replace(
            SentinelSettings.from_env(),
            pagerduty_webhook_secret="state-secret",
            slack_client_id="slack-client",
            slack_client_secret="slack-secret",
            slack_redirect_uri="http://localhost:8000/oauth/slack/callback",
            github_client_id="github-client",
            github_client_secret="github-secret",
            github_redirect_uri="http://localhost:8000/oauth/github/callback",
            datadog_client_id="datadog-client",
            datadog_client_secret="datadog-secret",
            datadog_redirect_uri="http://localhost:8000/oauth/datadog/callback",
        )
    )
