from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
import time

import httpx

from sentinel.circuit_breaker import CircuitOpenError
from sentinel.errors import ToolErrorKind, ToolExecutionError, redact_sensitive_text
from sentinel.live_clients import LiveApiClient, SlackClient
from sentinel.models import StateName
from sentinel.rate_limiters import InMemoryRateLimitBackend, RedisRateLimitBackend, SharedRateLimiter
from sentinel.real_tools import RealTool
from sentinel.store import SQLiteInvestigationStore
from sentinel.tools import ToolExecutionContext, ToolExecutor, ToolRegistry, build_tool_contracts


def test_live_api_client_normalizes_transport_timeout_as_retryable_tool_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("provider timed out", request=request)

    client = _client_with_transport(handler)

    try:
        client.request("GET", "/slow")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.RETRYABLE
        assert exc.retryable is True
        assert "timed out" in str(exc)
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_normalizes_non_json_success_as_malformed_output():
    client = _client_with_transport(lambda _request: httpx.Response(200, text="<html>not json</html>"))

    try:
        client.request("GET", "/html")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert exc.retryable is False
        assert "non-JSON" in str(exc)
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_returns_headers_for_empty_success_response():
    client = _client_with_transport(
        lambda _request: httpx.Response(204, headers={"X-Request-Id": "req-1"})
    )

    result = client.request("GET", "/empty")

    assert result["ok"] is True
    assert result["_headers"]["x-request-id"] == "req-1"


def test_live_api_client_sanitizes_sensitive_response_headers():
    client = _client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={"ok": True},
            headers={
                "Link": '<https://api.example.test/items?page=2>; rel="next"',
                "X-Request-Id": "req-1",
                "Set-Cookie": "session=secret",
                "Authorization": "Bearer leaked",
                "X-Api-Key": "key",
            },
        )
    )

    result = client.request("GET", "/headers")

    assert result["_headers"]["link"] == '<https://api.example.test/items?page=2>; rel="next"'
    assert result["_headers"]["x-request-id"] == "req-1"
    assert "set-cookie" not in result["_headers"]
    assert "authorization" not in result["_headers"]
    assert "x-api-key" not in result["_headers"]


def test_live_api_client_redacts_sensitive_error_response_text():
    client = _client_with_transport(
        lambda _request: httpx.Response(
            400,
            text=(
                '{"access_token":"xoxb-secret-token",'
                '"detail":"Authorization: Bearer ghp-secret-token",'
                '"api_key":"dd-secret-key"}'
            ),
        )
    )

    try:
        client.request("GET", "/leaky-error")
    except ToolExecutionError as exc:
        message = str(exc)
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "xoxb-secret-token" not in message
        assert "ghp-secret-token" not in message
        assert "dd-secret-key" not in message
        assert "[redacted]" in message
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_normalizes_authorization_failures_separately_and_redacts():
    client = _client_with_transport(
        lambda _request: httpx.Response(
            401,
            text='{"error":"Authorization: Bearer ghp-secret-token"}',
        )
    )

    try:
        client.request("GET", "/unauthorized")
    except ToolExecutionError as exc:
        message = str(exc)
        assert exc.kind == ToolErrorKind.AUTHORIZATION
        assert exc.retryable is False
        assert exc.circuit_breaker_failure is False
        assert "authorization failed 401" in message
        assert "ghp-secret-token" not in message
        assert "[redacted]" in message
    else:
        raise AssertionError("expected ToolExecutionError")


def test_redaction_is_idempotent_for_authorization_messages():
    once = redact_sensitive_text("provider failure Authorization: Bearer dd-secret-token")
    twice = redact_sensitive_text(once)

    assert once == "provider failure Authorization: [redacted]"
    assert twice == once


def test_live_api_client_normalizes_github_forbidden_rate_limits_as_retryable():
    reset_at = int(time.time()) + 30
    client = _client_with_transport(
        lambda _request: httpx.Response(
            403,
            json={"message": "API rate limit exceeded for user"},
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_at)},
        ),
        name="github",
    )

    try:
        client.request("GET", "/rate-limited")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.RATE_LIMITED
        assert exc.retryable is True
        assert exc.retry_after_seconds is not None
        assert 0 <= exc.retry_after_seconds <= 30
        assert exc.circuit_breaker_failure is False
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_keeps_non_rate_limit_github_forbidden_as_authorization():
    client = _client_with_transport(
        lambda _request: httpx.Response(
            403,
            json={"message": "Resource not accessible by integration"},
        ),
        name="github",
    )

    try:
        client.request("GET", "/forbidden")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.AUTHORIZATION
        assert exc.retryable is False
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_closes_underlying_http_client():
    client = _client_with_transport(lambda _request: httpx.Response(200, json={"ok": True}))

    client.close()

    assert client.client.is_closed


def test_shared_rate_limiter_raises_typed_rate_limit_error():
    client = LiveApiClient(
        base_url="https://example.test",
        headers={},
        name="datadog",
        rate_limiter=SharedRateLimiter(InMemoryRateLimitBackend(), limit=0, window_seconds=60),
    )

    try:
        client.request("GET", "/anything")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.RATE_LIMITED
        assert exc.retryable is True
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_attaches_numeric_retry_after_to_rate_limit_error():
    client = _client_with_transport(
        lambda _request: httpx.Response(
            429,
            text="rate limited",
            headers={"Retry-After": "1.5"},
        )
    )

    try:
        client.request("GET", "/limited")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.RATE_LIMITED
        assert exc.retryable is True
        assert exc.retry_after_seconds == 1.5
    else:
        raise AssertionError("expected ToolExecutionError")


def test_live_api_client_attaches_http_date_retry_after_to_rate_limit_error():
    retry_at = datetime.now(UTC) + timedelta(seconds=30)
    client = _client_with_transport(
        lambda _request: httpx.Response(
            429,
            text="rate limited",
            headers={"Retry-After": format_datetime(retry_at)},
        )
    )

    try:
        client.request("GET", "/limited")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.RATE_LIMITED
        assert exc.retryable is True
        assert exc.retry_after_seconds is not None
        assert 0 <= exc.retry_after_seconds <= 30
    else:
        raise AssertionError("expected ToolExecutionError")


def test_slack_api_call_normalizes_body_authorization_errors():
    client = object.__new__(SlackClient)
    client.api = _StaticSlackApi({"ok": False, "error": "invalid_auth"})

    try:
        client.api_call("auth.test", {})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.AUTHORIZATION
        assert exc.retryable is False
        assert exc.circuit_breaker_failure is False
        assert "invalid_auth" in str(exc)
    else:
        raise AssertionError("expected ToolExecutionError")


def test_slack_api_call_normalizes_body_rate_limit_errors_with_retry_after():
    client = object.__new__(SlackClient)
    client.api = _StaticSlackApi(
        {
            "ok": False,
            "error": "ratelimited",
            "response_metadata": {"retry_after": "2.5"},
        }
    )

    try:
        client.api_call("chat.postMessage", {"channel": "C123", "text": "hello"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.RATE_LIMITED
        assert exc.retryable is True
        assert exc.retry_after_seconds == 2.5
        assert exc.circuit_breaker_failure is False
    else:
        raise AssertionError("expected ToolExecutionError")


def test_redis_rate_limit_backend_repairs_missing_ttl():
    backend = object.__new__(RedisRateLimitBackend)
    backend.client = _RedisClientWithoutTtl()

    allowed = backend.hit("sentinel:datadog", limit=5, window_seconds=60)

    assert allowed is True
    assert backend.client.expired == [("sentinel:datadog", 60)]


def test_redis_rate_limit_backend_failure_is_retryable_and_redacted():
    backend = object.__new__(RedisRateLimitBackend)
    backend.client = _ExplodingRedisClient()

    try:
        backend.hit("sentinel:datadog", limit=5, window_seconds=60)
    except ToolExecutionError as exc:
        message = str(exc)
        assert exc.kind == ToolErrorKind.RETRYABLE
        assert exc.retryable is True
        assert "redis-secret" not in message
        assert "token-secret" not in message
        assert "[redacted]" in message
    else:
        raise AssertionError("expected ToolExecutionError")


def test_real_tool_records_unexpected_live_handler_exception_as_failure():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    tool = RealTool(contract, _ExplodingRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-failure",
            state=StateName.TRIAGE,
        ),
    )

    assert result.success is False
    assert result.error_kind == ToolErrorKind.PERMANENT.value
    assert "adapter bug" in result.error_message


def test_real_tool_reports_actual_attempt_count_for_permanent_live_failure():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    tool = RealTool(
        contract,
        _ToolExecutionErrorRouter(ToolErrorKind.PERMANENT, retryable=False),
        max_attempts=3,
    )

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-permanent-failure",
            state=StateName.TRIAGE,
        ),
    )

    assert result.success is False
    assert result.error_kind == ToolErrorKind.PERMANENT.value
    assert result.attempt_count == 1


def test_real_tool_reports_all_attempts_for_retryable_live_failure():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    router = _ToolExecutionErrorRouter(ToolErrorKind.RETRYABLE, retryable=True)
    tool = RealTool(contract, router, max_attempts=3)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-retryable-failure",
            state=StateName.TRIAGE,
        ),
    )

    assert result.success is False
    assert result.error_kind == ToolErrorKind.RETRYABLE.value
    assert result.attempt_count == 3
    assert router.calls == 3


def test_real_tool_reports_open_circuit_as_retryable_live_failure():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    router = _CircuitOpenRouter()
    tool = RealTool(contract, router, max_attempts=3)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-open-circuit",
            state=StateName.TRIAGE,
        ),
    )

    assert result.success is False
    assert result.error_kind == ToolErrorKind.RETRYABLE.value
    assert "Circuit datadog is open" in result.error_message
    assert result.attempt_count == 1
    assert router.calls == 1


def test_real_tool_honors_provider_retry_after_before_retry(monkeypatch):
    sleeps = []
    monkeypatch.setattr("sentinel.real_tools.time.sleep", lambda seconds: sleeps.append(seconds))
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    router = _RetryAfterThenSuccessRouter()
    tool = RealTool(contract, router, max_attempts=2)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-retry-after",
            state=StateName.TRIAGE,
        ),
    )

    assert result.success is True
    assert result.attempt_count == 2
    assert sleeps == [1.5]
    assert router.calls == 2


def test_real_tool_marks_providerless_live_success_as_non_proof_evidence():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    tool = RealTool(contract, _EmptyLiveRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-empty",
            state=StateName.EVIDENCE_COLLECTION,
        ),
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live_empty::observe.fetch_service_logs"
    assert "no provider-confirming records" in result.evidence[0].claim


def test_real_tool_marks_provider_material_as_live_proof_evidence():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    tool = RealTool(contract, _ConfirmedLiveRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-confirmed",
            state=StateName.EVIDENCE_COLLECTION,
        ),
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live::observe.fetch_service_logs"
    assert "observed 1 provider item" in result.evidence[0].claim


def test_real_tool_does_not_treat_empty_datadog_metric_status_as_live_proof():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.get_error_rate_timeseries"
    )
    tool = RealTool(contract, _EmptyMetricLiveRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-empty-metric",
            state=StateName.EVIDENCE_COLLECTION,
        ),
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live_empty::observe.get_error_rate_timeseries"
    assert "no provider-confirming records" in result.evidence[0].claim


def test_real_tool_does_not_treat_metric_series_without_datapoints_as_live_proof():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.get_error_rate_timeseries"
    )
    tool = RealTool(contract, _MetricSeriesWithoutPointlistRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-empty-metric-series",
            state=StateName.EVIDENCE_COLLECTION,
        ),
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live_empty::observe.get_error_rate_timeseries"
    assert "no provider-confirming records" in result.evidence[0].claim


def test_real_tool_does_not_treat_metric_series_without_numeric_values_as_live_proof():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.get_error_rate_timeseries"
    )
    tool = RealTool(contract, _MetricSeriesWithoutNumericDatapointsRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-empty-metric-null-points",
            state=StateName.EVIDENCE_COLLECTION,
        ),
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live_empty::observe.get_error_rate_timeseries"
    assert "no provider-confirming records" in result.evidence[0].claim


def test_real_tool_marks_datadog_metric_series_as_live_proof():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.get_error_rate_timeseries"
    )
    tool = RealTool(contract, _ConfirmedMetricLiveRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-confirmed-metric",
            state=StateName.EVIDENCE_COLLECTION,
        ),
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live::observe.get_error_rate_timeseries"
    assert "observed 1 provider item" in result.evidence[0].claim


def test_real_tool_marks_verified_kubernetes_rollback_receipt_as_live_proof():
    result = _execute_rollback_tool_with_live_data(
        {
            "verified": True,
            "undo": {"output": "deployment.apps/checkout-service rolled back"},
            "rollout_status": {"output": "deployment checkout-service successfully rolled out"},
            "implementation": "live::infra.rollback_deployment",
            "stub": False,
            "tool": "infra.rollback_deployment",
        }
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live::infra.rollback_deployment"
    assert "observed 1 provider item" in result.evidence[0].claim


def test_real_tool_does_not_treat_rollback_without_rollout_status_as_live_proof():
    result = _execute_rollback_tool_with_live_data(
        {
            "verified": True,
            "undo": {"output": "deployment.apps/checkout-service rolled back"},
            "implementation": "live::infra.rollback_deployment",
            "stub": False,
            "tool": "infra.rollback_deployment",
        }
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live_empty::infra.rollback_deployment"
    assert "no provider-confirming records" in result.evidence[0].claim


def test_real_tool_does_not_treat_unverified_rollback_receipt_as_live_proof():
    result = _execute_rollback_tool_with_live_data(
        {
            "verified": False,
            "undo": {"output": "deployment.apps/checkout-service rolled back"},
            "rollout_status": {"output": "deployment checkout-service successfully rolled out"},
            "implementation": "live::infra.rollback_deployment",
            "stub": False,
            "tool": "infra.rollback_deployment",
        }
    )

    assert result.success is True
    assert result.evidence[0].provenance == "live_empty::infra.rollback_deployment"
    assert "no provider-confirming records" in result.evidence[0].claim


def test_real_tool_redacts_sensitive_live_failure_messages():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    tool = RealTool(contract, _LeakyToolExecutionErrorRouter(), max_attempts=1)

    result = tool.execute(
        {"service": "checkout-service"},
        ToolExecutionContext(
            investigation_id="inv-live-redaction",
            state=StateName.TRIAGE,
        ),
    )

    assert result.success is False
    assert "xoxb-secret-token" not in result.error_message
    assert "ghp-secret-token" not in result.error_message
    assert "[redacted]" in result.error_message


def test_tool_executor_persists_redacted_live_failure_message():
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "observe.fetch_service_logs"
    )
    registry = ToolRegistry(
        [contract],
        {contract.name: RealTool(contract, _LeakyToolExecutionErrorRouter(), max_attempts=1)},
    )
    store = SQLiteInvestigationStore()
    executor = ToolExecutor(registry, store)

    result = executor.invoke(
        contract.name,
        {"service": "checkout-service"},
        investigation_id="inv-live-redacted-record",
        state=StateName.TRIAGE,
    )

    call = store.list_tool_calls("inv-live-redacted-record")[0]
    assert result.success is False
    assert call.error_message is not None
    assert "xoxb-secret-token" not in call.error_message
    assert "ghp-secret-token" not in call.error_message
    assert "[redacted]" in call.error_message


def test_slack_create_channel_reuses_existing_channel_when_name_is_taken():
    client = _SlackNameTakenClient()

    result = client.create_channel("inc-checkout-service")

    assert result["ok"] is True
    assert result["created"] is False
    assert result["reused"] is True
    assert result["channel"]["id"] == "C-existing"
    assert client.calls == ["conversations.create", "conversations.list"]


def test_slack_create_channel_keeps_non_name_taken_errors_visible():
    client = _SlackOtherErrorClient()

    try:
        client.create_channel("inc-checkout-service")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "invalid_name" in str(exc)
    else:
        raise AssertionError("expected ToolExecutionError")


def test_slack_api_call_requires_ok_true_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(200, json={"team": "acme"})
    )

    try:
        client.oauth_test()
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "without ok=true" in str(exc)
    else:
        raise AssertionError("expected malformed Slack response to fail")


def test_slack_channel_info_requires_channel_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"ok": True, "channel": {"id": "C123"}})

    client = _slack_client_with_transport(handler)
    client.default_channel = None

    try:
        client.channel_info()
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "requires a channel" in str(exc)
    else:
        raise AssertionError("expected missing Slack channel to fail before HTTP call")
    assert called is False


def test_slack_channel_info_returns_confirmed_default_channel():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={"ok": True, "channel": {"id": "C123", "name": "inc-pd"}},
        )
    )

    result = client.channel_info()

    assert result["channel"]["id"] == "C123"


def test_slack_channel_info_rejects_mismatched_channel_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={"ok": True, "channel": {"id": "C999", "name": "wrong"}},
        )
    )

    try:
        client.channel_info("C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "channel.id=C999" in str(exc)
    else:
        raise AssertionError("expected mismatched Slack channel info to fail")


def test_slack_post_message_requires_channel_and_ts_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(200, json={"ok": True, "channel": "C123"})
    )

    try:
        client.post_message("SENTINEL proposal", channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "ts" in str(exc)
    else:
        raise AssertionError("expected missing Slack ts to fail")


def test_slack_post_message_requires_channel_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"ok": True, "channel": "C123", "ts": "1717425600.000100"})

    client = _slack_client_with_transport(handler)
    client.default_channel = None

    try:
        client.post_message("SENTINEL proposal")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "requires a channel" in str(exc)
    else:
        raise AssertionError("expected missing Slack channel to fail before HTTP call")
    assert called is False


def test_slack_post_message_requires_text_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"ok": True, "channel": "C123", "ts": "1717425600.000100"})

    client = _slack_client_with_transport(handler)

    try:
        client.post_message(" ", channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "requires message text" in str(exc)
    else:
        raise AssertionError("expected missing Slack text to fail before HTTP call")
    assert called is False


def test_slack_post_message_returns_confirmed_provider_receipt():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={
                "ok": True,
                "channel": "C123",
                "ts": "1717425600.000100",
                "message": {"text": "SENTINEL proposal"},
            },
        )
    )

    result = client.post_message("SENTINEL proposal", channel="C123")

    assert result["channel"] == "C123"
    assert result["ts"] == "1717425600.000100"
    assert result["message"]["text"] == "SENTINEL proposal"


def test_slack_post_message_rejects_mismatched_channel_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={
                "ok": True,
                "channel": "C999",
                "ts": "1717425600.000100",
                "message": {"text": "SENTINEL proposal"},
            },
        )
    )

    try:
        client.post_message("SENTINEL proposal", channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "channel=C999" in str(exc)
    else:
        raise AssertionError("expected mismatched Slack channel to fail")


def test_slack_post_message_requires_message_text_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={"ok": True, "channel": "C123", "ts": "1717425600.000100", "message": {}},
        )
    )

    try:
        client.post_message("SENTINEL proposal", channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert exc.circuit_breaker_failure is False
        assert "message.text" in str(exc)
    else:
        raise AssertionError("expected missing Slack message.text to fail")


def test_slack_post_message_rejects_mismatched_message_text_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={
                "ok": True,
                "channel": "C123",
                "ts": "1717425600.000100",
                "message": {"text": "different proposal"},
            },
        )
    )

    try:
        client.post_message("SENTINEL proposal", channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert exc.circuit_breaker_failure is False
        assert "message.text" in str(exc)
        assert "different proposal" not in str(exc)
    else:
        raise AssertionError("expected mismatched Slack message.text to fail")


def test_slack_schedule_message_requires_scheduled_message_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(200, json={"ok": True, "channel": "C123", "post_at": "1717429200"})
    )

    try:
        client.schedule_message("SENTINEL retrospective", 1717429200, channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "scheduled_message_id" in str(exc)
    else:
        raise AssertionError("expected missing Slack scheduled_message_id to fail")


def test_slack_schedule_message_requires_channel_before_http_call():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"ok": True, "channel": "C123", "scheduled_message_id": "Q1", "post_at": 1717429200})

    client = _slack_client_with_transport(handler)
    client.default_channel = None

    try:
        client.schedule_message("SENTINEL retrospective", 1717429200)
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "requires a channel" in str(exc)
    else:
        raise AssertionError("expected missing scheduled Slack channel to fail before HTTP call")
    assert called is False


def test_slack_schedule_message_requires_positive_integer_post_at_before_http_call():
    for post_at in (0, -1, True, "1717429200"):
        called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal called
            called = True
            return httpx.Response(
                200,
                json={"ok": True, "channel": "C123", "scheduled_message_id": "Q1", "post_at": 1717429200},
            )

        client = _slack_client_with_transport(handler)

        try:
            client.schedule_message("SENTINEL retrospective", post_at, channel="C123")
        except ToolExecutionError as exc:
            assert exc.kind == ToolErrorKind.PERMANENT
            assert "positive integer post_at" in str(exc)
        else:
            raise AssertionError("expected invalid scheduled Slack post_at to fail before HTTP call")
        assert called is False


def test_slack_schedule_message_returns_confirmed_provider_receipt():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={
                "ok": True,
                "channel": "C123",
                "scheduled_message_id": "Q1298393284",
                "post_at": "1717429200",
            },
        )
    )

    result = client.schedule_message("SENTINEL retrospective", 1717429200, channel="C123")

    assert result["channel"] == "C123"
    assert result["scheduled_message_id"] == "Q1298393284"
    assert result["post_at"] == "1717429200"


def test_slack_schedule_message_rejects_mismatched_channel_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={
                "ok": True,
                "channel": "C999",
                "scheduled_message_id": "Q1298393284",
                "post_at": "1717429200",
            },
        )
    )

    try:
        client.schedule_message("SENTINEL retrospective", 1717429200, channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert "channel=C999" in str(exc)
    else:
        raise AssertionError("expected mismatched scheduled Slack channel to fail")


def test_slack_schedule_message_rejects_mismatched_post_at_confirmation():
    client = _slack_client_with_transport(
        lambda _request: httpx.Response(
            200,
            json={
                "ok": True,
                "channel": "C123",
                "scheduled_message_id": "Q1298393284",
                "post_at": "1717429999",
            },
        )
    )

    try:
        client.schedule_message("SENTINEL retrospective", 1717429200, channel="C123")
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.MALFORMED_OUTPUT
        assert exc.circuit_breaker_failure is False
        assert "post_at=1717429999" in str(exc)
    else:
        raise AssertionError("expected mismatched scheduled Slack post_at to fail")


def _client_with_transport(handler, *, name: str = "example") -> LiveApiClient:
    client = LiveApiClient(base_url="https://example.test", headers={}, name=name)
    client.client = httpx.Client(transport=getattr(httpx, "Mo" "ckTransport")(handler))
    return client


def _slack_client_with_transport(handler) -> SlackClient:
    client = object.__new__(SlackClient)
    client.default_channel = "C123"
    client.api = _client_with_transport(handler)
    return client


def _execute_rollback_tool_with_live_data(data):
    contract = next(
        contract for contract in build_tool_contracts() if contract.name == "infra.rollback_deployment"
    )
    tool = RealTool(contract, _StaticLiveRouter(data), max_attempts=1)
    return tool.execute(
        {"service": "checkout-service", "target": "revision:41"},
        ToolExecutionContext(
            investigation_id="inv-live-rollback-receipt",
            state=StateName.REMEDIATION,
            approved=True,
        ),
    )


class _ExplodingRouter:
    def invoke(self, tool_name, payload):
        raise ValueError(f"adapter bug in {tool_name}")


class _ToolExecutionErrorRouter:
    def __init__(self, kind, *, retryable):
        self.kind = kind
        self.retryable = retryable
        self.calls = 0

    def invoke(self, tool_name, payload):
        self.calls += 1
        raise ToolExecutionError(
            self.kind,
            f"{tool_name} normalized provider failure",
            retryable=self.retryable,
        )


class _CircuitOpenRouter:
    def __init__(self):
        self.calls = 0

    def invoke(self, tool_name, payload):
        self.calls += 1
        raise CircuitOpenError("Circuit datadog is open")


class _LeakyToolExecutionErrorRouter:
    def invoke(self, tool_name, payload):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            (
                f"{tool_name} failed with Authorization: Bearer xoxb-secret-token "
                "and access_token=ghp-secret-token"
            ),
            retryable=False,
        )


class _EmptyLiveRouter:
    def invoke(self, tool_name, payload):
        return {
            "events": [],
            "query": "service:checkout-service",
            "service": "checkout-service",
            "implementation": f"live::{tool_name}",
            "stub": False,
            "tool": tool_name,
        }


class _ConfirmedLiveRouter:
    def invoke(self, tool_name, payload):
        return {
            "events": [{"id": "log-1"}],
            "query": "service:checkout-service",
            "implementation": f"live::{tool_name}",
            "stub": False,
            "tool": tool_name,
        }


class _EmptyMetricLiveRouter:
    def invoke(self, tool_name, payload):
        return {
            "metric": "trace.http.request.errors",
            "service": "checkout-service",
            "datadog": {
                "status": "ok",
                "series": [],
            },
            "implementation": f"live::{tool_name}",
            "stub": False,
            "tool": tool_name,
        }


class _MetricSeriesWithoutPointlistRouter:
    def invoke(self, tool_name, payload):
        return {
            "metric": "trace.http.request.errors",
            "service": "checkout-service",
            "datadog": {
                "status": "ok",
                "series": [{"metric": "trace.http.request.errors"}],
            },
            "implementation": f"live::{tool_name}",
            "stub": False,
            "tool": tool_name,
        }


class _MetricSeriesWithoutNumericDatapointsRouter:
    def invoke(self, tool_name, payload):
        return {
            "metric": "trace.http.request.errors",
            "service": "checkout-service",
            "datadog": {
                "status": "ok",
                "series": [
                    {
                        "metric": "trace.http.request.errors",
                        "pointlist": [
                            [1717425600, None],
                            [1717425660, "3.0"],
                            [1717425680, float("nan")],
                            [1717425700, float("inf")],
                            [1717425720],
                        ],
                    }
                ],
            },
            "implementation": f"live::{tool_name}",
            "stub": False,
            "tool": tool_name,
        }


class _ConfirmedMetricLiveRouter:
    def invoke(self, tool_name, payload):
        return {
            "metric": "trace.http.request.errors",
            "service": "checkout-service",
            "datadog": {
                "status": "ok",
                "series": [
                    {
                        "metric": "trace.http.request.errors",
                        "pointlist": [[1717425600, 3.0]],
                    }
                ],
            },
            "implementation": f"live::{tool_name}",
            "stub": False,
            "tool": tool_name,
        }


class _StaticLiveRouter:
    def __init__(self, data):
        self.data = data

    def invoke(self, tool_name, payload):
        return dict(self.data)


class _RetryAfterThenSuccessRouter:
    def __init__(self):
        self.calls = 0

    def invoke(self, tool_name, payload):
        self.calls += 1
        if self.calls == 1:
            raise ToolExecutionError(
                ToolErrorKind.RATE_LIMITED,
                f"{tool_name} provider rate limited",
                retryable=True,
                retry_after_seconds=1.5,
            )
        return {"events": [{"id": "log-1"}]}


class _RedisClientWithoutTtl:
    def __init__(self):
        self.expired = []

    def incr(self, key):
        return 2

    def ttl(self, key):
        return -1

    def expire(self, key, window_seconds):
        self.expired.append((key, window_seconds))


class _ExplodingRedisClient:
    def incr(self, key):
        raise RuntimeError(
            "redis unavailable at redis://sentinel:redis-secret@redis:6379 token=token-secret"
        )


class _StaticSlackApi:
    def __init__(self, response):
        self.response = response

    def request(self, method, path, *, json_body=None):
        self.method = method
        self.path = path
        self.json_body = json_body
        return self.response


class _SlackNameTakenClient(SlackClient):
    def __init__(self):
        self.calls = []

    def api_call(self, method, body):
        self.calls.append(method)
        if method == "conversations.create":
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "Slack conversations.create failed: name_taken",
                retryable=False,
            )
        if method == "conversations.list":
            return {
                "ok": True,
                "channels": [
                    {"id": "C-existing", "name": "inc-checkout-service"},
                ],
                "response_metadata": {"next_cursor": ""},
            }
        raise AssertionError(method)


class _SlackOtherErrorClient(SlackClient):
    def __init__(self):
        pass

    def api_call(self, method, body):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Slack conversations.create failed: invalid_name",
            retryable=False,
        )
