from datetime import UTC, datetime, timedelta
from dataclasses import replace

from sentinel.config import SentinelSettings
from sentinel.connectivity import run_live_connectivity_checks
from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.store import SQLiteInvestigationStore


def test_connectivity_report_keeps_infra_checks_but_skips_provider_network_when_credentials_missing(monkeypatch):
    called = []
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(SentinelSettings.from_env(), store=SQLiteInvestigationStore())

    assert report.ready is False
    assert report.missing_live_credentials
    assert called == []
    assert [check.name for check in report.checks] == ["sentinel.state_store", "sentinel.redis"]
    assert report.checks[0].passed is False
    assert report.checks[1].passed is False
    assert "DATABASE_URL" in report.checks[0].detail
    assert "REDIS_URL" in report.checks[1].detail
    assert report.checks[0].sample == {"configured": False}
    assert report.checks[1].sample == {"configured": False}


def test_connectivity_report_returns_structured_invalid_env_configuration(monkeypatch):
    monkeypatch.setenv("SENTINEL_LIVE_MAX_PAGES", "0")

    report = run_live_connectivity_checks()

    assert report.ready is False
    assert report.missing_live_credentials == []
    assert len(report.checks) == 1
    failed = report.checks[0]
    assert failed.name == "sentinel.config"
    assert failed.provider == "sentinel"
    assert failed.passed is False
    assert "SENTINEL_LIVE_MAX_PAGES" in failed.detail


def test_connectivity_report_returns_structured_store_failure(monkeypatch):
    settings = replace(
        _ready_settings(),
        database_url="postgresql://sentinel:secret@db/sentinel",
    )

    def fail_store(database_url):
        raise RuntimeError(
            "Postgres unavailable with api_key=dd-secret-key Authorization: Bearer ghp-secret-token"
        )

    monkeypatch.setattr("sentinel.connectivity.build_store", fail_store)

    report = run_live_connectivity_checks(settings)

    assert report.ready is False
    assert report.missing_live_credentials == []
    assert len(report.checks) == 1
    failed = report.checks[0]
    assert failed.name == "sentinel.state_store"
    assert failed.provider == "sentinel"
    assert failed.passed is False
    assert "dd-secret-key" not in failed.detail
    assert "ghp-secret-token" not in failed.detail
    assert "[redacted]" in failed.detail


def test_connectivity_report_rejects_provided_unreachable_store_before_network(monkeypatch):
    called = []

    class UnreachableStore:
        error = "Postgres unavailable api_key=dd-secret-key Authorization: Bearer ghp-secret-token"

        def ping(self):
            return False

        def load_oauth_token(self, provider):
            raise RuntimeError("token store unavailable")

    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(_ready_settings(), store=UnreachableStore())

    assert report.ready is False
    assert report.missing_live_credentials == []
    assert called == []
    assert len(report.checks) == 1
    failed = report.checks[0]
    assert failed.name == "sentinel.state_store"
    assert failed.provider == "sentinel"
    assert failed.passed is False
    assert "dd-secret-key" not in failed.detail
    assert "ghp-secret-token" not in failed.detail
    assert "[redacted]" in failed.detail


def test_connectivity_report_closes_owned_store_when_credentials_missing(monkeypatch):
    stores = []

    class ClosableStore:
        def __init__(self):
            self.closed = False

        def load_oauth_token(self, provider):
            return None

        def close(self):
            self.closed = True

    def build_stub_store(database_url):
        store = ClosableStore()
        stores.append(store)
        return store

    monkeypatch.setattr("sentinel.connectivity.build_store", build_stub_store)

    report = run_live_connectivity_checks(
        replace(
            SentinelSettings.from_env(),
            database_url="postgresql://sentinel:sentinel@db/sentinel",
        )
    )

    assert report.ready is False
    assert report.missing_live_credentials
    assert stores
    assert stores[0].closed is True


def test_connectivity_report_runs_all_provider_checks_with_stub_clients(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        github_token="gh",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    clients = _StubClients()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())

    assert report.ready is True
    assert clients.closed is True
    assert {check.provider for check in report.checks} == {
        "sentinel",
        "datadog",
        "github",
        "pagerduty",
        "slack",
        "kubernetes",
    }
    assert {check.name for check in report.checks} == {
        "sentinel.state_store",
        "sentinel.redis",
        "datadog.logs",
        "datadog.metrics",
        "datadog.apm_spans",
        "github.commits",
        "github.pull_requests",
        "github.deployments",
        "pagerduty.incidents",
        "pagerduty.on_calls",
        "slack.auth",
        "slack.default_channel",
        "slack.channels",
        "kubernetes.pods",
        "kubernetes.deployments",
        "kubernetes.rollout_revisions",
    }
    assert [check.name for check in report.checks[:2]] == ["sentinel.state_store", "sentinel.redis"]
    assert all(check.passed for check in report.checks)


def test_connectivity_report_uses_free_provider_checks_when_configured(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = replace(
        _ready_settings(),
        datadog_api_key=None,
        datadog_app_key=None,
        prometheus_url="http://prometheus:9090",
        loki_url="http://loki:3100",
        pagerduty_api_key=None,
        pagerduty_webhook_secret=None,
        slack_bot_token=None,
        slack_channel_id=None,
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
    )

    clients = _FreeStubClients()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())

    assert report.ready is True
    assert clients.closed is True
    assert {check.provider for check in report.checks} == {
        "sentinel",
        "prometheus",
        "loki",
        "github",
        "generic_webhook",
        "discord",
        "kubernetes",
    }
    assert {check.name for check in report.checks} == {
        "sentinel.state_store",
        "sentinel.redis",
        "loki.logs",
        "prometheus.metrics",
        "loki.apm_traces",
        "prometheus.alerting_rules",
        "github.commits",
        "github.pull_requests",
        "github.deployments",
        "generic_webhook.approver",
        "discord.webhook",
        "kubernetes.pods",
        "kubernetes.deployments",
        "kubernetes.rollout_revisions",
    }
    assert clients.discord.posts == ["SENTINEL connectivity check"]
    assert clients.prometheus.queries[0] == (
        ('sentinel_demo_info{service="payment-service"}',),
        {},
    )
    assert all(check.passed for check in report.checks)


def test_connectivity_report_uses_oauth_store_tokens_for_provider_clients(monkeypatch):
    _make_redis_reachable(monkeypatch)
    captured = []
    settings = replace(
        _ready_settings(),
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

    def stub_clients_from_settings(resolved):
        captured.append(resolved)
        return _StubClients()

    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        stub_clients_from_settings,
    )

    report = run_live_connectivity_checks(settings, store=store)

    assert report.ready is True
    assert captured
    assert captured[0].datadog_oauth_token == "dd-oauth"
    assert captured[0].datadog_site == "datadoghq.eu"
    assert captured[0].github_token == "gh-oauth"
    assert captured[0].slack_bot_token == "xoxb-oauth"


def test_connectivity_report_rejects_insufficient_stored_datadog_oauth_scopes_before_provider_network(monkeypatch):
    _make_redis_reachable(monkeypatch)
    called = []
    settings = replace(
        _ready_settings(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="dd-oauth",
        scopes=["logs_read_data"],
    )

    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(settings, store=store)

    assert report.ready is False
    assert report.missing_live_credentials == [
        "DD_OAUTH_TOKEN_SCOPE:metrics_read",
        "DD_OAUTH_TOKEN_SCOPE:apm_read",
    ]
    assert called == []
    assert [check.name for check in report.checks] == ["sentinel.state_store", "sentinel.redis"]


def test_connectivity_report_rejects_insufficient_stored_slack_and_github_oauth_scopes_before_provider_network(monkeypatch):
    _make_redis_reachable(monkeypatch)
    called = []
    settings = replace(
        _ready_settings(),
        github_token=None,
        slack_bot_token=None,
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(provider="github", access_token="gh-oauth", scopes=["read:org"])
    store.save_oauth_token(provider="slack", access_token="xoxb-oauth", scopes=["chat:write"])

    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(settings, store=store)

    assert report.ready is False
    assert report.missing_live_credentials == [
        "GITHUB_OAUTH_TOKEN_SCOPE:repo",
        "SLACK_OAUTH_TOKEN_SCOPE:channels:read",
        "SLACK_OAUTH_TOKEN_SCOPE:channels:manage",
        "SLACK_OAUTH_TOKEN_SCOPE:groups:read",
        "SLACK_OAUTH_TOKEN_SCOPE:groups:write",
    ]
    assert called == []
    assert [check.name for check in report.checks] == ["sentinel.state_store", "sentinel.redis"]


def test_connectivity_report_rejects_unreachable_redis_before_provider_network(monkeypatch):
    called = []

    class UnreachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return False

        def close(self):
            return None

    monkeypatch.setattr("sentinel.connectivity.RedisRateLimitBackend", UnreachableRedis)
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(_ready_settings(), store=SQLiteInvestigationStore())

    assert report.ready is False
    assert report.missing_live_credentials == []
    assert called == []
    assert [check.name for check in report.checks] == ["sentinel.state_store", "sentinel.redis"]
    assert report.checks[0].passed is True
    assert report.checks[1].passed is False


def test_connectivity_report_returns_structured_datadog_oauth_refresh_failure(monkeypatch):
    _make_redis_reachable(monkeypatch)
    called = []
    settings = replace(
        _ready_settings(),
        datadog_api_key=None,
        datadog_app_key=None,
        datadog_oauth_token=None,
        datadog_client_id=None,
        datadog_client_secret=None,
        datadog_redirect_uri=None,
    )
    store = SQLiteInvestigationStore()
    store.save_oauth_token(
        provider="datadog",
        access_token="old-dd-oauth",
        refresh_token="old-dd-refresh-token",
        metadata={
            "domain": "datadoghq.eu",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(settings, store=store)

    assert report.ready is False
    assert report.missing_live_credentials == []
    assert called == []
    assert [check.name for check in report.checks] == [
        "sentinel.state_store",
        "sentinel.redis",
        "datadog.oauth_refresh",
    ]
    failed = report.checks[-1]
    assert failed.provider == "datadog"
    assert failed.passed is False
    assert "DD_CLIENT_ID is required" in failed.detail
    assert "old-dd-refresh-token" not in failed.detail


def test_connectivity_report_returns_structured_oauth_store_read_failure(monkeypatch):
    _make_redis_reachable(monkeypatch)
    called = []

    class BrokenOAuthStore:
        def ping(self):
            return True

        def load_oauth_token(self, provider):
            raise RuntimeError(
                f"{provider} token store unavailable Authorization: Bearer ghp-secret-token"
            )

    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: called.append(True) or _StubClients(),
    )

    report = run_live_connectivity_checks(
        replace(_ready_settings(), github_token=None),
        store=BrokenOAuthStore(),
    )

    assert report.ready is False
    assert report.missing_live_credentials == []
    assert called == []
    assert [check.name for check in report.checks] == [
        "sentinel.state_store",
        "sentinel.redis",
        "sentinel.oauth_store",
    ]
    failed = report.checks[-1]
    assert failed.provider == "sentinel"
    assert failed.passed is False
    assert "github" in failed.detail
    assert "ghp-secret-token" not in failed.detail
    assert "[redacted]" in failed.detail


def test_connectivity_report_redacts_sensitive_failure_detail(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        github_token="gh",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )

    clients = _StubClients()
    clients.datadog = _LeakyDatadog()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "datadog.logs")

    assert report.ready is False
    assert failed.passed is False
    assert "xoxb-secret-token" not in failed.detail
    assert "dd-secret-key" not in failed.detail
    assert "[redacted]" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_malformed_success_payload(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.datadog = _MalformedDatadog()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "datadog.logs")

    assert report.ready is False
    assert failed.passed is False
    assert "events" in failed.detail
    assert "must be a list" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_empty_provider_read(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.datadog = _EmptyDatadogLogs()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "datadog.logs")

    assert report.ready is False
    assert failed.passed is False
    assert "at least one provider record" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_metric_sample_without_finite_numeric_datapoint(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.datadog = _DatadogMetricsWithoutFiniteDatapoints()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "datadog.metrics")

    assert report.ready is False
    assert failed.passed is False
    assert "finite numeric Datadog datapoint" in failed.detail
    assert clients.closed is True


def test_connectivity_report_preserves_typed_provider_error_metadata(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.github = _RateLimitedGitHub()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "github.commits")

    assert report.ready is False
    assert failed.passed is False
    assert failed.error_kind == ToolErrorKind.RATE_LIMITED.value
    assert failed.retryable is True
    assert "github provider rate limited" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_empty_github_pull_request_read(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.github = _EmptyGitHubPullRequests()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "github.pull_requests")

    assert report.ready is False
    assert failed.provider == "github"
    assert failed.passed is False
    assert "at least one provider record" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_missing_kubernetes_rollout_revisions(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.kubernetes = _EmptyKubernetesRolloutRevisions()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "kubernetes.rollout_revisions")

    assert report.ready is False
    assert failed.provider == "kubernetes"
    assert failed.passed is False
    assert "at least one provider record" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_rollout_revisions_without_previous_target(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.kubernetes = _SingleKubernetesRolloutRevision()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "kubernetes.rollout_revisions")

    assert report.ready is False
    assert failed.provider == "kubernetes"
    assert failed.passed is False
    assert "previous_revision" in failed.detail
    assert "revision:<positive integer>" in failed.detail
    assert clients.closed is True


def test_connectivity_report_rejects_slack_auth_without_ok_true(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.slack = _MalformedSlackAuth()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "slack.auth")

    assert report.ready is False
    assert failed.passed is False
    assert "ok" in failed.detail
    assert "must be true" in failed.detail
    assert clients.closed is True


def test_connectivity_report_fails_when_slack_default_channel_is_unreachable(monkeypatch):
    _make_redis_reachable(monkeypatch)
    settings = _ready_settings()
    clients = _StubClients()
    clients.slack = _MissingSlackDefaultChannel()
    monkeypatch.setattr(
        "sentinel.connectivity.LiveProviderClients.from_settings",
        lambda _settings: clients,
    )

    report = run_live_connectivity_checks(settings, store=SQLiteInvestigationStore())
    failed = next(check for check in report.checks if check.name == "slack.default_channel")

    assert report.ready is False
    assert failed.provider == "slack"
    assert failed.passed is False
    assert failed.error_kind == ToolErrorKind.AUTHORIZATION.value
    assert failed.retryable is False
    assert "channel_not_found" in failed.detail
    assert clients.closed is True


def _ready_settings():
    return replace(
        SentinelSettings.from_env(),
        datadog_api_key="dd-api",
        datadog_app_key="dd-app",
        github_token="gh",
        github_owner="owner",
        github_repo="repo",
        pagerduty_api_key="pd",
        api_token="sentinel-api-token",
        pagerduty_webhook_secret="pd-secret",
        slack_bot_token="xoxb",
        slack_channel_id="C123",
        kubeconfig=__file__,
        database_url="postgresql://sentinel:sentinel@db/sentinel",
        redis_url="redis://redis:6379/0",
    )


def _make_redis_reachable(monkeypatch):
    class ReachableRedis:
        def __init__(self, redis_url):
            self.redis_url = redis_url

        def ping(self):
            return True

        def close(self):
            return None

    monkeypatch.setattr("sentinel.connectivity.RedisRateLimitBackend", ReachableRedis)


class _StubDatadog:
    def search_logs(self, *args, **kwargs):
        return {"events": [{"id": "log"}]}

    def query_metric(self, *args, **kwargs):
        return {"series": [{"metric": "system.cpu.user", "pointlist": [[1717425600, 1.0]]}]}

    def search_spans(self, *args, **kwargs):
        return {"spans": [{"id": "span"}]}


class _StubPrometheus:
    def __init__(self):
        self.queries = []

    def query_range(self, *args, **kwargs):
        self.queries.append((args, kwargs))
        return {
            "result": [
                {
                    "metric": {"service": "payment-service"},
                    "values": [[1717425600, "1"]],
                }
            ]
        }

    def alerting_rules(self):
        return {"groups": [{"name": "sentinel-free-tier-demo", "rules": [{"name": "SentinelDemoPaymentErrors"}]}]}


class _StubLoki:
    def query_range(self, *args, **kwargs):
        return {
            "events": [
                {
                    "stream": {"service": "payment-service"},
                    "values": [["1717425600000000000", "trace db cdn error"]],
                }
            ]
        }


class _LeakyDatadog(_StubDatadog):
    def search_logs(self, *args, **kwargs):
        raise RuntimeError(
            "Datadog rejected Authorization: Bearer xoxb-secret-token with api_key=dd-secret-key"
        )


class _MalformedDatadog(_StubDatadog):
    def search_logs(self, *args, **kwargs):
        return {"events": {"id": "log"}}


class _EmptyDatadogLogs(_StubDatadog):
    def search_logs(self, *args, **kwargs):
        return {"events": []}


class _DatadogMetricsWithoutFiniteDatapoints(_StubDatadog):
    def query_metric(self, *args, **kwargs):
        return {
            "series": [
                {
                    "metric": "system.cpu.user",
                    "pointlist": [
                        [1717425600, None],
                        [1717425660, "1.0"],
                        [1717425720, float("nan")],
                        [1717425780, float("inf")],
                    ],
                }
            ]
        }


class _StubGitHub:
    def commits(self, *args, **kwargs):
        return [{"sha": "abc"}]

    def pull_requests(self, *args, **kwargs):
        return [{"number": 42, "url": "https://api.github.com/repos/owner/repo/pulls/42"}]

    def deployments(self, *args, **kwargs):
        return [{"id": 1}]


class _EmptyGitHubPullRequests(_StubGitHub):
    def pull_requests(self, *args, **kwargs):
        return []


class _RateLimitedGitHub(_StubGitHub):
    def commits(self, *args, **kwargs):
        raise ToolExecutionError(
            ToolErrorKind.RATE_LIMITED,
            "github provider rate limited",
            retryable=True,
            circuit_breaker_failure=False,
        )


class _StubPagerDuty:
    def list_incidents(self, *args, **kwargs):
        return [{"id": "PD", "status": "triggered"}]

    def on_calls(self, *args, **kwargs):
        return [{"user": {"id": "U"}}]


class _StubSlack:
    def oauth_test(self):
        return {"ok": True}

    def channel_info(self):
        return {"ok": True, "channel": {"id": "C123", "name": "inc-pd"}}

    def list_channels(self, *args, **kwargs):
        return [{"id": "C", "name": "inc-pd"}]


class _DisabledPagerDuty:
    enabled = False


class _DisabledSlack:
    enabled = False


class _StubDiscord:
    def __init__(self):
        self.posts = []

    def post_to_discord(self, text):
        self.posts.append(text)
        return {"ok": True, "provider": "discord", "content": text}


class _StubGenericAlerts:
    def on_call_context(self, incident_id=None):
        return {
            "incident": {"id": incident_id, "source": "generic_webhook"},
            "oncalls": [{"user": {"id": "eng-oncall", "summary": "eng-oncall"}}],
            "escalation_policy_ids": ["generic_webhook"],
            "oncall_scope": "generic_webhook",
            "provider": "generic_webhook",
        }


class _MalformedSlackAuth(_StubSlack):
    def oauth_test(self):
        return {"ok": False}


class _MissingSlackDefaultChannel(_StubSlack):
    def channel_info(self):
        raise ToolExecutionError(
            ToolErrorKind.AUTHORIZATION,
            "Slack conversations.info failed: channel_not_found",
            retryable=False,
            circuit_breaker_failure=False,
        )


class _EmptyKubernetesRolloutRevisions:
    def list_pods(self, *args, **kwargs):
        return {"items": [{"metadata": {"name": "checkout-abc"}}]}

    def list_deployments(self):
        return {"items": [{"metadata": {"name": "checkout-service"}}]}

    def rollout_revisions(self, *args, **kwargs):
        return {"revisions": [], "current_revision": None, "previous_revision": None}


class _SingleKubernetesRolloutRevision:
    def list_pods(self, *args, **kwargs):
        return {"items": [{"metadata": {"name": "checkout-abc"}}]}

    def list_deployments(self):
        return {"items": [{"metadata": {"name": "checkout-service"}}]}

    def rollout_revisions(self, *args, **kwargs):
        return {"revisions": [41], "current_revision": "revision:41", "previous_revision": None}


class _StubKubernetes:
    def list_pods(self, *args, **kwargs):
        return {"items": [{"metadata": {"name": "checkout-abc"}}]}

    def list_deployments(self):
        return {"items": [{"metadata": {"name": "checkout-service"}}]}

    def rollout_revisions(self, *args, **kwargs):
        return {
            "revisions": [40, 41],
            "current_revision": "revision:41",
            "previous_revision": "revision:40",
        }


class _StubClients:
    def __init__(self):
        self.datadog = _StubDatadog()
        self.github = _StubGitHub()
        self.pagerduty = _StubPagerDuty()
        self.slack = _StubSlack()
        self.kubernetes = _StubKubernetes()
        self.closed = False

    def close(self):
        self.closed = True


class _FreeStubClients:
    def __init__(self):
        self.prometheus = _StubPrometheus()
        self.loki = _StubLoki()
        self.github = _StubGitHub()
        self.pagerduty = _DisabledPagerDuty()
        self.generic_alerts = _StubGenericAlerts()
        self.slack = _DisabledSlack()
        self.discord = _StubDiscord()
        self.kubernetes = _StubKubernetes()
        self.closed = False

    def close(self):
        self.closed = True
