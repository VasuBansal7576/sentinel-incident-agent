from types import SimpleNamespace

import pytest

from sentinel.circuit_breaker import CircuitOpenError
from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.real_tools import LiveToolRouter


def test_logs_use_loki_before_datadog_when_both_clients_exist():
    clients = SimpleNamespace(
        loki=_RecordingLoki(),
        prometheus=None,
        datadog=_DatadogMustNotBeCalled(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.fetch_service_logs",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "loki"
    assert result["events"] == _LOKI_EVENTS
    assert clients.loki.queries[0]["query"] == '{service="checkout-service"}'
    assert result["implementation"] == "live::observe.fetch_service_logs"
    assert result["stub"] is False


def test_metrics_use_prometheus_before_datadog_when_both_clients_exist():
    clients = SimpleNamespace(
        prometheus=_RecordingPrometheus(),
        loki=None,
        datadog=_DatadogMustNotBeCalled(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_error_rate_timeseries",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "prometheus"
    assert result["metric"] == "trace.http.request.errors"
    assert result["prometheus"]["result"] == _PROMETHEUS_RESULTS
    assert 'service="checkout-service"' in clients.prometheus.queries[0]["query"]
    assert 'status=~"5.."' in clients.prometheus.queries[0]["query"]
    assert result["implementation"] == "live::observe.get_error_rate_timeseries"
    assert result["stub"] is False


def test_alerting_rules_use_prometheus_before_datadog_when_both_clients_exist():
    clients = SimpleNamespace(
        prometheus=_RecordingPrometheus(),
        loki=None,
        datadog=_DatadogMustNotBeCalled(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.fetch_alerting_rules",
        {"service": "checkout-service"},
    )

    assert result["provider"] == "prometheus"
    assert result["groups"] == _PROMETHEUS_RULE_GROUPS
    assert result["implementation"] == "live::observe.fetch_alerting_rules"
    assert result["stub"] is False


def test_dashboard_snapshot_uses_prometheus_targets_before_datadog_when_both_clients_exist():
    clients = SimpleNamespace(
        prometheus=_RecordingPrometheus(),
        loki=None,
        datadog=_DatadogMustNotBeCalled(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.read_dashboard_snapshot",
        {"service": "checkout-service"},
    )

    assert result["provider"] == "prometheus"
    assert result["dashboard_id"] == "prometheus-targets"
    assert result["activeTargets"] == _PROMETHEUS_TARGETS
    assert result["implementation"] == "live::observe.read_dashboard_snapshot"
    assert result["stub"] is False


def test_memory_cpu_uses_prometheus_demo_metric_names_and_escaped_pod_regex():
    clients = SimpleNamespace(
        prometheus=_RecordingPrometheus(),
        loki=None,
        datadog=_DatadogMustNotBeCalled(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_memory_cpu_usage",
        {"service": "checkout.service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "prometheus"
    assert clients.prometheus.queries[0]["query"] == (
        'sum(rate(container_cpu_usage_seconds_total{pod=~"checkout\\\\.service.*"}[5m]))'
    )
    assert clients.prometheus.queries[1]["query"] == (
        'sum(container_memory_working_set_bytes{pod=~"checkout\\\\.service.*"})'
    )


def test_traces_use_loki_before_datadog_when_both_clients_exist():
    clients = SimpleNamespace(
        loki=_RecordingLoki(),
        prometheus=None,
        datadog=_DatadogMustNotBeCalled(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_distributed_traces",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "loki"
    assert result["spans"] == _LOKI_EVENTS
    assert result["events"] == _LOKI_EVENTS
    assert result["streams"] == _LOKI_EVENTS
    assert clients.loki.queries[0]["query"] == '{service="checkout-service"} |= "trace"'
    assert result["implementation"] == "live::observe.get_distributed_traces"
    assert result["stub"] is False


def test_logs_fall_back_to_datadog_when_loki_is_absent():
    clients = SimpleNamespace(
        loki=None,
        prometheus=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.fetch_service_logs",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["events"] == _DATADOG_EVENTS
    assert clients.datadog.log_queries == ["service:checkout-service"]
    assert result["implementation"] == "live::observe.fetch_service_logs"
    assert result["stub"] is False


def test_logs_fall_back_to_datadog_when_loki_fails_and_datadog_is_configured():
    clients = SimpleNamespace(
        loki=_FailingLoki(),
        prometheus=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.fetch_service_logs",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "datadog"
    assert result["events"] == _DATADOG_EVENTS
    assert clients.datadog.log_queries == ["service:checkout-service"]


def test_logs_keep_loki_failure_when_datadog_is_not_configured():
    clients = SimpleNamespace(
        loki=_FailingLoki(),
        prometheus=None,
        datadog=_UnconfiguredDatadog(),
    )

    with pytest.raises(ToolExecutionError) as exc:
        LiveToolRouter(clients).invoke(
            "observe.fetch_service_logs",
            {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
        )

    assert exc.value.kind == ToolErrorKind.RETRYABLE
    assert "loki unavailable" in str(exc.value)
    assert clients.datadog.log_queries == []


@pytest.mark.parametrize(
    ("tool_name", "primary_provider", "query_attrs"),
    [
        ("observe.fetch_service_logs", "Loki", ("log_queries",)),
        ("observe.check_db_slow_queries", "Loki", ("log_queries",)),
        ("observe.fetch_cdn_logs", "Loki", ("log_queries",)),
        ("observe.get_distributed_traces", "Loki", ("span_queries",)),
        ("observe.fetch_apm_data", "Loki", ("span_queries",)),
        ("observe.get_error_rate_timeseries", "Prometheus", ("metric_queries",)),
        ("observe.get_memory_cpu_usage", "Prometheus", ("metric_queries",)),
    ],
)
def test_observe_tools_do_not_call_unconfigured_datadog_when_free_primary_is_absent(
    tool_name,
    primary_provider,
    query_attrs,
):
    datadog = _UnconfiguredDatadog()
    clients = SimpleNamespace(
        loki=None,
        prometheus=None,
        datadog=datadog,
    )

    with pytest.raises(ToolExecutionError) as exc:
        LiveToolRouter(clients).invoke(
            tool_name,
            {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
        )

    assert exc.value.kind == ToolErrorKind.AUTHORIZATION
    assert primary_provider in str(exc.value)
    assert "configured Datadog credentials" in str(exc.value)
    for query_attr in query_attrs:
        assert getattr(datadog, query_attr) == []


def test_metrics_fall_back_to_datadog_when_prometheus_is_absent():
    clients = SimpleNamespace(
        prometheus=None,
        loki=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_error_rate_timeseries",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "datadog"
    assert result["datadog"] == _DATADOG_METRIC
    assert clients.datadog.metric_queries == ["avg:trace.http.request.errors{service:checkout-service}"]
    assert result["implementation"] == "live::observe.get_error_rate_timeseries"
    assert result["stub"] is False


def test_alerting_rules_fall_back_to_datadog_when_prometheus_is_absent():
    clients = SimpleNamespace(
        prometheus=None,
        loki=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.fetch_alerting_rules",
        {"service": "checkout-service"},
    )

    assert result["provider"] == "datadog"
    assert result["monitors"] == _DATADOG_MONITORS
    assert clients.datadog.monitor_queries == ["checkout-service"]


def test_dashboard_snapshot_falls_back_to_datadog_when_prometheus_is_absent():
    clients = SimpleNamespace(
        prometheus=None,
        loki=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.read_dashboard_snapshot",
        {"dashboard_id": "dash-checkout"},
    )

    assert result["provider"] == "datadog"
    assert result["dashboard"] == _DATADOG_DASHBOARD
    assert clients.datadog.dashboard_ids == ["dash-checkout"]


def test_metrics_fall_back_to_datadog_when_prometheus_circuit_is_open():
    clients = SimpleNamespace(
        prometheus=_CircuitOpenPrometheus(),
        loki=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_error_rate_timeseries",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "datadog"
    assert result["datadog"] == _DATADOG_METRIC
    assert clients.datadog.metric_queries == ["avg:trace.http.request.errors{service:checkout-service}"]


def test_traces_fall_back_to_datadog_when_loki_is_absent():
    clients = SimpleNamespace(
        loki=None,
        prometheus=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_distributed_traces",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["spans"] == _DATADOG_SPANS
    assert clients.datadog.span_queries == ["service:checkout-service"]
    assert result["implementation"] == "live::observe.get_distributed_traces"
    assert result["stub"] is False


def test_traces_fall_back_to_datadog_when_loki_fails_and_datadog_is_configured():
    clients = SimpleNamespace(
        loki=_FailingLoki(),
        prometheus=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_distributed_traces",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "datadog"
    assert result["spans"] == _DATADOG_SPANS
    assert clients.datadog.span_queries == ["service:checkout-service"]


def test_db_logs_fall_back_to_datadog_when_loki_fails_and_datadog_is_configured():
    clients = SimpleNamespace(
        loki=_FailingLoki(),
        prometheus=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.check_db_slow_queries",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "datadog"
    assert clients.datadog.log_queries == ["service:checkout-service @db.statement:*"]


def test_memory_cpu_falls_back_to_datadog_when_prometheus_fails_and_datadog_is_configured():
    clients = SimpleNamespace(
        prometheus=_FailingPrometheus(),
        loki=None,
        datadog=_RecordingDatadog(),
    )

    result = LiveToolRouter(clients).invoke(
        "observe.get_memory_cpu_usage",
        {"service": "checkout-service", "time_window": "now-15m", "time_window_end": "now"},
    )

    assert result["provider"] == "datadog"
    assert clients.datadog.metric_queries == [
        "avg:kubernetes.cpu.usage.total{service:checkout-service}",
        "avg:kubernetes.memory.usage{service:checkout-service}",
    ]


_LOKI_EVENTS = [
    {
        "stream": {"service": "checkout-service"},
        "values": [["1717425600000000000", "trace error in checkout-service"]],
    }
]

_PROMETHEUS_RESULTS = [
    {
        "metric": {"service": "checkout-service"},
        "values": [[1717425600, "1"]],
    }
]
_PROMETHEUS_RULE_GROUPS = [{"name": "sentinel-free-tier", "rules": [{"name": "HighErrorRate"}]}]
_PROMETHEUS_TARGETS = [{"scrapeUrl": "http://sentinel:8000/metrics", "health": "up"}]

_DATADOG_EVENTS = [{"id": "log-1", "attributes": {"service": "checkout-service"}}]
_DATADOG_SPANS = [{"id": "span-1", "attributes": {"service": "checkout-service"}}]
_DATADOG_MONITORS = [{"id": 123, "name": "checkout error rate"}]
_DATADOG_DASHBOARD = {"id": "dash-checkout", "title": "Checkout overview"}
_DATADOG_METRIC = {
    "series": [
        {
            "metric": "trace.http.request.errors",
            "pointlist": [[1717425600, 1.0]],
        }
    ]
}


class _RecordingLoki:
    def __init__(self):
        self.queries = []

    def query_range(self, query, **kwargs):
        self.queries.append({"query": query, **kwargs})
        return {"events": _LOKI_EVENTS, "streams": _LOKI_EVENTS, "query": query}


class _RecordingPrometheus:
    def __init__(self):
        self.queries = []

    def query_range(self, query, **kwargs):
        self.queries.append({"query": query, **kwargs})
        return {"query": query, "result": _PROMETHEUS_RESULTS}

    def alerting_rules(self):
        return {"groups": _PROMETHEUS_RULE_GROUPS}

    def targets(self):
        return {"activeTargets": _PROMETHEUS_TARGETS}


class _RecordingDatadog:
    def __init__(self):
        self.log_queries = []
        self.metric_queries = []
        self.span_queries = []
        self.monitor_queries = []
        self.dashboard_ids = []

    def search_logs(self, query, **_kwargs):
        self.log_queries.append(query)
        return {"events": _DATADOG_EVENTS, "query": query}

    def query_metric(self, query, **_kwargs):
        self.metric_queries.append(query)
        return _DATADOG_METRIC

    def search_spans(self, query, **_kwargs):
        self.span_queries.append(query)
        return {"spans": _DATADOG_SPANS, "query": query}

    def list_monitors(self, query=None, **_kwargs):
        self.monitor_queries.append(query)
        return {"monitors": _DATADOG_MONITORS, "query": query}

    def get_dashboard(self, dashboard_id):
        self.dashboard_ids.append(dashboard_id)
        return {"dashboard": _DATADOG_DASHBOARD}


class _FailingLoki:
    def query_range(self, *_args, **_kwargs):
        raise ToolExecutionError(ToolErrorKind.RETRYABLE, "loki unavailable", retryable=True)


class _FailingPrometheus:
    def query_range(self, *_args, **_kwargs):
        raise ToolExecutionError(ToolErrorKind.RETRYABLE, "prometheus unavailable", retryable=True)

    def alerting_rules(self):
        raise ToolExecutionError(ToolErrorKind.RETRYABLE, "prometheus unavailable", retryable=True)

    def targets(self):
        raise ToolExecutionError(ToolErrorKind.RETRYABLE, "prometheus unavailable", retryable=True)


class _CircuitOpenPrometheus:
    def query_range(self, *_args, **_kwargs):
        raise CircuitOpenError("Circuit prometheus is open")


class _UnconfiguredDatadog(_RecordingDatadog):
    api = SimpleNamespace(headers={"DD-API-KEY": "", "DD-APPLICATION-KEY": ""})


class _DatadogMustNotBeCalled:
    def search_logs(self, *_args, **_kwargs):
        raise AssertionError("Datadog logs should not be used when Loki is configured")

    def query_metric(self, *_args, **_kwargs):
        raise AssertionError("Datadog metrics should not be used when Prometheus is configured")

    def search_spans(self, *_args, **_kwargs):
        raise AssertionError("Datadog spans should not be used when Loki is configured")

    def list_monitors(self, *_args, **_kwargs):
        raise AssertionError("Datadog monitors should not be used when Prometheus is configured")

    def get_dashboard(self, *_args, **_kwargs):
        raise AssertionError("Datadog dashboards should not be used when Prometheus is configured")
