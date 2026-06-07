import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_compose_uses_separate_host_and_container_kubeconfig_paths():
    compose = (ROOT / "docker-compose.yml").read_text()
    env_example = (ROOT / ".env.example").read_text()

    assert "${CONTAINER_KUBECONFIG:-~/.kube/config}:/root/.kube/config:ro" in compose
    assert "sentinel-data:/data" in compose
    assert "KUBECONFIG: /root/.kube/config" in compose
    assert "HOST_KUBECONFIG=~/.kube/config" in env_example
    assert "CONTAINER_KUBECONFIG=.sentinel/kubeconfig.container" in env_example
    assert "KUBECONFIG=/root/.kube/config" in env_example


def test_container_image_installs_kubectl_for_live_kubernetes_tools():
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert "dl.k8s.io" in dockerfile
    assert "/usr/local/bin/kubectl" in dockerfile
    assert 'arch="$(dpkg --print-architecture)"' in dockerfile
    assert 'amd64) kubectl_arch="amd64"' in dockerfile
    assert 'arm64) kubectl_arch="arm64"' in dockerfile
    assert "bin/linux/${kubectl_arch}/kubectl" in dockerfile
    assert "bin/linux/amd64/kubectl" not in dockerfile


def test_compose_passes_live_provider_configuration_into_sentinel_service():
    compose = (ROOT / "docker-compose.yml").read_text()

    for name in [
        "DD_API_KEY",
        "DD_APP_KEY",
        "DATADOG_APP_KEY",
        "DD_SITE",
        "DD_OAUTH_TOKEN",
        "PROMETHEUS_URL",
        "LOKI_URL",
        "DD_CLIENT_ID",
        "DD_CLIENT_SECRET",
        "DD_REDIRECT_URI",
        "DD_OAUTH_REQUIRED_SCOPES",
        "GITHUB_TOKEN",
        "GITHUB_OWNER",
        "GITHUB_REPO",
        "SENTINEL_GITHUB_WRITE_ENABLED",
        "PAGERDUTY_API_KEY",
        "SLACK_BOT_TOKEN",
        "SLACK_CHANNEL_ID",
        "DISCORD_WEBHOOK_URL",
        "SLACK_CLIENT_ID",
        "SLACK_CLIENT_SECRET",
        "SLACK_REDIRECT_URI",
        "SLACK_OAUTH_SCOPES",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GITHUB_REDIRECT_URI",
        "GITHUB_OAUTH_SCOPES",
        "SENTINEL_OAUTH_STATE_SECRET",
        "SENTINEL_API_TOKEN",
        "PAGERDUTY_WEBHOOK_SECRET",
        "SENTINEL_DEFAULT_SERVICE",
        "SENTINEL_SERVICE_ALIASES",
        "SENTINEL_APPROVER_ID",
        "KUBERNETES_NAMESPACE",
        "SENTINEL_KUBECTL_TIMEOUT_SECONDS",
        "SENTINEL_LIVE_MAX_PAGES",
        "DATABASE_URL",
        "REDIS_URL",
        "KUBECONFIG",
    ]:
        assert f"      {name}:" in compose

    assert "KUBECONFIG: /root/.kube/config" in compose
    assert "DATABASE_URL: ${DATABASE_URL:-postgresql://" in compose
    assert "REDIS_URL: ${REDIS_URL:-redis://" in compose
    assert "sentinel-data:" in compose


def test_compose_keeps_postgres_credentials_configurable():
    compose = (ROOT / "docker-compose.yml").read_text()
    env_example = (ROOT / ".env.example").read_text()

    assert "POSTGRES_USER: ${POSTGRES_USER:-sentinel}" in compose
    assert "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-change-me}" in compose
    assert "POSTGRES_DB: ${POSTGRES_DB:-sentinel}" in compose
    assert "${POSTGRES_PASSWORD:-change-me}@postgres:5432/${POSTGRES_DB:-sentinel}" in compose
    assert "POSTGRES_PASSWORD=change-me" in env_example
    assert "DATABASE_URL=postgresql://sentinel:change-me@postgres:5432/sentinel" in env_example
    assert "REDIS_URL=redis://redis:6379/0" in env_example
    assert "SENTINEL_SERVICE_ALIASES=" in env_example


def test_env_example_documents_live_demo_and_e2e_gate_variables():
    env_example = (ROOT / ".env.example").read_text()

    for name in [
        "SENTINEL_ENV",
        "SENTINEL_BASE_URL",
        "SENTINEL_LIVE_RECEIVER_URL",
        "SENTINEL_APPROVER_ID",
        "SENTINEL_GITHUB_WRITE_ENABLED",
        "RUN_LIVE_TESTS",
        "RUN_LIVE_E2E_TESTS",
        "RUN_LIVE_APPROVAL_E2E_TESTS",
        "RUN_LIVE_HTTP_E2E_TESTS",
        "RUN_LIVE_HTTP_APPROVAL_E2E_TESTS",
        "RUN_FREE_TIER_LIVE_E2E_TESTS",
        "RUN_FREE_TIER_LIVE_APPROVAL_E2E_TESTS",
        "SENTINEL_FREE_TIER_LIVE_TEST_INCIDENT_ID",
        "SENTINEL_ENV_FILE",
        "SENTINEL_LIVE_TEST_INCIDENT_ID",
        "SENTINEL_LIVE_TEST_SERVICE",
        "SENTINEL_LIVE_E2E_TIMEOUT_SECONDS",
    ]:
        assert f"{name}=" in env_example


def test_compose_waits_for_healthy_postgres_and_redis_before_sentinel():
    compose = (ROOT / "docker-compose.yml").read_text()

    assert "condition: service_healthy" in compose
    assert "pg_isready -U ${POSTGRES_USER:-sentinel} -d ${POSTGRES_DB:-sentinel}" in compose
    assert '["CMD", "redis-cli", "ping"]' in compose
    assert "http://localhost:8000/ready/live" in compose
    assert "Authorization: Bearer $$SENTINEL_API_TOKEN" in compose


def test_compose_includes_free_observability_services():
    compose = (ROOT / "docker-compose.yml").read_text()
    env_example = (ROOT / ".env.example").read_text()
    prometheus_config = (ROOT / "configs" / "prometheus.yml").read_text()
    prometheus_rules = (ROOT / "configs" / "prometheus.rules.yml").read_text()

    assert "prom/prometheus:v2.55.1" in compose
    assert "grafana/loki:3.2.1" in compose
    assert "PROMETHEUS_URL: ${PROMETHEUS_URL:-http://prometheus:9090}" in compose
    assert "LOKI_URL: ${LOKI_URL:-http://loki:3100}" in compose
    assert "DISCORD_WEBHOOK_URL: ${DISCORD_WEBHOOK_URL:-}" in compose
    assert "PROMETHEUS_URL=http://prometheus:9090" in env_example
    assert "LOKI_URL=http://loki:3100" in env_example
    assert "DISCORD_WEBHOOK_URL=" in env_example
    assert "metrics_path: /metrics" in prometheus_config
    assert "sentinel:8000" in prometheus_config
    assert "SentinelDemoPaymentErrors" in prometheus_rules


def test_webapp_module_app_import_survives_invalid_runtime_env():
    code = """
import json
from fastapi.testclient import TestClient
from sentinel.webapp import app

response = TestClient(app).get("/ready")
print(json.dumps({"status_code": response.status_code, "body": response.json()}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={**os.environ, "SENTINEL_LIVE_MAX_PAGES": "0"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    rendered = json.loads(result.stdout)
    assert rendered["status_code"] == 503
    assert rendered["body"]["status"] == "configuration_error"
    assert "SENTINEL_LIVE_MAX_PAGES" in rendered["body"]["config_error"]
