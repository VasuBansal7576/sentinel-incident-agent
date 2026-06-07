from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "sentinel-real"
CLUSTER = "sentinel-real-incident"
IMAGE = "sentinel-real-incident:local"
API_TOKEN = "real-incident-token"
APP_PORT = 18080
PROM_PORT = 19090
LOKI_PORT = 13100


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SENTINEL's real SQLite slow-query incident in local kind.")
    parser.add_argument("--cluster", default=CLUSTER)
    parser.add_argument("--row-count", type=int, default=250_000)
    parser.add_argument("--warmup-seconds", type=int, default=25)
    parser.add_argument("--poll-seconds", type=int, default=240)
    parser.add_argument("--summary-output", default=".sentinel/real-slow-query-summary.json")
    args = parser.parse_args()

    env = _load_env(PROJECT_ROOT / ".env")
    webhook = os.getenv("DISCORD_WEBHOOK_URL") or env.get("DISCORD_WEBHOOK_URL")
    if not webhook:
        raise SystemExit("DISCORD_WEBHOOK_URL is required in the environment or .env for the real incident demo.")

    _ensure_kind_cluster(args.cluster)
    _docker_build()
    _kind_load(args.cluster)
    _apply_stack(webhook)
    _restart_sentinel()
    _wait_rollouts()

    forwards = _start_port_forwards()
    stop_load = threading.Event()
    load_stats: dict[str, Any] = {}
    try:
        _wait_http(f"http://127.0.0.1:{APP_PORT}/health", timeout=120)
        _wait_http(f"http://127.0.0.1:{PROM_PORT}/-/ready", timeout=120)
        _post(f"http://127.0.0.1:{APP_PORT}/slow-query/reset", params={"row_count": args.row_count})
        load_thread = threading.Thread(target=_load_slow_query, args=(stop_load, load_stats), daemon=True)
        load_thread.start()
        _wait_for_prometheus_sample(args.warmup_seconds)
        alert = _wait_for_prometheus_alert(args.poll_seconds)
        incident_id = f"REAL-SLOW-{int(time.time())}"
        accepted = _post(
            f"http://127.0.0.1:{APP_PORT}/webhooks/generic",
            json_body=_generic_alert_payload(alert, incident_id),
        )
        investigation_id = accepted["investigation_id"]
        waiting = _wait_for_status(investigation_id, "waiting_for_approval", args.poll_seconds)
        approval_id = waiting["approval_request_id"]
        approver = (waiting.get("approval_approver_ids") or ["eng-oncall"])[0]
        _post(
            f"http://127.0.0.1:{APP_PORT}/investigations/{investigation_id}/approval",
            json_body={
                "request_id": approval_id,
                "approver_id": approver,
                "decision": "approve",
                "idempotency_key": f"{investigation_id}:real-slow-query-approval",
            },
            headers=_auth_headers(),
        )
        completed = _wait_for_status(investigation_id, "completed", args.poll_seconds)
        stop_load.set()
        load_thread.join(timeout=5)
        summary = _summarize(completed, load_stats, alert)
        _write_summary(summary, Path(args.summary_output))
        print(_render_summary(summary))
        if not summary["passed"]:
            raise SystemExit(1)
    finally:
        stop_load.set()
        for proc in forwards:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def _ensure_kind_cluster(cluster: str) -> None:
    clusters = _run(["kind", "get", "clusters"], check=False).stdout.splitlines()
    if cluster in {item.strip() for item in clusters}:
        return
    _run(["kind", "create", "cluster", "--name", cluster])


def _docker_build() -> None:
    _run(["docker", "build", "-t", IMAGE, "."], cwd=PROJECT_ROOT)


def _kind_load(cluster: str) -> None:
    _run(["kind", "load", "docker-image", IMAGE, "--name", cluster])


def _apply_stack(discord_webhook: str) -> None:
    _run(["kubectl", "create", "namespace", NAMESPACE], check=False)
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "sentinel-real-secrets", "namespace": NAMESPACE},
        "type": "Opaque",
        "stringData": {"DISCORD_WEBHOOK_URL": discord_webhook},
    }
    _run(["kubectl", "apply", "-f", "-"], input_text=json.dumps(secret))
    _run(["kubectl", "apply", "-f", "-"], input_text=json.dumps(_stack_manifest()))


def _restart_sentinel() -> None:
    _run(["kubectl", "rollout", "restart", "deployment/sentinel", "-n", NAMESPACE])


def _stack_manifest() -> dict[str, Any]:
    prometheus_config = """
global:
  scrape_interval: 2s
  evaluation_interval: 2s
rule_files:
  - /etc/prometheus/prometheus.rules.yml
scrape_configs:
  - job_name: sentinel-real
    metrics_path: /metrics
    static_configs:
      - targets: ["sentinel:8000"]
  - job_name: prometheus
    static_configs:
      - targets: ["prometheus:9090"]
""".strip()
    prometheus_rules = """
groups:
  - name: sentinel-real-slow-query
    rules:
      - alert: SentinelSlowQueryLatency
        expr: sentinel_slow_query_last_duration_seconds{service="payment-service"} > 0.02
        for: 0s
        labels:
          severity: page
          service: payment-service
          route: /slow-query
        annotations:
          summary: payment-service /slow-query latency spike from missing SQLite index
          description: Real Prometheus alert from sentinel_slow_query_last_duration_seconds.
""".strip()
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "prometheus-config", "namespace": NAMESPACE},
                "data": {
                    "prometheus.yml": prometheus_config,
                    "prometheus.rules.yml": prometheus_rules,
                    "kubeconfig": "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n",
                },
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "loki", "namespace": NAMESPACE},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "loki"}},
                    "template": {
                        "metadata": {"labels": {"app": "loki"}},
                        "spec": {
                            "containers": [
                                {
                                    "name": "loki",
                                    "image": "grafana/loki:3.2.1",
                                    "args": ["-config.file=/etc/loki/local-config.yaml"],
                                    "ports": [{"containerPort": 3100}],
                                    "volumeMounts": [{"name": "loki-data", "mountPath": "/loki"}],
                                }
                            ],
                            "volumes": [{"name": "loki-data", "emptyDir": {}}],
                        },
                    },
                },
            },
            _service("loki", 3100),
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "prometheus", "namespace": NAMESPACE},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "prometheus"}},
                    "template": {
                        "metadata": {"labels": {"app": "prometheus"}},
                        "spec": {
                            "containers": [
                                {
                                    "name": "prometheus",
                                    "image": "prom/prometheus:v2.55.1",
                                    "args": [
                                        "--config.file=/etc/prometheus/prometheus.yml",
                                        "--storage.tsdb.path=/prometheus",
                                    ],
                                    "ports": [{"containerPort": 9090}],
                                    "volumeMounts": [
                                        {"name": "config", "mountPath": "/etc/prometheus"},
                                        {"name": "data", "mountPath": "/prometheus"},
                                    ],
                                }
                            ],
                            "volumes": [
                                {"name": "config", "configMap": {"name": "prometheus-config"}},
                                {"name": "data", "emptyDir": {}},
                            ],
                        },
                    },
                },
            },
            _service("prometheus", 9090),
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "sentinel", "namespace": NAMESPACE},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "sentinel"}},
                    "template": {
                        "metadata": {"labels": {"app": "sentinel"}},
                        "spec": {
                            "containers": [
                                {
                                    "name": "sentinel",
                                    "image": IMAGE,
                                    "imagePullPolicy": "IfNotPresent",
                                    "ports": [{"containerPort": 8000}],
                                    "env": [
                                        {"name": "SENTINEL_ENV", "value": "development"},
                                        {"name": "SENTINEL_API_TOKEN", "value": API_TOKEN},
                                        {"name": "SENTINEL_APPROVER_ID", "value": "eng-oncall"},
                                        {"name": "SENTINEL_DEFAULT_SERVICE", "value": "payment-service"},
                                        {"name": "PROMETHEUS_URL", "value": "http://prometheus:9090"},
                                        {"name": "LOKI_URL", "value": "http://loki:3100"},
                                        {"name": "GITHUB_TOKEN", "value": "real-incident-unused"},
                                        {"name": "GITHUB_OWNER", "value": "sentinel"},
                                        {"name": "GITHUB_REPO", "value": "real-incident"},
                                        {"name": "KUBECONFIG", "value": "/etc/sentinel/kubeconfig"},
                                        {"name": "SENTINEL_SLOW_QUERY_DB_PATH", "value": "/tmp/sentinel-slow-query.db"},
                                        {"name": "SENTINEL_SLOW_QUERY_SCAN_REPEATS", "value": "16"},
                                        {"name": "SENTINEL_PUSH_SLOW_QUERY_LOGS_TO_LOKI", "value": "true"},
                                        {
                                            "name": "DISCORD_WEBHOOK_URL",
                                            "valueFrom": {
                                                "secretKeyRef": {
                                                    "name": "sentinel-real-secrets",
                                                    "key": "DISCORD_WEBHOOK_URL",
                                                }
                                            },
                                        },
                                    ],
                                    "volumeMounts": [{"name": "config", "mountPath": "/etc/sentinel"}],
                                }
                            ],
                            "volumes": [{"name": "config", "configMap": {"name": "prometheus-config"}}],
                        },
                    },
                },
            },
            _service("sentinel", 8000),
        ],
    }


def _service(name: str, port: int) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "selector": {"app": name},
            "ports": [{"name": "http", "port": port, "targetPort": port}],
        },
    }


def _wait_rollouts() -> None:
    for name in ("loki", "prometheus", "sentinel"):
        _run(["kubectl", "rollout", "status", f"deployment/{name}", "-n", NAMESPACE, "--timeout=180s"])


def _start_port_forwards() -> list[subprocess.Popen]:
    log_dir = PROJECT_ROOT / ".sentinel" / "real-incident"
    log_dir.mkdir(parents=True, exist_ok=True)
    forwards = [
        ("sentinel", APP_PORT, 8000),
        ("prometheus", PROM_PORT, 9090),
        ("loki", LOKI_PORT, 3100),
    ]
    procs = []
    for service, local_port, remote_port in forwards:
        log = (log_dir / f"port-forward-{service}.log").open("w")
        proc = subprocess.Popen(
            [
                "kubectl",
                "port-forward",
                "-n",
                NAMESPACE,
                f"svc/{service}",
                f"{local_port}:{remote_port}",
            ],
            stdout=log,
            stderr=log,
        )
        procs.append(proc)
    time.sleep(3)
    return procs


def _load_slow_query(stop: threading.Event, stats: dict[str, Any]) -> None:
    count = 0
    errors = 0
    durations: list[float] = []
    with httpx.Client(timeout=20.0) as client:
        while not stop.is_set():
            started = time.perf_counter()
            try:
                response = client.get(f"http://127.0.0.1:{APP_PORT}/slow-query")
                if response.status_code >= 400:
                    errors += 1
                else:
                    body = response.json()
                    durations.append(float(body.get("duration_ms") or 0))
            except Exception:
                errors += 1
            count += 1
            elapsed = time.perf_counter() - started
            time.sleep(max(0.01, 0.08 - elapsed))
    stats.update(
        {
            "requests": count,
            "errors": errors,
            "max_duration_ms": max(durations) if durations else None,
            "last_duration_ms": durations[-1] if durations else None,
        }
    )


def _wait_for_prometheus_sample(warmup_seconds: int) -> None:
    deadline = time.time() + warmup_seconds
    latest = None
    while time.time() < deadline:
        latest = _prom_query('sentinel_slow_query_last_duration_seconds{service="payment-service"}')
        result = latest.get("data", {}).get("result", [])
        if result:
            value = float(result[0]["value"][1])
            if value > 0:
                return
        time.sleep(2)
    raise RuntimeError(f"Prometheus did not scrape a real slow-query sample: {latest}")


def _wait_for_prometheus_alert(timeout: int) -> dict[str, Any]:
    deadline = time.time() + timeout
    latest = None
    while time.time() < deadline:
        response = httpx.get(f"http://127.0.0.1:{PROM_PORT}/api/v1/alerts", timeout=10.0)
        latest = response.json()
        for alert in latest.get("data", {}).get("alerts", []):
            labels = alert.get("labels") or {}
            if labels.get("alertname") == "SentinelSlowQueryLatency" and alert.get("state") in {"firing", "pending"}:
                return alert
        time.sleep(2)
    raise RuntimeError(f"Prometheus alert did not fire: {latest}")


def _generic_alert_payload(alert: dict[str, Any], incident_id: str) -> dict[str, Any]:
    labels = dict(alert.get("labels") or {})
    labels.setdefault("service", "payment-service")
    labels.setdefault("alertname", "SentinelSlowQueryLatency")
    labels.setdefault("route", "/slow-query")
    annotations = dict(alert.get("annotations") or {})
    annotations.setdefault("summary", "payment-service /slow-query latency spike from missing SQLite index")
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "receiver": "sentinel",
        "source": "prometheus",
        "status": "firing",
        "incident_id": incident_id,
        "groupKey": '{alertname="SentinelSlowQueryLatency", service="payment-service"}',
        "commonLabels": labels,
        "groupLabels": {"alertname": "SentinelSlowQueryLatency", "service": "payment-service"},
        "commonAnnotations": annotations,
        "alerts": [
            {
                "status": "firing",
                "fingerprint": incident_id,
                "startsAt": now,
                "labels": labels,
                "annotations": annotations,
            }
        ],
    }


def _wait_for_status(investigation_id: str, expected: str, timeout: int) -> dict[str, Any]:
    deadline = time.time() + timeout
    latest = None
    while time.time() < deadline:
        response = httpx.get(
            f"http://127.0.0.1:{APP_PORT}/investigations/{investigation_id}",
            headers=_auth_headers(),
            timeout=10.0,
        )
        response.raise_for_status()
        latest = response.json()
        if latest.get("status") == expected:
            return latest
        if latest.get("status") in {"failed", "insufficient_confidence"}:
            raise RuntimeError(f"Investigation ended before {expected}: {latest}")
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {expected}: {latest}")


def _summarize(completed: dict[str, Any], load_stats: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    message = completed.get("last_discord_message") or ""
    tool_calls = int(completed.get("tool_calls") or 0)
    required_terms = [
        "missing SQLite index",
        "orders.user_id",
        "Prometheus",
        "Loki",
        "idx_orders_user_id",
        "after fix",
    ]
    passed = (
        completed.get("status") == "completed"
        and tool_calls >= 20
        and completed.get("remediation_result", {}).get("status") == "executed"
        and all(term in message for term in required_terms)
    )
    return {
        "passed": passed,
        "status": completed.get("status"),
        "current_state": completed.get("current_state"),
        "tool_calls": tool_calls,
        "tool_call_names": completed.get("tool_call_names") or [],
        "diagnosis": completed.get("diagnosis"),
        "recommendation": completed.get("recommendation"),
        "remediation_result": completed.get("remediation_result"),
        "live_provider_proofs": completed.get("live_provider_proofs"),
        "live_tool_proofs": completed.get("live_tool_proofs"),
        "load_stats": load_stats,
        "prometheus_alert": alert,
        "last_discord_message": message,
    }


def _render_summary(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "REAL SLOW-QUERY INCIDENT DEMO",
            f"passed: {summary['passed']}",
            f"status: {summary['status']} state: {summary['current_state']}",
            f"tool_calls: {summary['tool_calls']}",
            f"tool_call_names: {', '.join(summary['tool_call_names'])}",
            f"live_provider_proofs: {json.dumps(summary['live_provider_proofs'], sort_keys=True)}",
            f"live_tool_proofs: {json.dumps(summary['live_tool_proofs'], sort_keys=True)}",
            f"diagnosis: {summary['diagnosis']}",
            f"recommendation: {summary['recommendation']}",
            f"remediation: {summary['remediation_result']}",
            f"load_stats: {summary['load_stats']}",
            "discord_message:",
            summary["last_discord_message"],
        ]
    )


def _prom_query(query: str) -> dict[str, Any]:
    response = httpx.get(
        f"http://127.0.0.1:{PROM_PORT}/api/v1/query",
        params={"query": query},
        timeout=10.0,
    )
    response.raise_for_status()
    return response.json()


def _wait_http(url: str, timeout: int) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=5.0)
            last = response.text
            if response.status_code < 500:
                return
        except Exception as exc:
            last = str(exc)
        time.sleep(2)
    raise RuntimeError(f"{url} did not become ready: {last}")


def _post(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    response = httpx.post(url, params=params, json=json_body, headers=headers, timeout=30.0)
    response.raise_for_status()
    return response.json()


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}"}


def _load_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        values[key.strip()] = value
    return values


def _write_summary(summary: dict[str, Any], path: Path) -> None:
    path = PROJECT_ROOT / path if not path.is_absolute() else path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, default=str) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(command)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


if __name__ == "__main__":
    main()
