import importlib.util
import json
from pathlib import Path

import httpx
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_http_receiver_check_verifies_ready_and_connectivity_with_operator_token():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready={"ready": True, "missing_live_credentials": []},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    summary = script.run_http_receiver_check(
        "http://sentinel.example/",
        "sentinel-api-token",
        client,
    )

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "ready",
        "ready": {"ready": True, "missing_live_credentials": []},
        "connectivity": {"ready": True, "missing_live_credentials": [], "checks": []},
    }
    assert script._exit_code(summary) == 0
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
    ]
    assert client.get_headers[0] == {"authorization": "Bearer sentinel-api-token"}
    assert client.get_headers[1] == {"authorization": "Bearer sentinel-api-token"}


def test_http_receiver_check_rejects_invalid_base_url_before_network_or_auth():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready={"ready": True, "missing_live_credentials": []},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    summary = script.run_http_receiver_check("ftp://sentinel.example?token=secret", "sentinel-api-token", client)

    assert summary["mode"] == "http"
    assert summary["status"] == "receiver_base_url_invalid"
    assert "http(s)" in summary["error"]
    assert script._exit_code(summary) == 2
    assert client.get_urls == []
    assert client.get_headers == []


def test_http_receiver_check_stops_before_connectivity_when_receiver_not_ready():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready={
            "ready": False,
            "missing_live_credentials": ["SLACK_BOT_TOKEN"],
            "checks": [],
        },
        ready_status_code=503,
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    summary = script.run_http_receiver_check("http://sentinel.example", None, client)

    assert summary["mode"] == "http"
    assert summary["status"] == "not_ready"
    assert summary["endpoint"] == "/ready/live"
    assert summary["missing_live_credentials"] == ["SLACK_BOT_TOKEN"]
    assert script._exit_code(summary) == 2
    assert client.get_urls == ["http://sentinel.example/ready/live"]


def test_http_receiver_check_reports_connectivity_auth_failure():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready={"ready": True, "missing_live_credentials": []},
        connectivity={"detail": "Invalid SENTINEL API token"},
        connectivity_status_code=401,
    )

    summary = script.run_http_receiver_check("http://sentinel.example", None, client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "connectivity_failed",
        "endpoint": "/live/connectivity",
        "code": 401,
        "body": {"detail": "Invalid SENTINEL API token"},
    }
    assert script._exit_code(summary) == 2
    assert client.get_headers[1] == {}


def test_http_receiver_check_reports_unreachable_receiver():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready=httpx.ReadTimeout("timed out"),
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    summary = script.run_http_receiver_check("http://sentinel.example", "token", client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "receiver_unreachable",
        "error": "timed out",
    }
    assert script._exit_code(summary) == 2


def test_http_receiver_check_reports_malformed_ready_success_body_as_preflight_failure():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready="ok",
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    summary = script.run_http_receiver_check("http://sentinel.example", "token", client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "ready_malformed",
        "endpoint": "/ready/live",
        "body": "ok",
    }
    assert script._exit_code(summary) == 2


def test_http_receiver_check_reports_malformed_connectivity_success_body_as_preflight_failure():
    script = _load_check_script()
    client = _StubReceiverClient(
        ready={"ready": True, "missing_live_credentials": []},
        connectivity={"status": "ok"},
    )

    summary = script.run_http_receiver_check("http://sentinel.example", "token", client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "connectivity_malformed",
        "endpoint": "/live/connectivity",
        "body": {"status": "ok"},
    }
    assert script._exit_code(summary) == 2


def test_main_loads_env_file_before_deployed_receiver_auth(monkeypatch, tmp_path, capsys):
    script = _load_check_script()
    env_file = tmp_path / ".env"
    env_file.write_text("SENTINEL_API_TOKEN=file-token\n")
    captured = {}
    original_token = script.os.environ.get("SENTINEL_API_TOKEN")

    monkeypatch.delenv("SENTINEL_API_TOKEN", raising=False)
    monkeypatch.setattr(script.httpx, "Client", lambda timeout: _NullClient())
    monkeypatch.setattr(
        script,
        "run_http_receiver_check",
        lambda base_url, api_token, client: captured.setdefault(
            "summary",
            {
                "mode": "http",
                "base_url": base_url,
                "status": "ready",
                "api_token": api_token,
                "client": client.__class__.__name__,
            },
        ),
    )

    try:
        with pytest.raises(SystemExit) as exit_info:
            script.main(["--env-file", str(env_file), "--base-url", "http://sentinel.example"])
    finally:
        if original_token is None:
            script.os.environ.pop("SENTINEL_API_TOKEN", None)
        else:
            script.os.environ["SENTINEL_API_TOKEN"] = original_token

    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["api_token"] == "file-token"


def test_main_keeps_exported_api_token_ahead_of_env_file(monkeypatch, tmp_path, capsys):
    script = _load_check_script()
    env_file = tmp_path / ".env"
    env_file.write_text("SENTINEL_API_TOKEN=file-token\n")

    monkeypatch.setenv("SENTINEL_API_TOKEN", "shell-token")
    monkeypatch.setattr(script.httpx, "Client", lambda timeout: _NullClient())
    monkeypatch.setattr(
        script,
        "run_http_receiver_check",
        lambda base_url, api_token, _client: {
            "mode": "http",
            "base_url": base_url,
            "status": "ready",
            "api_token": api_token,
        },
    )

    with pytest.raises(SystemExit) as exit_info:
        script.main(["--env-file", str(env_file), "--base-url", "http://sentinel.example"])

    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["api_token"] == "shell-token"


def test_main_reports_invalid_env_file_as_preflight_failure(tmp_path, capsys):
    script = _load_check_script()
    env_file = tmp_path / ".env.bad"
    env_file.write_text("not-a-valid-line\n")

    with pytest.raises(SystemExit) as exit_info:
        script.main(["--env-file", str(env_file)])

    body = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 2
    assert body["status"] == "invalid_env_file"
    assert ".env.bad:1" in body["error"]


def test_inprocess_check_still_prints_raw_connectivity_report(monkeypatch, tmp_path, capsys):
    script = _load_check_script()
    env_file = tmp_path / ".env.missing"

    monkeypatch.setattr(
        script,
        "run_live_connectivity_checks",
        lambda: _StubConnectivityReport(
            ready=True,
            missing_live_credentials=[],
            checks=[{"name": "sentinel.redis", "passed": True}],
        ),
    )

    script.main(["--env-file", str(env_file)])

    assert json.loads(capsys.readouterr().out) == {
        "ready": True,
        "missing_live_credentials": [],
        "checks": [{"name": "sentinel.redis", "passed": True}],
    }


def test_inprocess_check_exits_two_for_invalid_configuration(monkeypatch, tmp_path, capsys):
    script = _load_check_script()
    env_file = tmp_path / ".env.missing"

    monkeypatch.setattr(
        script,
        "run_live_connectivity_checks",
        lambda: _StubConnectivityReport(
            ready=False,
            missing_live_credentials=[],
            checks=[
                {
                    "name": "sentinel.config",
                    "provider": "sentinel",
                    "passed": False,
                    "detail": "SENTINEL_LIVE_MAX_PAGES must be a positive integer",
                }
            ],
        ),
    )

    with pytest.raises(SystemExit) as exit_info:
        script.main(["--env-file", str(env_file)])

    assert exit_info.value.code == 2
    assert json.loads(capsys.readouterr().out)["checks"][0]["name"] == "sentinel.config"


def _load_check_script():
    spec = importlib.util.spec_from_file_location(
        "check_live_connectivity",
        ROOT / "scripts" / "check_live_connectivity.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _StubConnectivityReport:
    def __init__(self, *, ready: bool, missing_live_credentials: list[str], checks: list[dict]):
        self.ready = ready
        self.missing_live_credentials = missing_live_credentials
        self.checks = checks

    def model_dump(self, mode: str = "python"):
        return {
            "ready": self.ready,
            "missing_live_credentials": self.missing_live_credentials,
            "checks": self.checks,
        }


class _NullClient:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _StubReceiverClient:
    def __init__(
        self,
        *,
        ready,
        connectivity,
        ready_status_code: int = 200,
        connectivity_status_code: int = 200,
    ):
        self.ready = ready
        self.connectivity = connectivity
        self.ready_status_code = ready_status_code
        self.connectivity_status_code = connectivity_status_code
        self.get_urls = []
        self.get_headers = []

    def get(self, url: str, headers: dict[str, str] | None = None):
        self.get_urls.append(url)
        self.get_headers.append(headers or {})
        if url.endswith("/ready/live"):
            if isinstance(self.ready, httpx.HTTPError):
                raise self.ready
            return _Response(self.ready_status_code, self.ready)
        if url.endswith("/live/connectivity"):
            if isinstance(self.connectivity, httpx.HTTPError):
                raise self.connectivity
            return _Response(self.connectivity_status_code, self.connectivity)
        raise AssertionError(f"unexpected GET {url}")


class _Response:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body
