import importlib.util
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "preflight_credentialed_live_e2e.py"
spec = importlib.util.spec_from_file_location("preflight_credentialed_live_e2e", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(preflight)


def test_preflight_passes_required_files_and_compose_when_docker_is_reachable(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight.subprocess, "run", _successful_run)
    monkeypatch.setattr(preflight, "_port_free", lambda port: True)
    monkeypatch.setattr(preflight.Path, "home", lambda: tmp_path)
    (tmp_path / ".kube").mkdir()
    (tmp_path / ".kube" / "config").write_text("apiVersion: v1\n")

    summary = preflight.run_preflight(project_root=tmp_path)

    assert summary["passed"] is True
    assert summary["status"] == "ready"
    assert summary["errors"] == []
    assert summary["warnings"] == []


def test_preflight_fails_before_credentials_when_docker_daemon_is_unreachable(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight.subprocess, "run", _docker_info_fails)
    monkeypatch.setattr(preflight, "_port_free", lambda port: True)

    summary = preflight.run_preflight(project_root=tmp_path)

    assert summary["passed"] is False
    assert summary["status"] == "not_ready"
    assert any(check["name"] == "docker.daemon" for check in summary["errors"])


def test_preflight_reports_ports_and_default_kubeconfig_as_warnings(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight.subprocess, "run", _successful_run)
    monkeypatch.setattr(preflight, "_port_free", lambda port: port != 8000)
    monkeypatch.setattr(preflight.Path, "home", lambda: tmp_path)

    summary = preflight.run_preflight(project_root=tmp_path, check_compose=False)

    assert summary["passed"] is True
    warning_names = {warning["name"] for warning in summary["warnings"]}
    assert "port.8000" in warning_names
    assert "kubeconfig.default" in warning_names


def test_preflight_fails_when_required_port_is_owned_by_non_docker_process(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight.subprocess, "run", _successful_run)
    monkeypatch.setattr(preflight, "_port_free", lambda port: port != 8000)
    monkeypatch.setattr(preflight.Path, "home", lambda: tmp_path)

    summary = preflight.run_preflight(project_root=tmp_path)

    assert summary["passed"] is False
    assert any(check["name"] == "port.8000" for check in summary["errors"])
    assert summary["cleanup_commands"] == ["lsof -nP -iTCP:8000 -sTCP:LISTEN"]


def test_preflight_fails_when_required_port_is_owned_by_other_compose_project(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight.subprocess, "run", _docker_ps_other_project)
    monkeypatch.setattr(preflight, "_port_free", lambda port: port != 8000)
    monkeypatch.setattr(preflight.Path, "home", lambda: tmp_path)

    summary = preflight.run_preflight(project_root=tmp_path, compose_project="sentinel-live")

    assert summary["passed"] is False
    assert any(check["name"] == "docker.port_owner.8000" for check in summary["errors"])
    assert "sentinet" in summary["errors"][0]["detail"]
    assert summary["cleanup_commands"] == ["docker compose -p sentinet down"]


def test_preflight_allows_required_port_owned_by_target_compose_project(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight.subprocess, "run", _docker_ps_target_project)
    monkeypatch.setattr(preflight, "_port_free", lambda port: port != 8000)
    monkeypatch.setattr(preflight.Path, "home", lambda: tmp_path)

    summary = preflight.run_preflight(project_root=tmp_path, compose_project="sentinel-live")

    assert summary["passed"] is True
    assert any(
        check["name"] == "docker.port_owner.8000" and check["passed"]
        for check in summary["checks"]
    )
    assert summary["cleanup_commands"] == []


def test_preflight_can_skip_compose_checks(monkeypatch, tmp_path):
    _write_required_files(tmp_path)
    subprocess_calls = []
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")

    def run(*args, **kwargs):
        subprocess_calls.append(args)
        return _successful_run(*args, **kwargs)

    monkeypatch.setattr(preflight.subprocess, "run", run)
    monkeypatch.setattr(preflight, "_port_free", lambda port: True)

    summary = preflight.run_preflight(project_root=tmp_path, check_compose=False)

    assert summary["passed"] is True
    assert subprocess_calls == []
    assert not any(check["name"].startswith("docker.") for check in summary["checks"])


def test_port_free_checks_ipv4_and_ipv6_loopback(monkeypatch):
    calls = []

    def host_port_free(host, port, family):
        calls.append((host, port, family))
        return host == "127.0.0.1"

    monkeypatch.setattr(preflight, "_host_port_free", host_port_free)

    assert preflight._port_free(8000) is False
    assert [host for host, _port, _family in calls] == ["127.0.0.1", "::1"]


def _write_required_files(root: Path) -> None:
    for relpath in preflight.REQUIRED_FILES:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok\n")


def _successful_run(*_args, **_kwargs):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok\n", stderr="")


def _docker_info_fails(command, *_args, **_kwargs):
    return subprocess.CompletedProcess(
        args=command,
        returncode=1 if command == ["docker", "info"] else 0,
        stdout="",
        stderr="daemon unavailable\n" if command == ["docker", "info"] else "",
    )


def _docker_ps_other_project(command, *_args, **_kwargs):
    if command == ["docker", "ps", "--format", "{{json .}}"]:
        return _docker_ps_result("sentinet")
    return _successful_run()


def _docker_ps_target_project(command, *_args, **_kwargs):
    if command == ["docker", "ps", "--format", "{{json .}}"]:
        return _docker_ps_result("sentinel-live")
    return _successful_run()


def _docker_ps_result(project: str):
    payload = {
        "Names": f"{project}-sentinel-1",
        "Ports": "0.0.0.0:8000->8000/tcp, [::]:8000->8000/tcp",
        "Labels": f"com.docker.compose.project={project},com.docker.compose.service=sentinel",
    }
    return subprocess.CompletedProcess(
        args=["docker", "ps"],
        returncode=0,
        stdout=json.dumps(payload) + "\n",
        stderr="",
    )
