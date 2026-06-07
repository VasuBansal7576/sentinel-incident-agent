import importlib.util
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

    summary = preflight.run_preflight(project_root=tmp_path)

    assert summary["passed"] is True
    warning_names = {warning["name"] for warning in summary["warnings"]}
    assert "port.8000" in warning_names
    assert "kubeconfig.default" in warning_names


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
