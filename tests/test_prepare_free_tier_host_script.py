import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_free_tier_host.py"
spec = importlib.util.spec_from_file_location("prepare_free_tier_host", SCRIPT)
prepare = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(prepare)


def test_prepare_host_reports_missing_kind_without_mutation(monkeypatch):
    args = SimpleNamespace(
        cluster_name="sentinel-free-tier",
        install_kind=False,
        create_cluster=False,
        use_context=False,
        dry_run=False,
    )
    monkeypatch.setattr(
        prepare.shutil,
        "which",
        lambda name: None if name == "kind" else f"/usr/local/bin/{name}",
    )
    monkeypatch.setattr(
        prepare,
        "_command_status",
        lambda _command, **_kwargs: {"passed": True, "status": "ok", "stdout": ""},
    )

    summary = prepare.prepare_host(args)

    assert summary["status"] == "not_ready"
    assert summary["checks"]["binaries"]["kind"] is None
    assert summary["cluster"]["detail"] == "kind is missing."
    assert summary["actions"] == []


def test_prepare_host_dry_run_plans_kind_install(monkeypatch):
    args = SimpleNamespace(
        cluster_name="sentinel-free-tier",
        install_kind=True,
        create_cluster=False,
        use_context=False,
        dry_run=True,
    )
    monkeypatch.setattr(
        prepare.shutil,
        "which",
        lambda name: {
            "docker": "/usr/local/bin/docker",
            "kubectl": "/usr/local/bin/kubectl",
            "brew": "/opt/homebrew/bin/brew",
        }.get(name),
    )
    monkeypatch.setattr(
        prepare,
        "_command_status",
        lambda _command, **_kwargs: {"passed": True, "status": "ok", "stdout": ""},
    )

    summary = prepare.prepare_host(args)

    assert summary["status"] == "would_prepare"
    assert summary["actions"] == [
        {
            "name": "install_kind",
            "status": "planned",
            "command": ["/opt/homebrew/bin/brew", "install", "kind"],
        }
    ]


def test_prepare_host_dry_run_plans_cluster_creation(monkeypatch):
    args = SimpleNamespace(
        cluster_name="sentinel-free-tier",
        install_kind=False,
        create_cluster=True,
        use_context=True,
        dry_run=True,
    )
    monkeypatch.setattr(
        prepare.shutil,
        "which",
        lambda name: f"/usr/local/bin/{name}",
    )
    monkeypatch.setattr(
        prepare,
        "_command_status",
        lambda command, **_kwargs: (
            {"passed": True, "status": "ok", "stdout": ""}
            if "kind" in command[0] and command[-1] == "clusters"
            else {"passed": True, "status": "ok", "stdout": "kind-other"}
        ),
    )

    summary = prepare.prepare_host(args)

    assert summary["status"] == "would_prepare"
    assert summary["actions"] == [
        {
            "name": "create_kind_cluster",
            "status": "planned",
            "command": ["/usr/local/bin/kind", "create", "cluster", "--name", "sentinel-free-tier"],
        }
    ]


def test_prepare_host_ready_when_expected_context_and_cluster_exist(monkeypatch):
    args = SimpleNamespace(
        cluster_name="sentinel-free-tier",
        install_kind=False,
        create_cluster=False,
        use_context=False,
        dry_run=False,
    )
    monkeypatch.setattr(
        prepare.shutil,
        "which",
        lambda name: f"/usr/local/bin/{name}",
    )

    def fake_status(command, **_kwargs):
        if command[:2] == ["/usr/local/bin/kind", "get"]:
            return {"passed": True, "status": "ok", "stdout": "sentinel-free-tier"}
        if command[:3] == ["/usr/local/bin/kubectl", "config", "current-context"]:
            return {"passed": True, "status": "ok", "stdout": "kind-sentinel-free-tier"}
        return {"passed": True, "status": "ok", "stdout": "ok"}

    monkeypatch.setattr(prepare, "_command_status", fake_status)

    summary = prepare.prepare_host(args)

    assert summary["status"] == "ready"
    assert summary["cluster"]["status"] == "ready"
    assert summary["kubectl_context"]["context"] == "kind-sentinel-free-tier"
