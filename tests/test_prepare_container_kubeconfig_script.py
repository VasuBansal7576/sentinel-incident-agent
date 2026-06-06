import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_container_kubeconfig.py"
spec = importlib.util.spec_from_file_location("prepare_container_kubeconfig", SCRIPT)
prepare = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(prepare)


def test_rewrite_kubeconfig_maps_localhost_to_docker_host():
    config = {
        "clusters": [
            {
                "name": "kind-sentinel-free-tier",
                "cluster": {
                    "server": "https://127.0.0.1:65012",
                    "certificate-authority-data": "ca",
                },
            }
        ]
    }

    rewritten, rewrites = prepare._rewrite_kubeconfig(config)

    cluster = rewritten["clusters"][0]["cluster"]
    assert cluster["server"] == "https://host.docker.internal:65012"
    assert cluster["tls-server-name"] == "127.0.0.1"
    assert rewrites == [
        {
            "cluster": "kind-sentinel-free-tier",
            "from": "https://127.0.0.1:65012",
            "to": "https://host.docker.internal:65012",
            "tls_server_name": "127.0.0.1",
        }
    ]


def test_prepare_container_kubeconfig_writes_output_and_updates_env(tmp_path, monkeypatch):
    source = tmp_path / "host-kubeconfig"
    source.write_text("apiVersion: v1\n")
    output = tmp_path / ".sentinel" / "kubeconfig.container"
    env_file = tmp_path / ".env"
    env_file.write_text("GITHUB_OWNER=owner\nHOST_KUBECONFIG=~/.kube/config\n")
    monkeypatch.setattr(
        prepare,
        "_read_minified_kubeconfig",
        lambda _path, context="": (
            {
                "clusters": [
                    {
                        "name": "kind-sentinel-free-tier",
                        "cluster": {"server": "https://localhost:65012"},
                    }
                ]
            },
            None,
        ),
    )
    args = SimpleNamespace(
        input=str(source),
        output=str(output),
        context="",
        update_env_file=str(env_file),
        dry_run=False,
    )

    summary = prepare.prepare_container_kubeconfig(args)

    assert summary["status"] == "created"
    assert summary["env_file_updated"] is True
    assert "host.docker.internal" in output.read_text()
    content = env_file.read_text()
    assert "HOST_KUBECONFIG=~/.kube/config" in content
    assert f"CONTAINER_KUBECONFIG={output}" in content


def test_prepare_container_kubeconfig_reports_missing_input(tmp_path):
    args = SimpleNamespace(
        input=str(tmp_path / "missing"),
        output=str(tmp_path / "out"),
        context="",
        update_env_file="",
        dry_run=False,
    )

    summary = prepare.prepare_container_kubeconfig(args)

    assert summary["status"] == "input_missing"
