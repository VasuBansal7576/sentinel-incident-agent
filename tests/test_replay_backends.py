from fastapi.testclient import TestClient

from sentinel.replay_backends import create_all_replay_backends


def test_four_fastapi_replay_backends_invoke_representative_tools():
    apps = create_all_replay_backends()

    checks = {
        "observe": "fetch_service_logs",
        "repo": "get_deploy_history",
        "infra": "rollback_deployment",
        "comms": "post_to_slack",
    }
    for namespace, short_name in checks.items():
        client = TestClient(apps[namespace])
        health = client.get("/health")
        response = client.post(
            f"/invoke/{short_name}",
            json={"service": "payment-service", "payload": {"target": "v2.3.1"}},
        )

        assert health.status_code == 200
        assert response.status_code == 200
        assert response.json()["tool"] == f"{namespace}.{short_name}"

