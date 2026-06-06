from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from sentinel.scenarios import build_scenarios
from sentinel.replay import ReplayIncidentEnvironment
from sentinel.tools import ToolFactory


class InvokeRequest(BaseModel):
    service: str = "payment-service"
    time_window: str = "02:30-03:30 UTC"
    payload: dict[str, Any] = {}


def create_observe_app() -> FastAPI:
    return _create_namespace_app("observe")


def create_repo_app() -> FastAPI:
    return _create_namespace_app("repo")


def create_infra_app() -> FastAPI:
    return _create_namespace_app("infra")


def create_comms_app() -> FastAPI:
    return _create_namespace_app("comms")


def create_all_replay_backends() -> dict[str, FastAPI]:
    return {
        "observe": create_observe_app(),
        "repo": create_repo_app(),
        "infra": create_infra_app(),
        "comms": create_comms_app(),
    }


def _create_namespace_app(namespace: str) -> FastAPI:
    scenario = build_scenarios()["golden_path"].model_copy(
        update={"transient_failures": {}, "degraded_tools": {}}
    )
    environment = ReplayIncidentEnvironment(scenario)
    registry = ToolFactory(environment).build_registry()
    app = FastAPI(title=f"SENTINEL {namespace} replay backend")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "namespace": namespace}

    @app.post("/invoke/{short_name}")
    def invoke(short_name: str, request: InvokeRequest) -> dict[str, Any]:
        tool_name = f"{namespace}.{short_name}"
        if tool_name not in registry.contracts:
            raise HTTPException(status_code=404, detail=f"Unknown tool {tool_name}")
        contract = registry.get_contract(tool_name)
        payload = {"service": request.service, "time_window": request.time_window, **request.payload}
        try:
            return environment.invoke(contract, payload)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    return app
