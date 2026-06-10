from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Iterable


SIMULATED_OBSERVABILITY_WINDOW = "02:30-03:30 UTC"
SIMULATED_REPOSITORY_WINDOW = "last 6h"
LIVE_OBSERVABILITY_WINDOW = "now-30m"
LIVE_REPOSITORY_WINDOW = "now-6h"
LIVE_WINDOW_END = "now"

_TIMESTAMP_KEYS = {
    "created_at",
    "detected_at",
    "fired_at",
    "last_status_change_at",
    "occurred_at",
    "started_at",
    "triggered_at",
}


def live_time_window_artifacts(webhook_payload: dict[str, Any] | None) -> dict[str, Any]:
    incident_at = extract_webhook_timestamp(webhook_payload)
    artifacts: dict[str, Any] = {
        "observability_window": LIVE_OBSERVABILITY_WINDOW,
        "observability_window_end": LIVE_WINDOW_END,
        "repo_window": LIVE_REPOSITORY_WINDOW,
        "repo_window_end": LIVE_WINDOW_END,
    }
    if not incident_at:
        return artifacts

    end_at = min(incident_at + timedelta(minutes=15), datetime.now(UTC))
    if end_at < incident_at:
        end_at = datetime.now(UTC)
    artifacts.update(
        {
            "incident_occurred_at": _iso_z(incident_at),
            "observability_window": _iso_z(incident_at - timedelta(minutes=30)),
            "observability_window_end": _iso_z(end_at),
            "repo_window": _iso_z(incident_at - timedelta(hours=6)),
            "repo_window_end": _iso_z(end_at),
        }
    )
    return artifacts


def observability_payload(state: Any | None, service: str) -> dict[str, Any]:
    payload = {"service": service, "time_window": observability_window(state)}
    end = observability_window_end(state)
    if end:
        payload["time_window_end"] = end
    return payload


def repository_payload(state: Any | None, service: str) -> dict[str, Any]:
    payload = {"service": service, "time_window": repository_window(state)}
    end = repository_window_end(state)
    if end:
        payload["time_window_end"] = end
    artifacts = getattr(state, "artifacts", {}) if state is not None else {}
    if isinstance(artifacts, dict):
        ref = artifacts.get("deployment_ref") or artifacts.get("commit_sha")
        if ref:
            payload["ref"] = ref
        pull_request = artifacts.get("pull_request")
        if pull_request:
            payload["pull_request"] = pull_request
    return payload


def observability_window(state: Any | None) -> str:
    if state is not None and _is_live(state):
        return state.artifacts.get("observability_window") or LIVE_OBSERVABILITY_WINDOW
    return SIMULATED_OBSERVABILITY_WINDOW


def observability_window_end(state: Any | None) -> str | None:
    if state is not None and _is_live(state):
        return state.artifacts.get("observability_window_end") or LIVE_WINDOW_END
    return None


def repository_window(state: Any | None) -> str:
    if state is not None and _is_live(state):
        return state.artifacts.get("repo_window") or LIVE_REPOSITORY_WINDOW
    return SIMULATED_REPOSITORY_WINDOW


def repository_window_end(state: Any | None) -> str | None:
    if state is not None and _is_live(state):
        return state.artifacts.get("repo_window_end") or LIVE_WINDOW_END
    return None


def extract_webhook_timestamp(webhook_payload: dict[str, Any] | None) -> datetime | None:
    if not webhook_payload:
        return None
    for candidate in _timestamp_candidates(webhook_payload):
        parsed = _parse_datetime(candidate)
        if parsed:
            return parsed
    return None


def _timestamp_candidates(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in _TIMESTAMP_KEYS and isinstance(child, str):
                yield child
            yield from _timestamp_candidates(child)
    elif isinstance(value, list):
        for item in value:
            yield from _timestamp_candidates(item)


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_live(state: Any | None) -> bool:
    return bool(state and getattr(state, "scenario_name", None) == "live")
