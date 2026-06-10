from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableMapping, cast


PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
DEFAULT_PROFILE = "free-local"


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    description: str
    defaults: dict[str, str]
    credential_checks: tuple[str, ...]


UNSELECTED = ProviderProfile(
    name="unselected",
    description="No SENTINEL_PROFILE selected; preserve legacy environment defaults.",
    defaults={},
    credential_checks=(),
)


def load_selected_profile(environ: Mapping[str, str] | None = None) -> ProviderProfile:
    env = environ or os.environ
    name = (env.get("SENTINEL_PROFILE") or DEFAULT_PROFILE).strip() or DEFAULT_PROFILE
    return load_profile(name)


def load_profile(name: str) -> ProviderProfile:
    normalized = _safe_profile_name(name)
    path = PROFILE_DIR / f"{normalized}.yaml"
    if not path.is_file():
        available = ", ".join(available_profiles())
        raise ValueError(f"SENTINEL_PROFILE must be one of: {available}")
    raw = _parse_profile_yaml(path.read_text())
    profile_name = str(raw.get("name") or normalized).strip()
    defaults = cast(dict[object, object], raw.get("defaults")) if isinstance(raw.get("defaults"), dict) else {}
    credential_checks = cast(list[object], raw.get("credential_checks")) if isinstance(raw.get("credential_checks"), list) else []
    return ProviderProfile(
        name=profile_name,
        description=str(raw.get("description") or "").strip(),
        defaults={str(key): str(value) for key, value in defaults.items()},
        credential_checks=tuple(str(item) for item in credential_checks),
    )


def available_profiles() -> list[str]:
    return sorted(path.stem for path in PROFILE_DIR.glob("*.yaml"))


def apply_selected_profile_defaults(environ: MutableMapping[str, str] | None = None) -> ProviderProfile:
    env = environ if environ is not None else os.environ
    if not str(env.get("SENTINEL_PROFILE", "")).strip():
        return UNSELECTED
    profile = load_selected_profile(env)
    env["SENTINEL_PROFILE"] = profile.name
    for key, value in profile.defaults.items():
        if not str(env.get(key, "")).strip():
            env[key] = value
    return profile


def profile_missing_credentials(profile: ProviderProfile, env: Mapping[str, str]) -> list[str]:
    effective = dict(env)
    for key, value in profile.defaults.items():
        if not str(effective.get(key, "")).strip():
            effective[key] = value
    return [key for key in profile.credential_checks if not str(effective.get(key, "")).strip()]


def _safe_profile_name(name: str) -> str:
    normalized = name.strip()
    if not normalized or any(char in normalized for char in "/\\:"):
        raise ValueError("SENTINEL_PROFILE contains an invalid profile name")
    return normalized


def _parse_profile_yaml(text: str) -> dict[str, object]:
    data: dict[str, object] = {}
    current_section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            current_section = stripped[:-1]
            data[current_section] = {}
            continue
        if not line.startswith(" ") and ":" in stripped:
            key, value = stripped.split(":", 1)
            data[key.strip()] = _yaml_scalar(value.strip())
            current_section = None
            continue
        if current_section is None:
            continue
        section = data[current_section]
        if stripped.startswith("- "):
            if not isinstance(section, list):
                section = []
                data[current_section] = section
            section.append(_yaml_scalar(stripped[2:].strip()))
        elif ":" in stripped:
            if not isinstance(section, dict):
                section = {}
                data[current_section] = section
            key, value = stripped.split(":", 1)
            section[key.strip()] = _yaml_scalar(value.strip())
    return data


def _yaml_scalar(value: str) -> str:
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value
