from __future__ import annotations

from scripts import doctor
from sentinel.config import SentinelSettings
from sentinel.profiles import available_profiles, load_profile, profile_missing_credentials


BASE_ENV = {
    "SENTINEL_ENV": "development",
    "SENTINEL_API_TOKEN": "token",
    "SENTINEL_APPROVER_ID": "eng-oncall",
    "DATABASE_URL": "sqlite:///:memory:",
    "REDIS_URL": "redis://redis:6379/0",
    "CONTAINER_KUBECONFIG": ".sentinel/kubeconfig.container",
}


def test_provider_profiles_are_present_and_parseable():
    assert available_profiles() == ["enterprise-airgapped", "free-local", "startup"]

    free = load_profile("free-local")
    startup = load_profile("startup")

    assert free.defaults["PROMETHEUS_URL"] == "http://prometheus:9090"
    assert "GITHUB_TOKEN" not in free.credential_checks
    assert "GITHUB_TOKEN" in startup.credential_checks


def test_doctor_validates_only_selected_profile_credentials():
    free_check = doctor._check_profile_credentials({**BASE_ENV, "SENTINEL_PROFILE": "free-local"})
    startup_check = doctor._check_profile_credentials({**BASE_ENV, "SENTINEL_PROFILE": "startup"})

    assert free_check.passed is True
    assert startup_check.passed is False
    assert "startup missing GITHUB_TOKEN" in startup_check.detail


def test_profile_defaults_apply_before_settings_read(monkeypatch):
    monkeypatch.setenv("SENTINEL_PROFILE", "free-local")
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)
    monkeypatch.delenv("LOKI_URL", raising=False)
    monkeypatch.setenv("SENTINEL_API_TOKEN", "token")
    monkeypatch.setenv("SENTINEL_APPROVER_ID", "eng-oncall")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("REDIS_URL", "redis://redis:6379/0")

    settings = SentinelSettings.from_env()

    assert settings.profile == "free-local"
    assert settings.prometheus_url == "http://prometheus:9090"
    assert settings.loki_url == "http://loki:3100"


def test_profile_missing_credentials_uses_profile_defaults():
    profile = load_profile("free-local")

    missing = profile_missing_credentials(profile, BASE_ENV)

    assert missing == []


def test_doctor_effective_env_allows_shell_profile_override(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("\n".join(f"{key}={value}" for key, value in BASE_ENV.items()) + "\n")
    monkeypatch.setenv("SENTINEL_PROFILE", "startup")

    env = doctor._effective_env(env_path)

    assert env["SENTINEL_PROFILE"] == "startup"
    assert doctor._check_profile_credentials(env).passed is False
