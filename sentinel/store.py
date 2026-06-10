from __future__ import annotations

import json
import hashlib
import sqlite3
from threading import RLock
from pathlib import Path
from typing import Any

from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.models import AuditEvent, EvaluationResult, InvestigationState, ToolCallRecord


class SQLiteInvestigationStore:
    """Durable checkpoint store for Investigation State and audit records."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.db_path = str(db_path)
        self._lock = RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.migrate()

    def migrate(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    scenario_name TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    call_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    key TEXT PRIMARY KEY,
                    scope TEXT NOT NULL,
                    investigation_id TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS evaluation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scenario_name TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    provider TEXT PRIMARY KEY,
                    subject TEXT,
                    access_token TEXT NOT NULL,
                    token_type TEXT,
                    refresh_token TEXT,
                    scopes_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT OR IGNORE INTO schema_migrations(version) VALUES (2);
                CREATE TABLE IF NOT EXISTS incident_fingerprints (
                    id TEXT PRIMARY KEY,
                    service_name TEXT NOT NULL,
                    fingerprint_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS service_profiles (
                    service_name TEXT PRIMARY KEY,
                    profile_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS approved_remediations (
                    id TEXT PRIMARY KEY,
                    service_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    remediation_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS runbook_snippets (
                    id TEXT PRIMARY KEY,
                    service_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    snippet TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

    def save_state(self, state: InvestigationState) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO investigations(id, incident_id, scenario_name, state_json, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET
                    incident_id=excluded.incident_id,
                    scenario_name=excluded.scenario_name,
                    state_json=excluded.state_json,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (state.id, state.incident_id, state.scenario_name, state.model_dump_json()),
            )

    def load_state(self, investigation_id: str) -> InvestigationState:
        with self._lock:
            row = self._conn.execute(
                "SELECT state_json FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"Investigation {investigation_id} was not found")
        return InvestigationState.model_validate_json(row["state_json"])

    def append_audit_event(self, event: AuditEvent) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO audit_events(id, investigation_id, event_type, event_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.investigation_id,
                    event.event_type,
                    event.model_dump_json(),
                ),
            )

    def append_tool_call(self, call: ToolCallRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO tool_calls(id, investigation_id, tool_name, call_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    call.id,
                    call.investigation_id,
                    call.tool_name,
                    call.model_dump_json(),
                ),
            )

    def list_tool_calls(self, investigation_id: str) -> list[ToolCallRecord]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT call_json FROM tool_calls
                WHERE investigation_id = ?
                ORDER BY rowid ASC
                """,
                (investigation_id,),
            ).fetchall()
        return [ToolCallRecord.model_validate_json(row["call_json"]) for row in rows]

    def remember_idempotency_key(self, key: str, scope: str, investigation_id: str) -> bool:
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    """
                    INSERT INTO idempotency_keys(key, scope, investigation_id)
                    VALUES (?, ?, ?)
                    """,
                    (key, scope, investigation_id),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def lookup_idempotency_key(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT investigation_id FROM idempotency_keys
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
        return row["investigation_id"] if row else None

    def record_evaluation(self, result: EvaluationResult) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO evaluation_results(scenario_name, result_json) VALUES (?, ?)",
                (result.scenario_name, result.model_dump_json()),
            )

    def save_oauth_token(
        self,
        *,
        provider: str,
        access_token: str,
        subject: str | None = None,
        token_type: str | None = None,
        refresh_token: str | None = None,
        scopes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        provider, access_token, scopes, metadata = validate_oauth_token_record(
            provider,
            access_token,
            scopes,
            metadata,
        )
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO oauth_tokens(
                    provider, subject, access_token, token_type, refresh_token,
                    scopes_json, metadata_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(provider) DO UPDATE SET
                    subject=excluded.subject,
                    access_token=excluded.access_token,
                    token_type=excluded.token_type,
                    refresh_token=excluded.refresh_token,
                    scopes_json=excluded.scopes_json,
                    metadata_json=excluded.metadata_json,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    provider,
                    subject,
                    access_token,
                    token_type,
                    refresh_token,
                    json.dumps(scopes or []),
                    json.dumps(metadata or {}, sort_keys=True),
                ),
            )

    def load_oauth_token(self, provider: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT provider, subject, access_token, token_type, refresh_token,
                       scopes_json, metadata_json, updated_at
                FROM oauth_tokens
                WHERE provider = ?
                """,
                (provider,),
            ).fetchone()
        if row is None:
            return None
        return {
            "provider": row["provider"],
            "subject": row["subject"],
            "access_token": row["access_token"],
            "token_type": row["token_type"],
            "refresh_token": row["refresh_token"],
            "scopes": json.loads(row["scopes_json"]),
            "metadata": json.loads(row["metadata_json"]),
            "updated_at": row["updated_at"],
        }

    def remember_incident(self, fingerprint: dict[str, Any]) -> None:
        service_name = _memory_text(fingerprint.get("service_name") or fingerprint.get("service"))
        if not service_name:
            raise ValueError("incident fingerprint missing service_name")
        normalized = {**fingerprint, "service_name": service_name}
        fingerprint_id = _stable_memory_id("incident", normalized)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO incident_fingerprints(id, service_name, fingerprint_json)
                VALUES (?, ?, ?)
                """,
                (fingerprint_id, service_name, json.dumps(normalized, sort_keys=True, default=str)),
            )
            self._conn.execute(
                """
                INSERT INTO service_profiles(service_name, profile_json, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(service_name) DO UPDATE SET
                    profile_json=excluded.profile_json,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    service_name,
                    json.dumps(_service_profile_from_fingerprint(normalized), sort_keys=True, default=str),
                ),
            )
            remediation = normalized.get("remediation")
            if isinstance(remediation, dict) and remediation.get("status") == "executed":
                remediation_id = _stable_memory_id("remediation", normalized)
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO approved_remediations(id, service_name, action, remediation_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        remediation_id,
                        service_name,
                        _memory_text(remediation.get("action")) or "unknown",
                        json.dumps(remediation, sort_keys=True, default=str),
                    ),
                )
            runbook = _runbook_snippet_from_fingerprint(normalized)
            if runbook:
                runbook_id = _stable_memory_id("runbook", normalized)
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO runbook_snippets(id, service_name, title, snippet)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        runbook_id,
                        service_name,
                        runbook["title"],
                        runbook["snippet"],
                    ),
                )

    def get_similar_incidents(self, alert: dict[str, Any], *, limit: int = 3) -> list[str]:
        services = _services_from_alert(alert)
        if not services:
            return []
        placeholders = ", ".join("?" for _ in services)
        query = f"""
            SELECT fingerprint_json FROM incident_fingerprints
            WHERE service_name IN ({placeholders})
            ORDER BY created_at DESC
            LIMIT ?
        """
        with self._lock:
            rows = self._conn.execute(query, (*services, limit)).fetchall()
        hints = [_incident_hint(json.loads(row["fingerprint_json"])) for row in rows]
        return list(dict.fromkeys(hint for hint in hints if hint))[:limit]

    def get_service_context(self, service_name: str) -> dict[str, Any]:
        service_name = _memory_text(service_name)
        if not service_name:
            return {"service_name": "", "profile": None, "approved_remediations": [], "runbook_snippets": []}
        with self._lock:
            profile_row = self._conn.execute(
                "SELECT profile_json FROM service_profiles WHERE service_name = ?",
                (service_name,),
            ).fetchone()
            remediation_rows = self._conn.execute(
                """
                SELECT remediation_json FROM approved_remediations
                WHERE service_name = ?
                ORDER BY created_at DESC
                LIMIT 3
                """,
                (service_name,),
            ).fetchall()
            runbook_rows = self._conn.execute(
                """
                SELECT title, snippet FROM runbook_snippets
                WHERE service_name = ?
                ORDER BY created_at DESC
                LIMIT 3
                """,
                (service_name,),
            ).fetchall()
        return {
            "service_name": service_name,
            "profile": json.loads(profile_row["profile_json"]) if profile_row else None,
            "approved_remediations": [
                json.loads(row["remediation_json"]) for row in remediation_rows
            ],
            "runbook_snippets": [
                {"title": row["title"], "snippet": row["snippet"]} for row in runbook_rows
            ],
        }

    def count_rows(self, table: str) -> int:
        allowed = {
            "investigations",
            "audit_events",
            "tool_calls",
            "idempotency_keys",
            "evaluation_results",
            "oauth_tokens",
            "incident_fingerprints",
            "service_profiles",
            "approved_remediations",
            "runbook_snippets",
            "schema_migrations",
        }
        if table not in allowed:
            raise ValueError(f"Unsupported table: {table}")
        with self._lock:
            row = self._conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
        return int(row["count"])

    def ping(self) -> bool:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()
        return True

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def safe_json_hash_payload(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str)


def _stable_memory_id(prefix: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _memory_text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _services_from_alert(alert: dict[str, Any]) -> list[str]:
    raw = alert.get("affected_services") or alert.get("services")
    if isinstance(raw, list):
        return [service for item in raw if (service := _memory_text(item))]
    service = _memory_text(alert.get("service_name") or alert.get("service"))
    return [service] if service else []


def _incident_hint(fingerprint: dict[str, Any]) -> str:
    service_name = _memory_text(fingerprint.get("service_name")) or "unknown-service"
    incident_id = _memory_text(fingerprint.get("incident_id")) or "prior incident"
    summary = _sentence_text(fingerprint.get("summary") or fingerprint.get("root_cause"))
    raw_remediation = fingerprint.get("remediation")
    remediation = raw_remediation if isinstance(raw_remediation, dict) else {}
    action = _sentence_text(remediation.get("message") or remediation.get("action")) or "review the prior remediation and verification evidence"
    if not summary:
        return ""
    return (
        f"Similar prior incident {incident_id} affected {service_name}: {summary}. "
        f"Prior approved remediation: {action}."
    )


def _sentence_text(value: Any) -> str:
    return _memory_text(value).rstrip(".")


def _service_profile_from_fingerprint(fingerprint: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_name": fingerprint["service_name"],
        "last_incident_id": fingerprint.get("incident_id"),
        "last_root_cause": fingerprint.get("root_cause"),
        "last_summary": fingerprint.get("summary"),
        "last_seen_at": fingerprint.get("timestamp"),
    }


def _runbook_snippet_from_fingerprint(fingerprint: dict[str, Any]) -> dict[str, str] | None:
    summary = _memory_text(fingerprint.get("summary"))
    if not summary:
        return None
    service_name = fingerprint["service_name"]
    return {
        "title": f"Prior SENTINEL incident for {service_name}",
        "snippet": summary[:1000],
    }


def validate_oauth_token_record(
    provider: str,
    access_token: str,
    scopes: list[str] | None,
    metadata: dict[str, Any] | None,
) -> tuple[str, str, list[str], dict[str, Any]]:
    if not isinstance(provider, str) or not provider.strip():
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            "OAuth token record missing provider",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if not isinstance(access_token, str) or not access_token.strip():
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"OAuth token record for {provider} missing usable access_token",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if scopes is None:
        normalized_scopes: list[str] = []
    elif isinstance(scopes, list) and all(isinstance(item, str) for item in scopes):
        normalized_scopes = scopes
    else:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"OAuth token record for {provider} has malformed scopes",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if metadata is None:
        normalized_metadata: dict[str, Any] = {}
    elif isinstance(metadata, dict):
        normalized_metadata = metadata
    else:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"OAuth token record for {provider} has malformed metadata",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return provider.strip(), access_token.strip(), normalized_scopes, normalized_metadata
