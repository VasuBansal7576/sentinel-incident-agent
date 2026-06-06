from __future__ import annotations

import json
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

    def count_rows(self, table: str) -> int:
        allowed = {
            "investigations",
            "audit_events",
            "tool_calls",
            "idempotency_keys",
            "evaluation_results",
            "oauth_tokens",
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
