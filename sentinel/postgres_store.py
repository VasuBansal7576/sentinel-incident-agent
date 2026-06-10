from __future__ import annotations

from pathlib import Path
from threading import RLock
from typing import Any

from sentinel.models import AuditEvent, EvaluationResult, InvestigationState, ToolCallRecord
from sentinel.store import (
    _incident_hint,
    _memory_text,
    _runbook_snippet_from_fingerprint,
    _service_profile_from_fingerprint,
    _services_from_alert,
    _stable_memory_id,
    validate_oauth_token_record,
)


class PostgresInvestigationStore:
    """PostgreSQL-backed Investigation Store for production deployments."""

    def __init__(self, database_url: str):
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("psycopg is required for PostgresInvestigationStore") from exc

        self.psycopg = psycopg
        from psycopg.types.json import Jsonb

        self.Jsonb = Jsonb
        self.database_url = database_url
        self._lock = RLock()
        self._conn = psycopg.connect(database_url)
        self.migrate()

    def migrate(self) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    INSERT INTO schema_migrations(version) VALUES (1)
                    ON CONFLICT (version) DO NOTHING;
                    CREATE TABLE IF NOT EXISTS investigations (
                        id TEXT PRIMARY KEY,
                        incident_id TEXT NOT NULL,
                        scenario_name TEXT NOT NULL,
                        state_json JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id TEXT PRIMARY KEY,
                        investigation_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        event_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS tool_calls (
                        id TEXT PRIMARY KEY,
                        investigation_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        call_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS idempotency_keys (
                        key TEXT PRIMARY KEY,
                        scope TEXT NOT NULL,
                        investigation_id TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS evaluation_results (
                        id BIGSERIAL PRIMARY KEY,
                        scenario_name TEXT NOT NULL,
                        result_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS oauth_tokens (
                        provider TEXT PRIMARY KEY,
                        subject TEXT,
                        access_token TEXT NOT NULL,
                        token_type TEXT,
                        refresh_token TEXT,
                        scopes_json JSONB NOT NULL,
                        metadata_json JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    INSERT INTO schema_migrations(version) VALUES (2)
                    ON CONFLICT (version) DO NOTHING;
                    CREATE TABLE IF NOT EXISTS incident_fingerprints (
                        id TEXT PRIMARY KEY,
                        service_name TEXT NOT NULL,
                        fingerprint_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS service_profiles (
                        service_name TEXT PRIMARY KEY,
                        profile_json JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS approved_remediations (
                        id TEXT PRIMARY KEY,
                        service_name TEXT NOT NULL,
                        action TEXT NOT NULL,
                        remediation_json JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS runbook_snippets (
                        id TEXT PRIMARY KEY,
                        service_name TEXT NOT NULL,
                        title TEXT NOT NULL,
                        snippet TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    """
                )
            self._conn.commit()

    def save_state(self, state: InvestigationState) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO investigations(id, incident_id, scenario_name, state_json, updated_at)
                    VALUES (%s, %s, %s, %s, now())
                    ON CONFLICT (id) DO UPDATE SET
                        incident_id = excluded.incident_id,
                        scenario_name = excluded.scenario_name,
                        state_json = excluded.state_json,
                        updated_at = now()
                    """,
                    (
                        state.id,
                        state.incident_id,
                        state.scenario_name,
                        self.Jsonb(state.model_dump(mode="json")),
                    ),
                )
            self._conn.commit()

    def load_state(self, investigation_id: str) -> InvestigationState:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute("SELECT state_json FROM investigations WHERE id = %s", (investigation_id,))
                row = cur.fetchone()
        if row is None:
            raise KeyError(f"Investigation {investigation_id} was not found")
        return InvestigationState.model_validate(row[0])

    def append_audit_event(self, event: AuditEvent) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_events(id, investigation_id, event_type, event_json)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET event_json = excluded.event_json
                    """,
                    (
                        event.id,
                        event.investigation_id,
                        event.event_type,
                        self.Jsonb(event.model_dump(mode="json")),
                    ),
                )
            self._conn.commit()

    def append_tool_call(self, call: ToolCallRecord) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tool_calls(id, investigation_id, tool_name, call_json)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET call_json = excluded.call_json
                    """,
                    (
                        call.id,
                        call.investigation_id,
                        call.tool_name,
                        self.Jsonb(call.model_dump(mode="json")),
                    ),
                )
            self._conn.commit()

    def list_tool_calls(self, investigation_id: str) -> list[ToolCallRecord]:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT call_json FROM tool_calls
                    WHERE investigation_id = %s
                    ORDER BY created_at ASC, id ASC
                    """,
                    (investigation_id,),
                )
                rows = cur.fetchall()
        return [ToolCallRecord.model_validate(row[0]) for row in rows]

    def remember_idempotency_key(self, key: str, scope: str, investigation_id: str) -> bool:
        with self._lock:
            try:
                with self._conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO idempotency_keys(key, scope, investigation_id)
                        VALUES (%s, %s, %s)
                        """,
                        (key, scope, investigation_id),
                    )
                self._conn.commit()
                return True
            except self.psycopg.errors.UniqueViolation:
                self._conn.rollback()
                return False
            except Exception:
                self._conn.rollback()
                raise

    def lookup_idempotency_key(self, key: str) -> str | None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT investigation_id FROM idempotency_keys
                    WHERE key = %s
                    """,
                    (key,),
                )
                row = cur.fetchone()
        return row[0] if row else None

    def record_evaluation(self, result: EvaluationResult) -> None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO evaluation_results(scenario_name, result_json) VALUES (%s, %s)",
                    (result.scenario_name, self.Jsonb(result.model_dump(mode="json"))),
                )
            self._conn.commit()

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
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO oauth_tokens(
                        provider, subject, access_token, token_type, refresh_token,
                        scopes_json, metadata_json, updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, now())
                    ON CONFLICT (provider) DO UPDATE SET
                        subject = excluded.subject,
                        access_token = excluded.access_token,
                        token_type = excluded.token_type,
                        refresh_token = excluded.refresh_token,
                        scopes_json = excluded.scopes_json,
                        metadata_json = excluded.metadata_json,
                        updated_at = now()
                    """,
                    (
                        provider,
                        subject,
                        access_token,
                        token_type,
                        refresh_token,
                        self.Jsonb(scopes or []),
                        self.Jsonb(metadata or {}),
                    ),
                )
            self._conn.commit()

    def load_oauth_token(self, provider: str) -> dict[str, Any] | None:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT provider, subject, access_token, token_type, refresh_token,
                           scopes_json, metadata_json, updated_at
                    FROM oauth_tokens
                    WHERE provider = %s
                    """,
                    (provider,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return {
            "provider": row[0],
            "subject": row[1],
            "access_token": row[2],
            "token_type": row[3],
            "refresh_token": row[4],
            "scopes": row[5],
            "metadata": row[6],
            "updated_at": row[7],
        }

    def remember_incident(self, fingerprint: dict[str, Any]) -> None:
        service_name = _memory_text(fingerprint.get("service_name") or fingerprint.get("service"))
        if not service_name:
            raise ValueError("incident fingerprint missing service_name")
        normalized = {**fingerprint, "service_name": service_name}
        fingerprint_id = _stable_memory_id("incident", normalized)
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incident_fingerprints(id, service_name, fingerprint_json)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        service_name = excluded.service_name,
                        fingerprint_json = excluded.fingerprint_json
                    """,
                    (fingerprint_id, service_name, self.Jsonb(normalized)),
                )
                cur.execute(
                    """
                    INSERT INTO service_profiles(service_name, profile_json, updated_at)
                    VALUES (%s, %s, now())
                    ON CONFLICT (service_name) DO UPDATE SET
                        profile_json = excluded.profile_json,
                        updated_at = now()
                    """,
                    (service_name, self.Jsonb(_service_profile_from_fingerprint(normalized))),
                )
                remediation = normalized.get("remediation")
                if isinstance(remediation, dict) and remediation.get("status") == "executed":
                    cur.execute(
                        """
                        INSERT INTO approved_remediations(id, service_name, action, remediation_json)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            service_name = excluded.service_name,
                            action = excluded.action,
                            remediation_json = excluded.remediation_json
                        """,
                        (
                            _stable_memory_id("remediation", normalized),
                            service_name,
                            _memory_text(remediation.get("action")) or "unknown",
                            self.Jsonb(remediation),
                        ),
                    )
                runbook = _runbook_snippet_from_fingerprint(normalized)
                if runbook:
                    cur.execute(
                        """
                        INSERT INTO runbook_snippets(id, service_name, title, snippet)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            service_name = excluded.service_name,
                            title = excluded.title,
                            snippet = excluded.snippet
                        """,
                        (
                            _stable_memory_id("runbook", normalized),
                            service_name,
                            runbook["title"],
                            runbook["snippet"],
                        ),
                    )
            self._conn.commit()

    def get_similar_incidents(self, alert: dict[str, Any], *, limit: int = 3) -> list[str]:
        services = _services_from_alert(alert)
        if not services:
            return []
        placeholders = ", ".join(["%s"] * len(services))
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT fingerprint_json FROM incident_fingerprints
                    WHERE service_name IN ({placeholders})
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (*services, limit),
                )
                rows = cur.fetchall()
        hints = [_incident_hint(row[0]) for row in rows]
        return list(dict.fromkeys(hint for hint in hints if hint))[:limit]

    def get_service_context(self, service_name: str) -> dict[str, Any]:
        service_name = _memory_text(service_name)
        if not service_name:
            return {"service_name": "", "profile": None, "approved_remediations": [], "runbook_snippets": []}
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(
                    "SELECT profile_json FROM service_profiles WHERE service_name = %s",
                    (service_name,),
                )
                profile_row = cur.fetchone()
                cur.execute(
                    """
                    SELECT remediation_json FROM approved_remediations
                    WHERE service_name = %s
                    ORDER BY created_at DESC
                    LIMIT 3
                    """,
                    (service_name,),
                )
                remediation_rows = cur.fetchall()
                cur.execute(
                    """
                    SELECT title, snippet FROM runbook_snippets
                    WHERE service_name = %s
                    ORDER BY created_at DESC
                    LIMIT 3
                    """,
                    (service_name,),
                )
                runbook_rows = cur.fetchall()
        return {
            "service_name": service_name,
            "profile": profile_row[0] if profile_row else None,
            "approved_remediations": [row[0] for row in remediation_rows],
            "runbook_snippets": [
                {"title": row[0], "snippet": row[1]} for row in runbook_rows
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
            with self._conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                row = cur.fetchone()
                if row is None:
                    return 0
                return int(row[0])

    def ping(self) -> bool:
        with self._lock:
            try:
                with self._conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
                return True
            except Exception:
                try:
                    self._conn.rollback()
                except Exception:
                    pass
                return False

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def build_store(database_url: str | None):
    if database_url and database_url.startswith("sqlite:///"):
        from sentinel.store import SQLiteInvestigationStore

        path = database_url.removeprefix("sqlite:///")
        if path != ":memory:":
            expanded = Path(path).expanduser()
            expanded.parent.mkdir(parents=True, exist_ok=True)
            path = str(expanded)
        return SQLiteInvestigationStore(path)
    if database_url:
        return PostgresInvestigationStore(database_url)
    from sentinel.store import SQLiteInvestigationStore

    return SQLiteInvestigationStore()
