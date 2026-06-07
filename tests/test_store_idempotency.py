import pytest

from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.postgres_store import PostgresInvestigationStore, build_store
from sentinel.store import SQLiteInvestigationStore


def test_sqlite_store_can_lookup_idempotency_key_owner(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")

    inserted = store.remember_idempotency_key("PD-1:webhook", "webhook", "inv-1")
    duplicate = store.remember_idempotency_key("PD-1:webhook", "webhook", "inv-2")

    assert inserted is True
    assert duplicate is False
    assert store.lookup_idempotency_key("PD-1:webhook") == "inv-1"
    assert store.lookup_idempotency_key("missing") is None


def test_build_store_accepts_sqlite_database_url(tmp_path):
    db_path = tmp_path / "nested" / "sentinel.db"
    store = build_store(f"sqlite:///{db_path}")

    assert isinstance(store, SQLiteInvestigationStore)
    assert db_path.exists()
    assert store.ping() is True


def test_sqlite_store_rejects_empty_oauth_token_before_persistence(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")

    with pytest.raises(ToolExecutionError) as exc:
        store.save_oauth_token(provider="slack", access_token=" ")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "access_token" in str(exc.value)
    assert store.load_oauth_token("slack") is None


def test_sqlite_store_rejects_malformed_oauth_scopes_before_persistence(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")

    with pytest.raises(ToolExecutionError) as exc:
        store.save_oauth_token(provider="github", access_token="gh-oauth", scopes=["repo", 42])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "scopes" in str(exc.value)
    assert store.load_oauth_token("github") is None


def test_sqlite_store_trims_oauth_provider_and_token(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")

    store.save_oauth_token(provider=" github ", access_token=" gh-oauth ", scopes=["repo"], metadata={"source": "test"})

    token = store.load_oauth_token("github")
    assert token["provider"] == "github"
    assert token["access_token"] == "gh-oauth"
    assert token["scopes"] == ["repo"]
    assert token["metadata"] == {"source": "test"}


def test_postgres_store_treats_unique_violation_as_duplicate_idempotency_key():
    store = object.__new__(PostgresInvestigationStore)
    store.psycopg = _StubPsycopg
    store._conn = _FailingConnection(_StubUniqueViolation("duplicate key"))
    store._lock = _RecordingLock()

    result = store.remember_idempotency_key("PD-1:webhook", "webhook", "inv-1")

    assert result is False
    assert store._conn.rollbacks == 1
    assert store._conn.commits == 0
    assert store._lock.events == ["enter", "exit"]


def test_postgres_store_reraises_non_duplicate_idempotency_failures():
    store = object.__new__(PostgresInvestigationStore)
    store.psycopg = _StubPsycopg
    store._conn = _FailingConnection(RuntimeError("database is unavailable"))
    store._lock = _RecordingLock()

    with pytest.raises(RuntimeError, match="database is unavailable"):
        store.remember_idempotency_key("PD-1:webhook", "webhook", "inv-1")

    assert store._conn.rollbacks == 1
    assert store._conn.commits == 0
    assert store._lock.events == ["enter", "exit"]


def test_postgres_store_serializes_successful_idempotency_insert_with_lock():
    store = object.__new__(PostgresInvestigationStore)
    store.psycopg = _StubPsycopg
    store._conn = _SuccessfulConnection()
    store._lock = _RecordingLock()

    result = store.remember_idempotency_key("PD-1:webhook", "webhook", "inv-1")

    assert result is True
    assert store._conn.executes == 1
    assert store._conn.commits == 1
    assert store._conn.rollbacks == 0
    assert store._lock.events == ["enter", "exit"]


def test_postgres_store_rejects_empty_oauth_token_before_query():
    store = object.__new__(PostgresInvestigationStore)
    store.Jsonb = lambda value: value
    store._conn = _SuccessfulConnection()
    store._lock = _RecordingLock()

    with pytest.raises(ToolExecutionError) as exc:
        store.save_oauth_token(provider="slack", access_token="")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "access_token" in str(exc.value)
    assert store._conn.executes == 0
    assert store._conn.commits == 0
    assert store._lock.events == []


def test_postgres_store_rejects_malformed_oauth_metadata_before_query():
    store = object.__new__(PostgresInvestigationStore)
    store.Jsonb = lambda value: value
    store._conn = _SuccessfulConnection()
    store._lock = _RecordingLock()

    with pytest.raises(ToolExecutionError) as exc:
        store.save_oauth_token(provider="github", access_token="gh-oauth", metadata=["not", "object"])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "metadata" in str(exc.value)
    assert store._conn.executes == 0
    assert store._conn.commits == 0
    assert store._lock.events == []


class _StubUniqueViolation(Exception):
    pass


class _StubErrors:
    UniqueViolation = _StubUniqueViolation


class _StubPsycopg:
    errors = _StubErrors


class _FailingConnection:
    def __init__(self, exc):
        self.exc = exc
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, *args, **kwargs):
        raise self.exc

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _SuccessfulConnection:
    def __init__(self):
        self.executes = 0
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, *args, **kwargs):
        self.executes += 1

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _RecordingLock:
    def __init__(self):
        self.events = []

    def __enter__(self):
        self.events.append("enter")
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.events.append("exit")
        return False
