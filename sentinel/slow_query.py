from __future__ import annotations

import json
import os
import random
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


SLOW_QUERY_SQL = "SELECT * FROM orders WHERE user_id = ?"
INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)"
DEFAULT_ROW_COUNT = 120_000
TARGET_USER_ID = 424242

_LOCK = threading.RLock()
_STATS: dict[str, float | int] = {
    "requests_total": 0,
    "errors_total": 0,
    "duration_sum_seconds": 0.0,
    "duration_count": 0,
    "last_duration_seconds": 0.0,
    "max_duration_seconds": 0.0,
    "index_created_total": 0,
}


@dataclass(frozen=True)
class SlowQueryResult:
    user_id: int
    matched_rows: int
    duration_seconds: float
    index_present: bool
    query_plan: str
    row_count: int
    scan_repeats: int


def db_path() -> Path:
    return Path(os.getenv("SENTINEL_SLOW_QUERY_DB_PATH", "/tmp/sentinel_slow_query.db"))


def reset_slow_query_database(row_count: int = DEFAULT_ROW_COUNT) -> dict[str, Any]:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        if path.exists():
            path.unlink()
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, payload TEXT NOT NULL)"
            )
            batch = []
            rng = random.Random(847)
            for order_id in range(1, row_count + 1):
                user_id = TARGET_USER_ID if order_id == row_count else rng.randint(1, row_count * 10)
                batch.append((order_id, user_id, f"order-payload-{order_id:06d}"))
                if len(batch) >= 1000:
                    conn.executemany(
                        "INSERT INTO orders(id, user_id, payload) VALUES (?, ?, ?)",
                        batch,
                    )
                    batch.clear()
            if batch:
                conn.executemany(
                    "INSERT INTO orders(id, user_id, payload) VALUES (?, ?, ?)",
                    batch,
                )
            conn.commit()
        _reset_stats_locked()
    return {
        "status": "reset",
        "db_path": str(path),
        "row_count": row_count,
        "index_present": False,
        "target_user_id": TARGET_USER_ID,
        "query": SLOW_QUERY_SQL,
    }


def run_slow_query(user_id: int = TARGET_USER_ID) -> SlowQueryResult:
    ensure_slow_query_database()
    started = time.perf_counter()
    with sqlite3.connect(db_path()) as conn:
        plan = _query_plan(conn, user_id)
        index_present = _index_present(conn)
        repeats = 1 if index_present else _scan_repeats()
        rows = []
        for _ in range(repeats):
            rows = conn.execute(SLOW_QUERY_SQL, (user_id,)).fetchall()
        row_count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    duration = time.perf_counter() - started
    result = SlowQueryResult(
        user_id=user_id,
        matched_rows=len(rows),
        duration_seconds=duration,
        index_present=index_present,
        query_plan=plan,
        row_count=int(row_count),
        scan_repeats=repeats,
    )
    record_slow_query_result(result)
    push_slow_query_log(result)
    return result


def create_orders_user_id_index() -> dict[str, Any]:
    ensure_slow_query_database()
    started = time.perf_counter()
    with _LOCK, sqlite3.connect(db_path()) as conn:
        before = _index_present(conn)
        conn.execute(INDEX_SQL)
        conn.commit()
        after = _index_present(conn)
    duration = time.perf_counter() - started
    with _LOCK:
        _STATS["index_created_total"] = int(_STATS["index_created_total"]) + 1
    event = {
        "event": "sqlite_index_created",
        "service": service_name(),
        "db_path": str(db_path()),
        "index": "idx_orders_user_id",
        "table": "orders",
        "column": "user_id",
        "before_index_present": before,
        "after_index_present": after,
        "duration_ms": round(duration * 1000, 3),
        "message": "created real SQLite index idx_orders_user_id on orders(user_id)",
    }
    push_loki_event(event)
    print(json.dumps(event), flush=True)
    return {**event, "status": "executed", "verified": after}


def ensure_slow_query_database() -> None:
    path = db_path()
    if path.exists():
        return
    reset_slow_query_database()


def slow_query_status() -> dict[str, Any]:
    ensure_slow_query_database()
    with sqlite3.connect(db_path()) as conn:
        row_count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        index_present = _index_present(conn)
        plan = _query_plan(conn, TARGET_USER_ID)
    with _LOCK:
        stats = dict(_STATS)
    return {
        "db_path": str(db_path()),
        "row_count": int(row_count),
        "index_present": index_present,
        "target_user_id": TARGET_USER_ID,
        "query": SLOW_QUERY_SQL,
        "query_plan": plan,
        "stats": stats,
    }


def slow_query_metrics(service: str | None = None) -> str:
    service = _prom_label(service or service_name())
    with _LOCK:
        stats = dict(_STATS)
    index_present = 1 if slow_query_status()["index_present"] else 0
    return "\n".join(
        [
            "# HELP sentinel_slow_query_last_duration_seconds Last /slow-query SQLite query duration.",
            "# TYPE sentinel_slow_query_last_duration_seconds gauge",
            f"sentinel_slow_query_last_duration_seconds{{service={service}}} {float(stats['last_duration_seconds']):.6f}",
            "# HELP sentinel_slow_query_max_duration_seconds Max /slow-query SQLite query duration in this process.",
            "# TYPE sentinel_slow_query_max_duration_seconds gauge",
            f"sentinel_slow_query_max_duration_seconds{{service={service}}} {float(stats['max_duration_seconds']):.6f}",
            "# HELP sentinel_slow_query_missing_index Whether orders.user_id is missing its index.",
            "# TYPE sentinel_slow_query_missing_index gauge",
            f"sentinel_slow_query_missing_index{{service={service}}} {0 if index_present else 1}",
            "# HELP sentinel_slow_query_index_created_total Number of index creation remediations.",
            "# TYPE sentinel_slow_query_index_created_total counter",
            f"sentinel_slow_query_index_created_total{{service={service}}} {int(stats['index_created_total'])}",
            "# HELP http_requests_total Real HTTP requests by status.",
            "# TYPE http_requests_total counter",
            f"http_requests_total{{service={service},path=\"/slow-query\",status=\"200\"}} {int(stats['requests_total'])}",
            f"http_requests_total{{service={service},path=\"/slow-query\",status=\"500\"}} {int(stats['errors_total'])}",
            "# HELP http_request_duration_seconds Real HTTP request duration summary.",
            "# TYPE http_request_duration_seconds summary",
            f"http_request_duration_seconds_sum{{service={service},path=\"/slow-query\"}} {float(stats['duration_sum_seconds']):.6f}",
            f"http_request_duration_seconds_count{{service={service},path=\"/slow-query\"}} {int(stats['duration_count'])}",
            "",
        ]
    )


def record_slow_query_result(result: SlowQueryResult) -> None:
    with _LOCK:
        _STATS["requests_total"] = int(_STATS["requests_total"]) + 1
        _STATS["duration_count"] = int(_STATS["duration_count"]) + 1
        _STATS["duration_sum_seconds"] = float(_STATS["duration_sum_seconds"]) + result.duration_seconds
        _STATS["last_duration_seconds"] = result.duration_seconds
        _STATS["max_duration_seconds"] = max(
            float(_STATS["max_duration_seconds"]),
            result.duration_seconds,
        )


def push_slow_query_log(result: SlowQueryResult) -> None:
    event = {
        "event": "slow_query",
        "service": service_name(),
        "db_system": "sqlite",
        "db_table": "orders",
        "db_column": "user_id",
        "db_statement": SLOW_QUERY_SQL,
        "duration_ms": round(result.duration_seconds * 1000, 3),
        "matched_rows": result.matched_rows,
        "row_count": result.row_count,
        "scan_repeats": result.scan_repeats,
        "index_present": result.index_present,
        "missing_index": not result.index_present,
        "query_plan": result.query_plan,
        "root_cause_candidate": "missing_index_orders_user_id" if not result.index_present else "index_present",
        "message": (
            "slow SQLite query SELECT * FROM orders WHERE user_id = ? used sequential scan; "
            "missing index orders.user_id"
            if not result.index_present
            else "SQLite query SELECT * FROM orders WHERE user_id = ? used idx_orders_user_id"
        ),
    }
    print(json.dumps(event), flush=True)
    push_loki_event(event)


def push_loki_event(event: dict[str, Any]) -> None:
    loki_url = os.getenv("LOKI_URL")
    if not loki_url or os.getenv("SENTINEL_PUSH_SLOW_QUERY_LOGS_TO_LOKI", "true").lower() in {"0", "false", "no"}:
        return
    stream = {
        "streams": [
            {
                "stream": {
                    "service": service_name(),
                    "app": "sentinel",
                    "source": "sentinel-slow-query",
                    "level": "info",
                },
                "values": [[str(time.time_ns()), json.dumps(event, sort_keys=True)]],
            }
        ]
    }
    try:
        httpx.post(loki_url.rstrip("/") + "/loki/api/v1/push", json=stream, timeout=2.0)
    except Exception:
        return


def service_name() -> str:
    return os.getenv("SENTINEL_DEFAULT_SERVICE", "payment-service")


def _query_plan(conn: sqlite3.Connection, user_id: int) -> str:
    rows = conn.execute(f"EXPLAIN QUERY PLAN {SLOW_QUERY_SQL}", (user_id,)).fetchall()
    return " | ".join(str(row[-1]) for row in rows)


def _index_present(conn: sqlite3.Connection) -> bool:
    rows = conn.execute("PRAGMA index_list('orders')").fetchall()
    return any(str(row[1]) == "idx_orders_user_id" for row in rows)


def _reset_stats_locked() -> None:
    _STATS.update(
        {
            "requests_total": 0,
            "errors_total": 0,
            "duration_sum_seconds": 0.0,
            "duration_count": 0,
            "last_duration_seconds": 0.0,
            "max_duration_seconds": 0.0,
            "index_created_total": 0,
        }
    )


def _prom_label(value: str) -> str:
    return json.dumps(str(value))


def _scan_repeats() -> int:
    raw = os.getenv("SENTINEL_SLOW_QUERY_SCAN_REPEATS", "12")
    try:
        value = int(raw)
    except ValueError:
        return 12
    return max(1, min(value, 100))
