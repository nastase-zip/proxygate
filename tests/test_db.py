"""
Traffic database queries (backend/db.py).

The traffic table's filter box feeds straight into these, so SQL-injection
safety and graceful degradation on a missing/locked DB both matter.
"""
import sqlite3

import pytest

from backend import db as db_mod


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "traffic.db"
    monkeypatch.setattr(db_mod, "DB_PATH", str(path))
    # init_db chowns to SUDO_UID/GID; irrelevant (and a no-op) under a normal
    # user, but patched at its source so the import inside init_db picks it up.
    from backend import rules as _rules
    monkeypatch.setattr(_rules, "_restore_owner", lambda *a, **k: None)
    db_mod.init_db()
    return path


def insert(db, **over):
    row = {
        "timestamp": "2026-09-21 09:00:00", "source_ip": "192.168.100.5",
        "dest_host": "example.com", "dest_port": 443, "method": "GET",
        "status_code": 200, "bytes_transferred": 100,
        "rule_matched": "default", "proxy_used": "DIRECT", "protocol": "TCP",
    }
    row.update(over)
    conn = sqlite3.connect(str(db))
    with conn:
        conn.execute(
            """INSERT INTO connections
               (timestamp, source_ip, dest_host, dest_port, method, status_code,
                bytes_transferred, rule_matched, proxy_used, protocol)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            tuple(row[k] for k in (
                "timestamp", "source_ip", "dest_host", "dest_port", "method",
                "status_code", "bytes_transferred", "rule_matched",
                "proxy_used", "protocol")),
        )
    conn.close()


# ── schema ────────────────────────────────────────────────────────────────────

def test_init_db_is_idempotent(db):
    db_mod.init_db()
    db_mod.init_db()
    assert db_mod.get_max_id() == 0


def test_empty_db_queries_are_safe(db):
    assert db_mod.get_connections_filtered() == []
    assert db_mod.get_max_id() == 0
    assert db_mod.get_connections_since(0) == []
    assert db_mod.get_flow_details(1) is None


# ── filtering ─────────────────────────────────────────────────────────────────

def test_filter_matches_host_and_source(db):
    insert(db, dest_host="google.com")
    insert(db, dest_host="example.com", source_ip="192.168.100.9")

    assert len(db_mod.get_connections_filtered("google")) == 1
    assert len(db_mod.get_connections_filtered("192.168.100.9")) == 1
    assert len(db_mod.get_connections_filtered("")) == 2


@pytest.mark.parametrize("payload", [
    "'; DROP TABLE connections; --",
    "' OR '1'='1",
    '" OR 1=1 --',
    "%",            # a bare LIKE wildcard must not be treated as SQL
    "_",
])
def test_filter_is_injection_safe(db, payload):
    insert(db, dest_host="example.com")
    # Must not raise, and must not destroy the table.
    db_mod.get_connections_filtered(payload)
    assert db_mod.get_max_id() == 1, "table should survive the filter"


def test_results_are_chronological(db):
    for i in range(3):
        insert(db, dest_host=f"h{i}.com")
    hosts = [r["dest_host"] for r in db_mod.get_connections_filtered()]
    assert hosts == ["h0.com", "h1.com", "h2.com"]


def test_limit_returns_most_recent(db):
    for i in range(10):
        insert(db, dest_host=f"h{i}.com")
    rows = db_mod.get_connections_filtered(limit=3)
    assert [r["dest_host"] for r in rows] == ["h7.com", "h8.com", "h9.com"]


# ── incremental polling ───────────────────────────────────────────────────────

def test_get_connections_since_is_exclusive(db):
    for i in range(3):
        insert(db, dest_host=f"h{i}.com")
    assert len(db_mod.get_connections_since(0)) == 3
    assert len(db_mod.get_connections_since(1)) == 2
    assert len(db_mod.get_connections_since(3)) == 0


def test_stats_on_empty_db(db):
    stats = db_mod.get_connection_stats()
    assert stats["total_count"] == 0
    assert stats["total_bytes"] == 0


def test_stats_count_and_bytes(db):
    insert(db, bytes_transferred=100)
    insert(db, bytes_transferred=250)
    stats = db_mod.get_connection_stats()
    assert stats["total_count"] == 2
    assert stats["total_bytes"] == 350


# ── resilience ────────────────────────────────────────────────────────────────

def test_missing_db_degrades_gracefully(tmp_path, monkeypatch):
    """The UI polls before mitmproxy has ever created the DB."""
    monkeypatch.setattr(db_mod, "DB_PATH", str(tmp_path / "nonexistent.db"))
    assert db_mod.get_connections_filtered() == []
    assert db_mod.get_max_id() == 0
    assert db_mod.get_connection_stats()["total_count"] == 0
