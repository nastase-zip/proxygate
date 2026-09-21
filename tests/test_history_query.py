"""
History window queries (db.get_history_page).

The QUIC exclusion here is what makes the client's row limit mean "rows you
will actually see". Blocked-QUIC attempts dominated a real session (196 of
200 rows), so without it the capped window arrived nearly empty after the
client dropped them.
"""
import sqlite3

import pytest

from backend import db as db_mod


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "traffic.db"
    monkeypatch.setattr(db_mod, "DB_PATH", str(path))
    from backend import rules as _rules
    monkeypatch.setattr(_rules, "_restore_owner", lambda *a, **k: None)
    db_mod.init_db()
    return path


def insert(db, protocol="TLS", host="example.com", src="192.168.100.5"):
    conn = sqlite3.connect(str(db))
    with conn:
        conn.execute(
            """INSERT INTO connections
               (timestamp, source_ip, dest_host, dest_port, method, status_code,
                bytes_transferred, rule_matched, proxy_used, protocol)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            ("2026-09-21 09:00:00", src, host, 443, None, None, 0,
             "default", "DIRECT", protocol),
        )
    conn.close()


def test_quic_rows_included_by_default(db):
    insert(db, protocol="QUIC (blocked)")
    insert(db, protocol="TLS")
    assert len(db_mod.get_history_page(0, limit=50)) == 2


def test_quic_rows_excluded_when_asked(db):
    insert(db, protocol="QUIC (blocked)")
    insert(db, protocol="TLS")
    rows = db_mod.get_history_page(0, limit=50, include_quic=False)
    assert [r["protocol"] for r in rows] == ["TLS"]


def test_limit_counts_visible_rows_when_quic_excluded(db):
    """
    The point of the flag: a limit of 5 should return 5 *renderable* rows,
    not 5 rows that are mostly discarded client-side.
    """
    for _ in range(50):
        insert(db, protocol="QUIC (blocked)")
    for i in range(10):
        insert(db, protocol="TLS", host=f"h{i}.com")

    rows = db_mod.get_history_page(0, limit=5, include_quic=False)
    assert len(rows) == 5
    assert all(r["protocol"] != "QUIC (blocked)" for r in rows)


def test_null_protocol_rows_are_not_dropped(db):
    """
    Rows written before the `protocol` column existed have NULL there.
    "protocol != ?" would never be true for them in SQL, silently hiding
    them; the query uses IS NOT for exactly this reason.
    """
    insert(db, protocol=None)
    insert(db, protocol="QUIC (blocked)")
    rows = db_mod.get_history_page(0, limit=50, include_quic=False)
    assert len(rows) == 1
    assert rows[0]["protocol"] is None


def test_session_floor_still_applies(db):
    insert(db, protocol="TLS")
    insert(db, protocol="TLS")
    all_rows = db_mod.get_history_page(0, limit=50)
    floor = all_rows[-1]["id"]
    assert len(db_mod.get_history_page(floor, limit=50)) == 1


def test_rows_come_back_newest_first(db):
    for i in range(3):
        insert(db, host=f"h{i}.com")
    hosts = [r["dest_host"] for r in db_mod.get_history_page(0, limit=50)]
    assert hosts == ["h2.com", "h1.com", "h0.com"]


def test_filter_and_quic_exclusion_combine(db):
    insert(db, protocol="QUIC (blocked)", host="google.com")
    insert(db, protocol="TLS", host="google.com")
    insert(db, protocol="TLS", host="example.com")
    rows = db_mod.get_history_page(0, limit=50, filter_text="google",
                                   include_quic=False)
    assert len(rows) == 1
    assert rows[0]["dest_host"] == "google.com"
