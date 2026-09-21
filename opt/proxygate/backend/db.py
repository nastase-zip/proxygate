"""
backend/db.py — SQLite read helpers for the ProxyGate GUI.

The schema is created by mitm_logger.py (the mitmproxy addon).
This module is read-only from the GUI's perspective; all writes
come from the addon running inside mitmproxy.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Optional

# Self-contained under this checkout by default — see services.py's
# PROJECT_ROOT comment.
_HERE        = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))

DB_PATH = os.getenv("PROXYGATE_DB", os.path.join(_PROJECT_ROOT, "var/lib/proxygate/traffic.db"))


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist (safe to call on startup)."""
    from backend.rules import _restore_owner
    db_existed = os.path.exists(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    _restore_owner(os.path.dirname(DB_PATH), is_dir=True)
    conn = _conn()
    with conn:
        # MUST stay in sync with mitm_logger._init_db(): whichever process
        # starts first creates the DB. This one previously omitted `protocol`
        # and `flow_details` entirely, so if the web UI won that race on a
        # fresh install, every query here referenced a column that didn't
        # exist — and the resulting OperationalError is swallowed, showing an
        # empty traffic table rather than an error.
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp         TEXT    NOT NULL,
                source_ip         TEXT,
                dest_host         TEXT,
                dest_port         INTEGER,
                method            TEXT,
                status_code       INTEGER,
                bytes_transferred INTEGER,
                rule_matched      TEXT,
                proxy_used        TEXT,
                protocol          TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_connections_ts
                ON connections(timestamp);

            CREATE TABLE IF NOT EXISTS dns_cache (
                ip        TEXT PRIMARY KEY,
                hostname  TEXT NOT NULL,
                seen_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS flow_details (
                connection_id     INTEGER PRIMARY KEY REFERENCES connections(id),
                request_headers   TEXT,
                request_body      BLOB,
                request_truncated INTEGER NOT NULL DEFAULT 0,
                response_headers  TEXT,
                response_body     BLOB,
                response_truncated INTEGER NOT NULL DEFAULT 0
            );
        """)
        # Older DBs created before `protocol` existed — add it in place so
        # upgrading doesn't require deleting traffic.db. Mirrors the same
        # migration in mitm_logger._init_db().
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(connections)")]
        if "protocol" not in cols:
            conn.execute("ALTER TABLE connections ADD COLUMN protocol TEXT")
    conn.close()
    if not db_existed:
        _restore_owner(DB_PATH)


def get_connections_since(last_id: int, limit: int = 200) -> list[dict]:
    """
    Return up to `limit` new connection rows with id > last_id, oldest first.
    Thread-safe: opens a fresh connection each call.
    """
    try:
        conn = _conn()
        rows = conn.execute(
            """SELECT id, timestamp, source_ip, dest_host, dest_port,
                      method, status_code, bytes_transferred,
                      rule_matched, proxy_used, protocol
               FROM connections
               WHERE id > ?
               ORDER BY id ASC
               LIMIT ?""",
            (last_id, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def get_connection_stats() -> dict:
    """Return total connection count and total bytes transferred."""
    try:
        conn = _conn()
        row = conn.execute(
            """SELECT COUNT(*) as total_count,
                      COALESCE(SUM(bytes_transferred), 0) as total_bytes
               FROM connections"""
        ).fetchone()
        conn.close()
        return {"total_count": row["total_count"], "total_bytes": row["total_bytes"]}
    except sqlite3.OperationalError:
        return {"total_count": 0, "total_bytes": 0}


def get_connections_filtered(
    filter_text: str = "",
    limit: int = 500,
) -> list[dict]:
    """Return the most recent `limit` connections matching filter_text."""
    try:
        conn = _conn()
        if filter_text:
            pat = f"%{filter_text}%"
            rows = conn.execute(
                """SELECT id, timestamp, source_ip, dest_host, dest_port,
                          method, status_code, bytes_transferred,
                          rule_matched, proxy_used, protocol
                   FROM connections
                   WHERE dest_host LIKE ? OR source_ip LIKE ?
                   ORDER BY id DESC
                   LIMIT ?""",
                (pat, pat, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, timestamp, source_ip, dest_host, dest_port,
                          method, status_code, bytes_transferred,
                          rule_matched, proxy_used, protocol
                   FROM connections
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        conn.close()
        # Return chronological order
        return list(reversed([dict(r) for r in rows]))
    except sqlite3.OperationalError:
        return []


def get_max_id() -> int:
    """Return the highest connection id currently in the DB."""
    try:
        conn = _conn()
        row = conn.execute("SELECT MAX(id) as m FROM connections").fetchone()
        conn.close()
        return row["m"] or 0
    except sqlite3.OperationalError:
        return 0


# The protocol value mitm_logger writes for a QUIC attempt the gateway
# blocked. Must match _classify_protocol() in mitm_logger.py and the string
# the frontend checks in shouldRenderRow().
QUIC_BLOCKED_PROTOCOL = "QUIC (blocked)"


def get_history_page(
    session_floor_id: int,
    before_id: Optional[int] = None,
    limit: int = 50,
    filter_text: str = "",
    include_quic: bool = True,
) -> list[dict]:
    """
    Return up to `limit` rows from the current session (id > session_floor_id),
    strictly older than `before_id` (or the newest page if before_id is None),
    newest first. Used for backward/scroll-up pagination in the traffic panel —
    each call is one "chunk" so the browser never holds the full table in memory.

    include_quic=False drops blocked-QUIC rows in SQL. The client hides them
    anyway when its "show blocked QUIC" preference is off, but filtering them
    out here is what makes `limit` mean "rows you will actually see": QUIC
    attempts can be the overwhelming majority of a session, so a 200-row
    window could otherwise arrive with only a handful of renderable rows in it.
    """
    try:
        conn = _conn()
        clauses = ["id > ?"]
        params: list = [session_floor_id]
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        if filter_text:
            clauses.append("(dest_host LIKE ? OR source_ip LIKE ?)")
            pat = f"%{filter_text}%"
            params.extend([pat, pat])
        if not include_quic:
            # IS NOT rather than != so rows with a NULL protocol (written
            # before the column existed) are kept: "!= NULL" is never true
            # in SQL and would silently drop them.
            clauses.append("protocol IS NOT ?")
            params.append(QUIC_BLOCKED_PROTOCOL)
        where = " AND ".join(clauses)
        params.append(limit)
        rows = conn.execute(
            f"""SELECT id, timestamp, source_ip, dest_host, dest_port,
                       method, status_code, bytes_transferred,
                       rule_matched, proxy_used, protocol
                FROM connections
                WHERE {where}
                ORDER BY id DESC
                LIMIT ?""",
            params,
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def get_session_stats(session_floor_id: int, filter_text: str = "") -> dict:
    """Connection count and byte total for the current session only, optionally filtered."""
    try:
        conn = _conn()
        clauses = ["id > ?"]
        params: list = [session_floor_id]
        if filter_text:
            clauses.append("(dest_host LIKE ? OR source_ip LIKE ?)")
            pat = f"%{filter_text}%"
            params.extend([pat, pat])
        where = " AND ".join(clauses)
        row = conn.execute(
            f"""SELECT COUNT(*) as total_count,
                       COALESCE(SUM(bytes_transferred), 0) as total_bytes
                FROM connections
                WHERE {where}""",
            params,
        ).fetchone()
        conn.close()
        return {"total_count": row["total_count"], "total_bytes": row["total_bytes"]}
    except sqlite3.OperationalError:
        return {"total_count": 0, "total_bytes": 0}


def resolve_host_from_cache(ip: str) -> Optional[str]:
    """Look up a hostname from the DNS cache table."""
    try:
        conn = _conn()
        row = conn.execute(
            "SELECT hostname FROM dns_cache WHERE ip = ?", (ip,)
        ).fetchone()
        conn.close()
        return row["hostname"] if row else None
    except sqlite3.OperationalError:
        return None


def get_flow_details(connection_id: int) -> Optional[dict]:
    """
    Full request/response capture for one connection (Charles/Burp-style
    detail view) — headers as newline-joined "Name: value" text, bodies as
    raw bytes (decoded to str by the caller once it knows/guesses the
    encoding; this layer stays encoding-agnostic). None if this connection
    was never decrypted (raw-TLS passthrough never reaches the hooks that
    populate flow_details) or the id doesn't exist.
    """
    try:
        conn = _conn()
        row = conn.execute(
            """SELECT connection_id, request_headers, request_body, request_truncated,
                      response_headers, response_body, response_truncated
               FROM flow_details
               WHERE connection_id = ?""",
            (connection_id,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except sqlite3.OperationalError:
        return None
