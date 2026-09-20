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

DB_PATH = os.getenv("PROXYGATE_DB", "/var/lib/proxygate/traffic.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist (safe to call on startup)."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = _conn()
    with conn:
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
                proxy_used        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_connections_ts
                ON connections(timestamp);

            CREATE TABLE IF NOT EXISTS dns_cache (
                ip        TEXT PRIMARY KEY,
                hostname  TEXT NOT NULL,
                seen_at   TEXT NOT NULL
            );
        """)
    conn.close()


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


def get_history_page(
    session_floor_id: int,
    before_id: Optional[int] = None,
    limit: int = 50,
    filter_text: str = "",
) -> list[dict]:
    """
    Return up to `limit` rows from the current session (id > session_floor_id),
    strictly older than `before_id` (or the newest page if before_id is None),
    newest first. Used for backward/scroll-up pagination in the traffic panel —
    each call is one "chunk" so the browser never holds the full table in memory.
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
