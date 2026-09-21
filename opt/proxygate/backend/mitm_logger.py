"""
ProxyGate mitmproxy addon — mitm_logger.py

Responsibilities:
  1. Log every connection to SQLite (traffic.db)
  2. Build a DNS cache by tailing the dnsmasq log
  3. Resolve raw IPs to hostnames
  4. Kill HTTP flows whose matched rule is BLOCK
  5. Route ALL outbound connections through the correct upstream proxy per rule.

Upstream proxy routing strategy
---------------------------------
mitmproxy's server.py opens ALL outbound TCP via:
    asyncio.open_connection(host, port, ...)
(module attribute lookup — patching asyncio.open_connection intercepts this)

Per-connection proxy selection uses a dict keyed by (host, port).
The tls_clienthello / request hook fires before open_connection is called
for that destination, so:

  1. Hook fires → matches rule for this destination → stores proxy in _dest_proxy[(host, port)]
  2. mitmproxy calls asyncio.open_connection(host, port)
  3. Our patch looks up _dest_proxy[(host, port)] → gets the right proxy
  4. Entry removed after use (pop)

Fallback: if no entry exists (race or non-hook path), use _default_proxy.

DIRECT → call original asyncio.open_connection unmodified.
BLOCK  → hook kills the flow before open_connection is ever called.
proxy  → hand-rolled SOCKS5/SOCKS4/HTTP-CONNECT blocking handshake in a
         thread executor (see "Upstream proxy protocol clients" below), hand
         the connected socket back to asyncio.  Does not call
         setblocking(False) — asyncio does that itself when it takes
         ownership of the socket.  Supports IPv4 and IPv6 destinations for
         SOCKS5 and HTTP; SOCKS4 is IPv4-only (a limitation of that
         protocol's wire format, not this implementation).
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import contextvars
import fnmatch
import ipaddress
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import traceback
from datetime import datetime
from typing import Optional

import logging
import yaml
from mitmproxy import ctx, http

# mitmdump loads this file directly (`-s mitm_logger.py`), as its own script —
# NOT as the `backend.mitm_logger` package main.py imports it as. That means
# `backend`'s parent dir is never automatically on sys.path here, so `from
# backend.services import resolve_mac` (used below for the decrypt-devices
# MAC lookup) would silently fail every single call and MAC resolution would
# always return None — decryption would never actually engage for any
# flagged device, with no error anywhere (the import is wrapped in a bare
# `except Exception` specifically so a resolution hiccup fails closed to
# passthrough, which also means an import failure looks identical to "MAC
# just couldn't be resolved this time" unless sys.path is fixed here first).
_APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _APP_ROOT not in sys.path:
    sys.path.insert(0, _APP_ROOT)

# Imported after the sys.path fix above, for the reason documented there.
# Shared with web.py so rule validation and rule matching agree exactly.
from backend.patterns import matches_any  # noqa: E402

_log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
# Self-contained under this checkout by default — see services.py's
# PROJECT_ROOT comment.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_APP_ROOT))

DB_PATH      = os.getenv("PROXYGATE_DB",      os.path.join(_PROJECT_ROOT, "var/lib/proxygate/traffic.db"))
RULES_PATH   = os.getenv("PROXYGATE_RULES",   os.path.join(_PROJECT_ROOT, "etc/proxygate/rules.yaml"))
DEVICES_PATH = os.getenv("PROXYGATE_DEVICES", os.path.join(_PROJECT_ROOT, "etc/proxygate/devices.yaml"))
CONFIG_PATH  = os.getenv("PROXYGATE_CONFIG",  os.path.join(_PROJECT_ROOT, "etc/proxygate/config.yaml"))
DNSMASQ_LOG  = os.getenv("DNSMASQ_LOG",       os.path.join(_PROJECT_ROOT, "var/log/proxygate/dnsmasq.log"))
# Where apply_iptables()'s "PGQUIC: " LOG rule (services.py) actually lands —
# rsyslog routes kernel LOG target output here on this distro. journalctl -k
# would be the more portable way to read it, but tailing a plain file matches
# the existing DnsLogTailer pattern and needs no subprocess.
KERN_LOG     = os.getenv("KERN_LOG",          "/var/log/kern.log")

_DNS_REPLY_RE = re.compile(r"\breply\s+(\S+)\s+is\s+(\d{1,3}(?:\.\d{1,3}){3})\b")
_QUIC_LOG_RE  = re.compile(r"PGQUIC:.*\bSRC=(\S+).*\bDST=(\S+).*\bDPT=(\d+)")


# ── Database helpers ──────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    from backend.rules import _restore_owner
    db_existed = os.path.exists(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    _restore_owner(os.path.dirname(DB_PATH), is_dir=True)
    conn = _get_conn()
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

            -- Full request/response capture for decrypted HTTPS flows (and
            -- plain HTTP, which was already fully visible). One row per
            -- connection that actually got decrypted — most rows in
            -- `connections` never have one, since most traffic is raw-TLS
            -- passthrough with no visibility into headers/body at all.
            -- Bodies are capped (see _MAX_BODY_CAPTURE) so a large download/
            -- video stream can't balloon the DB — this is a debugging/
            -- inspection capture, not a full proxy replay archive.
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
        # Older DBs created before `protocol` existed — add it if missing so
        # upgrading in place doesn't require deleting traffic.db.
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(connections)")]
        if "protocol" not in cols:
            conn.execute("ALTER TABLE connections ADD COLUMN protocol TEXT")
    conn.close()
    if not db_existed:
        _restore_owner(DB_PATH)


# ── Own-traffic filter ────────────────────────────────────────────────────────
#
# The gateway machine itself goes through the same proxy as its clients, so
# without this its own requests (the browser running the web UI, package
# managers, background OS chatter) land in the traffic table interleaved with
# the hotspot clients' — indistinguishable to anyone reading the list, and by
# far the noisiest source on the table. Only devices ON the hotspot are of
# interest here, so anything originating from this machine is dropped at the
# single insert chokepoint below.
#
# "This machine" means loopback, or the hotspot's own gateway address (the
# address the AP interface holds, e.g. 192.168.100.1). Client traffic arrives
# from elsewhere in the hotspot subnet, so it's never caught by this.

# A second, related case: mitmproxy binds 0.0.0.0, so any machine that can
# reach this box on the mitm port can use it as a proxy — the iptables
# REDIRECT is correctly scoped to the hotspot NIC, but nothing stops a LAN
# machine from connecting to the port directly. Such a device is not on the
# hotspot and doesn't belong in a table that's meant to answer "what are the
# devices on my hotspot doing", so the filter is expressed positively: keep
# traffic from the hotspot subnet, drop everything else.

_filter_cache: Optional[tuple[set[str], Optional[object]]] = None
_filter_lock = threading.Lock()


def _filter_config() -> tuple[set[str], Optional[object]]:
    """
    (own_ips, hotspot_subnet), cached for the process lifetime — both come
    from config, not from anything that changes underneath a running
    mitmproxy.
    """
    global _filter_cache
    with _filter_lock:
        if _filter_cache is not None:
            return _filter_cache
        ips = {"127.0.0.1", "::1"}
        subnet = None
        try:
            with open(CONFIG_PATH) as f:
                cfg = yaml.safe_load(f) or {}
            gw = (cfg.get("hotspot_gw") or "").strip()
            if gw:
                ips.add(gw)
            sub = (cfg.get("hotspot_subnet") or "").strip()
            if sub:
                subnet = ipaddress.ip_network(sub, strict=False)
        except Exception:
            # Fall back to dropping only our own traffic. Better to log a few
            # extra rows than to silently drop a real client's by guessing at
            # a subnet we couldn't read.
            pass
        _filter_cache = (ips, subnet)
        _log.info(f"[proxygate] traffic filter: own={sorted(ips)} hotspot_subnet={subnet}")
        return _filter_cache


def _is_own_traffic(source_ip: Optional[str]) -> bool:
    """
    True when this row should NOT appear in the traffic table: it came from
    the gateway machine itself, or from something that isn't on the hotspot
    at all (e.g. a LAN machine using the mitm port as a plain proxy).
    """
    if not source_ip or source_ip == "?":
        return False
    ips, subnet = _filter_config()
    raw = source_ip.strip()
    if raw in ips:
        return True
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    # Anything outside the hotspot subnet isn't a hotspot client.
    if subnet is not None and addr.version == subnet.version:
        return addr not in subnet
    return False


def _insert_connection(
    source_ip: str,
    dest_host: str,
    dest_port: int,
    method: Optional[str],
    status_code: Optional[int],
    bytes_xfer: int,
    rule_matched: str,
    proxy_used: str,
    protocol: Optional[str] = None,
) -> Optional[int]:
    """Insert a connections row and return its id (None on failure) — the
    caller needs the id to attach flow_details for a decrypted flow.

    Traffic from the gateway machine itself is dropped here rather than at
    each call site: every logging path (HTTP, TLS passthrough, QUIC-blocked)
    funnels through this one function, so one check covers them all."""
    if _is_own_traffic(source_ip):
        return None
    try:
        conn = _get_conn()
        with conn:
            cur = conn.execute(
                """INSERT INTO connections
                   (timestamp, source_ip, dest_host, dest_port, method,
                    status_code, bytes_transferred, rule_matched, proxy_used, protocol)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    source_ip, dest_host, dest_port, method,
                    status_code, bytes_xfer, rule_matched, proxy_used, protocol,
                ),
            )
            row_id = cur.lastrowid
        conn.close()
        return row_id
    except Exception:
        return None


# Charles/Burp-style capture is a debugging aid, not a full replay archive —
# cap body storage so one large download/video stream can't balloon the DB.
_MAX_BODY_CAPTURE = 1 * 1024 * 1024  # 1 MiB per direction


def _insert_flow_details(
    connection_id: Optional[int],
    request_headers: Optional[str],
    request_body: Optional[bytes],
    response_headers: Optional[str],
    response_body: Optional[bytes],
) -> None:
    if not connection_id:
        return
    try:
        req_truncated = bool(request_body and len(request_body) > _MAX_BODY_CAPTURE)
        resp_truncated = bool(response_body and len(response_body) > _MAX_BODY_CAPTURE)
        req_body = request_body[:_MAX_BODY_CAPTURE] if request_body else None
        resp_body = response_body[:_MAX_BODY_CAPTURE] if response_body else None
        conn = _get_conn()
        with conn:
            conn.execute(
                """INSERT OR REPLACE INTO flow_details
                   (connection_id, request_headers, request_body, request_truncated,
                    response_headers, response_body, response_truncated)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    connection_id, request_headers, req_body, int(req_truncated),
                    response_headers, resp_body, int(resp_truncated),
                ),
            )
        conn.close()
    except Exception:
        pass


# ── Protocol classification (for the traffic table's "Type" column) ──────────
#
# Best-effort label from what's actually observable at each hook — not a deep
# packet inspection feature. QUIC/HTTP3 (UDP/443) never reaches mitmproxy at
# all (see apply_iptables() in services.py: all UDP from the hotspot is
# dropped, there's no UDP proxy path) — that's logged separately, from the
# iptables LOG rule, by QuicLogTailer below, not from here.

def _classify_protocol(dest_port: int, decrypted: bool, is_tls: bool) -> str:
    if is_tls:
        return "HTTPS" if decrypted else "TLS"
    return "HTTP" if dest_port == 80 else "TCP"


def _upsert_dns(ip: str, hostname: str) -> None:
    try:
        conn = _get_conn()
        with conn:
            conn.execute(
                """INSERT OR REPLACE INTO dns_cache (ip, hostname, seen_at)
                   VALUES (?, ?, ?)""",
                (ip, hostname, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
            )
        conn.close()
    except Exception:
        pass


def _lookup_dns_cache(ip: str) -> Optional[str]:
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT hostname FROM dns_cache WHERE ip = ?", (ip,)
        ).fetchone()
        conn.close()
        return row["hostname"] if row else None
    except Exception:
        return None


# ── DNS resolution ────────────────────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_host(host: str) -> str:
    if not _is_ip(host):
        return host
    cached = _lookup_dns_cache(host)
    if cached:
        return cached
    try:
        hostname, _, _ = socket.gethostbyaddr(host)
        _upsert_dns(host, hostname)
        return hostname
    except (socket.herror, socket.gaierror):
        pass
    try:
        import dns.resolver
        import dns.reversename
        rev = dns.reversename.from_address(host)
        answer = dns.resolver.resolve(rev, "PTR", lifetime=2.0)
        hostname = str(answer[0]).rstrip(".")
        _upsert_dns(host, hostname)
        return hostname
    except Exception:
        pass
    return host


# ── Per-connection proxy routing ──────────────────────────────────────────────
#
# _dest_proxy maps (host, port) → proxy_cfg dict (or None for DIRECT).
# Set by tls_clienthello / request hook before open_connection is called.
# Popped by _proxied_open_connection on first use.
#
# _default_proxy is the catch-all used when no entry exists in _dest_proxy
# (e.g. non-HTTP/TLS TCP, or a race where open_connection fires before the hook).
# It is always set to the rules default proxy on every rules reload.

_dest_proxy: dict[tuple[str, int], Optional[dict]] = {}
_dest_proxy_lock = threading.Lock()

_default_proxy: Optional[dict] = None
_default_proxy_lock = threading.Lock()


def _register_proxy(host: str, port: int, proxy_cfg: Optional[dict]) -> None:
    with _dest_proxy_lock:
        _dest_proxy[(host, port)] = proxy_cfg


def _pop_proxy(host: str, port: int) -> Optional[dict]:
    """Return the proxy for (host, port), falling back to _default_proxy."""
    with _dest_proxy_lock:
        # Use pop — each open_connection call consumes the entry.
        # If the same host:port reconnects, the hook will re-register it.
        cfg = _dest_proxy.pop((host, port), _SENTINEL)
    if cfg is _SENTINEL:
        with _default_proxy_lock:
            return _default_proxy
    return cfg


_SENTINEL = object()


def _set_default_proxy(proxy_cfg: Optional[dict]) -> None:
    global _default_proxy
    with _default_proxy_lock:
        _default_proxy = proxy_cfg
    if proxy_cfg:
        msg = (f"[proxygate] default proxy: "
               f"{proxy_cfg.get('type')}://{proxy_cfg.get('host')}:{proxy_cfg.get('port')}")
    else:
        msg = "[proxygate] default proxy: DIRECT"
    _log.warning(msg)
    print(msg, flush=True)


# ── socket.listen() backlog patch ─────────────────────────────────────────────
# mitmproxy calls socket.listen(100) — patch it to always use 4096 so burst
# traffic from the hotspot never overflows the accept queue and causes SYN drops.

_ORIG_SOCKET_LISTEN = socket.socket.listen


def _patched_listen(self, backlog=socket.SOMAXCONN):
    _ORIG_SOCKET_LISTEN(self, 4096)


socket.socket.listen = _patched_listen

# ── Upstream proxy protocol clients (SOCKS5 / SOCKS4 / HTTP CONNECT) ──────────
#
# Hand-rolled instead of using PySocks. PySocks has two problems that showed
# up as real bugs: (1) socksocket.connect() unconditionally rejects any IPv6
# destination literal ("PySocks doesn't support IPv6"), so IPv6 sites never
# worked through ANY proxy type; (2) its HTTP CONNECT negotiator sends
# "Proxy-Authorization: basic" (lowercase scheme) and no Proxy-Connection/
# User-Agent headers, and never retries on a 407 challenge — some HTTP proxy
# servers do case-sensitive scheme matching or expect those headers and
# reject the request outright, which is why "some HTTP proxies work, others
# don't" even with correct credentials.
#
# These implementations support both IPv4 and IPv6 destinations wherever the
# underlying protocol allows it:
#   - SOCKS5:  full support (RFC 1928 address type 0x04 for IPv6).
#   - HTTP CONNECT: full support (RFC 7230 — IPv6 literals just get
#     bracketed in the request line, same as any HTTP client would do).
#   - SOCKS4/SOCKS4a: IPv4 only — this is a limitation of the SOCKS4 wire
#     format itself (a fixed 4-byte address field), not something a client
#     implementation can work around. Use socks5 or http for IPv6 upstreams.

_PROXY_CONNECT_TIMEOUT = 20.0

_proxy_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=64, thread_name_prefix="pg-proxy"
)


class ProxyProtocolError(OSError):
    """Raised for a proxy handshake failure, with enough context to diagnose
    *why* a specific proxy failed instead of a single generic message."""


def _connect_tcp(host: str, port: int, timeout: float) -> socket.socket:
    """Connect a plain TCP socket to (host, port), IPv4 or IPv6, whichever
    getaddrinfo resolves — this is used for the proxy's own address, not the
    final destination (that's sent as protocol data, not the TCP peer)."""
    last_exc: Optional[Exception] = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
        host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
    ):
        s = socket.socket(family, socktype, proto)
        try:
            s.settimeout(timeout)
            s.connect(sockaddr)
            return s
        except OSError as exc:
            s.close()
            last_exc = exc
    raise ProxyProtocolError(f"could not connect to proxy {host}:{port}: {last_exc}")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProxyProtocolError("proxy closed connection unexpectedly")
        buf += chunk
    return buf


def _dest_addr_kind(host: str) -> str:
    """Return 'ipv4', 'ipv6', or 'domain' for a destination host string."""
    try:
        ip = ipaddress.ip_address(host)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        return "domain"


# ── SOCKS5 (RFC 1928) ──────────────────────────────────────────────────────────

def _socks5_connect(sock: socket.socket, dest_host: str, dest_port: int,
                     username: Optional[str], password: Optional[str]) -> None:
    # Greeting: offer no-auth, and username/password auth if creds are set.
    methods = b"\x00" if not (username and password) else b"\x00\x02"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    ver, chosen = _recv_exact(sock, 2)
    if ver != 0x05:
        raise ProxyProtocolError(f"SOCKS5: unexpected version in greeting reply: {ver}")

    if chosen == 0x02:
        if not (username and password):
            raise ProxyProtocolError("SOCKS5 server requires auth but no credentials configured")
        user_b = username.encode("utf-8")
        pass_b = password.encode("utf-8")
        sock.sendall(b"\x01" + bytes([len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
        _ver, status = _recv_exact(sock, 2)
        if status != 0x00:
            raise ProxyProtocolError("SOCKS5 authentication failed (bad username/password)")
    elif chosen == 0xFF:
        raise ProxyProtocolError("SOCKS5 server rejected all offered auth methods")
    elif chosen != 0x00:
        raise ProxyProtocolError(f"SOCKS5 server chose unsupported auth method: {chosen}")

    # CONNECT request. Address type depends on the destination's own kind —
    # this is the fix for IPv6 destinations: RFC 1928 defines ATYP 0x04 for a
    # literal 16-byte IPv6 address, which PySocks's connect() never reached
    # because it raised before getting this far.
    kind = _dest_addr_kind(dest_host)
    if kind == "ipv4":
        atyp = b"\x01"
        addr_bytes = socket.inet_aton(dest_host)
    elif kind == "ipv6":
        atyp = b"\x04"
        addr_bytes = socket.inet_pton(socket.AF_INET6, dest_host)
    else:
        name_b = dest_host.encode("idna") if dest_host.isascii() else dest_host.encode("utf-8")
        if len(name_b) > 255:
            raise ProxyProtocolError(f"SOCKS5: destination hostname too long: {dest_host!r}")
        atyp = b"\x03"
        addr_bytes = bytes([len(name_b)]) + name_b

    sock.sendall(b"\x05\x01\x00" + atyp + addr_bytes + dest_port.to_bytes(2, "big"))

    ver, rep, _rsv, bound_atyp = _recv_exact(sock, 4)
    if ver != 0x05:
        raise ProxyProtocolError("SOCKS5: unexpected version in CONNECT reply")
    if rep != 0x00:
        reasons = {
            0x01: "general SOCKS server failure", 0x02: "connection not allowed by ruleset",
            0x03: "network unreachable", 0x04: "host unreachable", 0x05: "connection refused",
            0x06: "TTL expired", 0x07: "command not supported",
            0x08: "address type not supported",
        }
        raise ProxyProtocolError(
            f"SOCKS5 CONNECT to {dest_host}:{dest_port} refused: "
            f"{reasons.get(rep, f'unknown error code {rep}')}"
        )
    # Consume the bound-address field (its length depends on atyp) — we don't
    # need the value, but it's still sitting in the stream and must be drained.
    if bound_atyp == 0x01:
        _recv_exact(sock, 4 + 2)
    elif bound_atyp == 0x04:
        _recv_exact(sock, 16 + 2)
    elif bound_atyp == 0x03:
        (name_len,) = _recv_exact(sock, 1)
        _recv_exact(sock, name_len + 2)
    else:
        raise ProxyProtocolError(f"SOCKS5: unsupported bound address type in reply: {bound_atyp}")


# ── SOCKS4 / SOCKS4a (IPv4 only — protocol limitation) ────────────────────────

def _socks4_connect(sock: socket.socket, dest_host: str, dest_port: int,
                     username: Optional[str]) -> None:
    kind = _dest_addr_kind(dest_host)
    if kind == "ipv6":
        raise ProxyProtocolError(
            "SOCKS4 cannot address IPv6 destinations (protocol limitation — "
            "use a socks5 or http proxy for IPv6 targets)"
        )
    user_b = (username or "").encode("utf-8") + b"\x00"
    if kind == "domain":
        # SOCKS4a: signal via a 0.0.0.x placeholder address, send hostname after.
        req = b"\x04\x01" + dest_port.to_bytes(2, "big") + b"\x00\x00\x00\x01" + user_b
        req += dest_host.encode("idna") + b"\x00"
    else:
        req = b"\x04\x01" + dest_port.to_bytes(2, "big") + socket.inet_aton(dest_host) + user_b
    sock.sendall(req)

    reply = _recv_exact(sock, 8)
    if reply[0] != 0x00 or reply[1] != 0x5A:
        reasons = {
            0x5B: "request rejected or failed", 0x5C: "no identd reachable at client",
            0x5D: "identd could not confirm user id",
        }
        raise ProxyProtocolError(
            f"SOCKS4 CONNECT to {dest_host}:{dest_port} refused: "
            f"{reasons.get(reply[1], f'unknown status {reply[1]}')}"
        )


# ── HTTP CONNECT (RFC 7231 §4.3.6 / RFC 7230) ─────────────────────────────────

def _http_connect(sock: socket.socket, dest_host: str, dest_port: int,
                   username: Optional[str], password: Optional[str]) -> socket.socket:
    # IPv6 literals in a CONNECT request line must be bracketed (RFC 3986) —
    # this is the whole fix for "IPv6 doesn't work over HTTP proxies" once
    # you're not going through PySocks's AF_INET-only socket path.
    target = f"[{dest_host}]" if _dest_addr_kind(dest_host) == "ipv6" else dest_host

    def _build_request(auth_header: bytes = b"") -> bytes:
        lines = [
            f"CONNECT {target}:{dest_port} HTTP/1.1".encode(),
            f"Host: {target}:{dest_port}".encode(),
            b"Proxy-Connection: keep-alive",
            b"User-Agent: proxygate/1.0",
        ]
        if auth_header:
            lines.append(auth_header)
        return b"\r\n".join(lines) + b"\r\n\r\n"

    def _do_request(auth_header: bytes = b""):
        sock.sendall(_build_request(auth_header))
        return _read_http_response(sock)

    auth_header = b""
    if username and password:
        creds = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        # "Basic" with a capital B — PySocks sent lowercase "basic", which
        # RFC 7235 treats as case-insensitive but not every proxy parser does.
        auth_header = f"Proxy-Authorization: Basic {creds}".encode()

    # Send credentials on the FIRST request whenever we have them, rather
    # than waiting for an unauthenticated request to be challenged with 407
    # first. Some proxies (residential/P2P networks in particular) never
    # send a 407 at all — they just silently drop the connection if the
    # first request lacks valid credentials, which made every single
    # request to a credentialed proxy fail identically when this only
    # attempted auth after seeing a 407 that would never arrive.
    status, _headers = _do_request(auth_header)

    if status == 407 and auth_header:
        # Proxy challenged anyway despite creds being sent upfront (e.g. it
        # only issues 407 on the very first request per connection, or wants
        # a session-specific realm/nonce from its own challenge) — retry
        # once with the same credentials in response to the explicit ask.
        status, _headers = _do_request(auth_header)

    if status != 200:
        raise ProxyProtocolError(
            f"HTTP proxy CONNECT to {dest_host}:{dest_port} failed: "
            f"upstream returned HTTP {status}"
        )
    return sock


def _read_http_response(sock: socket.socket) -> tuple[int, list[bytes]]:
    """
    Read a full HTTP response head (status line + headers) ending at
    \\r\\n\\r\\n — one byte at a time, deliberately, so the read stops the
    instant the terminator is seen and never consumes a single byte of the
    tunnelled stream that follows.

    Reading in a larger chunk (e.g. recv(4096)) risks grabbing the start of
    the real (post-CONNECT) traffic in the same read if a proxy happens to
    pack both into one TCP segment. There's no way to hand bytes back to the
    socket for asyncio to see again once ownership of it is handed over
    after this function returns — especially not through a TLS layer, which
    reads the raw fd itself rather than going through any wrapper this
    module could intercept — so avoiding the over-read in the first place is
    the only fully reliable option. This response head is tiny (a handful of
    header lines), so the per-byte syscall cost here is negligible and only
    paid once per new connection.
    """
    buf = b""
    while not buf.endswith(b"\r\n\r\n"):
        b_ = sock.recv(1)
        if not b_:
            if not buf:
                raise ProxyProtocolError(
                    "HTTP proxy closed connection with zero bytes sent back — "
                    "likely rejected the request outright (bad/missing credentials, "
                    "IP not allowlisted, or the proxy doesn't speak CONNECT at all)"
                )
            raise ProxyProtocolError(
                f"HTTP proxy closed connection mid-response, after {len(buf)} bytes "
                f"(partial head: {buf!r})"
            )
        buf += b_
        if len(buf) > 65536:
            raise ProxyProtocolError("HTTP proxy CONNECT response headers too large")
    lines = buf[:-4].split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/"):
        raise ProxyProtocolError(f"HTTP proxy sent a malformed CONNECT response: {lines[:1]!r}")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise ProxyProtocolError(f"HTTP proxy sent an unparseable status line: {lines[0]!r}")
    return status, lines[1:]


# ── Dispatch ───────────────────────────────────────────────────────────────────

_ORIG_OPEN_CONN = asyncio.open_connection


async def _proxied_open_connection(host=None, port=None, **kwargs):
    proxy = _pop_proxy(host, port) if host is not None else None

    if proxy is None or host is None:
        return await _ORIG_OPEN_CONN(host=host, port=port, **kwargs)

    kwargs.pop("local_addr", None)
    ssl_ctx         = kwargs.pop("ssl", None)
    server_hostname = kwargs.pop("server_hostname", None)

    ptype_key  = proxy.get("type", "socks5").lower()
    proxy_host = proxy.get("host", "")
    proxy_port = int(proxy.get("port", 0))
    login      = proxy.get("login")   or None
    pw         = proxy.get("password") or None

    def _sync_connect() -> socket.socket:
        print(f"[proxygate] {ptype_key}://{proxy_host}:{proxy_port} → {host}:{port}", flush=True)
        s = _connect_tcp(proxy_host, proxy_port, _PROXY_CONNECT_TIMEOUT)
        try:
            s.settimeout(_PROXY_CONNECT_TIMEOUT)
            if ptype_key == "socks5":
                _socks5_connect(s, host, port, login, pw)
            elif ptype_key == "socks4":
                _socks4_connect(s, host, port, login)
            elif ptype_key in ("http", "https"):
                _http_connect(s, host, port, login, pw)
            else:
                raise ProxyProtocolError(f"unknown proxy type: {ptype_key!r}")
            s.settimeout(None)
            print(f"[proxygate] OK {host}:{port}", flush=True)
            return s
        except Exception:
            s.close()
            raise

    try:
        loop = asyncio.get_running_loop()
        sock = await loop.run_in_executor(_proxy_executor, _sync_connect)
        if ssl_ctx is not None:
            return await _ORIG_OPEN_CONN(
                sock=sock, ssl=ssl_ctx, server_hostname=server_hostname, **kwargs
            )
        return await _ORIG_OPEN_CONN(sock=sock, **kwargs)
    except Exception as exc:
        print(f"[proxygate] FAIL {host}:{port} via {ptype_key}://{proxy_host}:{proxy_port}: {exc}", flush=True)
        raise OSError(f"proxy error {host}:{port} via {proxy_host}:{proxy_port}: {exc}") from exc


# Install patch once at import time — never removed.
asyncio.open_connection = _proxied_open_connection


# ── Rules engine ──────────────────────────────────────────────────────────────

class RulesEngine:
    def __init__(self) -> None:
        self._lock   = threading.RLock()
        self.rules:   list[dict]      = []
        self.proxies: dict[str, dict] = {}
        self.default: str             = "DIRECT"
        self.load()

    def load(self) -> None:
        try:
            with open(RULES_PATH) as f:
                data = yaml.safe_load(f) or {}
            with self._lock:
                self.proxies = {p["name"]: p for p in data.get("proxies", [])}
                self.rules   = data.get("rules", [])
                self.default = data.get("default", "DIRECT")
            default_cfg = self.proxies.get(self.default) if self.default not in ("DIRECT", "BLOCK") else None
            _set_default_proxy(default_cfg)
            _log.info(f"[proxygate] loaded {len(self.rules)} rules, default={self.default}")
        except FileNotFoundError:
            _log.warning(f"[proxygate] rules file not found: {RULES_PATH}")
        except Exception as e:
            _log.error(f"[proxygate] error loading rules: {e}")

    def resolve_proxy(self, target: str) -> Optional[dict]:
        """Return proxy dict for target name, or None for DIRECT/BLOCK/unknown."""
        with self._lock:
            if target in ("DIRECT", "BLOCK") or not target:
                return None
            return self.proxies.get(target)

    def match(self, host: str) -> tuple[str, str]:
        """
        Return (rule_name, target) — target is DIRECT, BLOCK, or a proxy name.

        Splitting and matching both live in backend.patterns so this and the
        API's validation can't disagree about what a rule means.
        """
        with self._lock:
            for rule in self.rules:
                if not rule.get("enabled", True):
                    continue
                if matches_any(rule.get("pattern", ""), host):
                    return rule["name"], rule["proxy"]
            return "default", self.default


# ── Decrypt-devices engine (TLS-MITM opt-in, by MAC) ──────────────────────────
#
# Devices whose MAC is listed here (via the web UI's Devices panel, persisted
# to devices.yaml) get real TLS interception — mitmproxy terminates TLS with
# its own CA and re-encrypts to the upstream, exactly like a normal mitmproxy
# session, which requires that CA to be installed+trusted on the device. Every
# other device keeps the original raw-TLS passthrough (ignore_connection=True)
# behavior: no CA needed, no decryption, SNI-only routing/logging as before.
#
# Devices are identified by MAC, not IP, because a MAC survives a DHCP lease
# renewal — flagging a phone once in the UI keeps working even if its IP on
# the hotspot subnet changes later in the same session or across reconnects.

class DevicesEngine:
    def __init__(self) -> None:
        self._lock: threading.RLock = threading.RLock()
        self.decrypt_macs: set[str] = set()
        self.load()

    def load(self) -> None:
        try:
            with open(DEVICES_PATH) as f:
                data = yaml.safe_load(f) or {}
            macs = {
                d["mac"].strip().lower().replace("-", ":")
                for d in data.get("devices", [])
                if d.get("decrypt") and d.get("mac")
            }
            with self._lock:
                self.decrypt_macs = macs
            _log.info(f"[proxygate] loaded {len(macs)} decrypt-enabled device(s)")
        except FileNotFoundError:
            with self._lock:
                self.decrypt_macs = set()
        except Exception as e:
            _log.error(f"[proxygate] error loading devices: {e}")

    def should_decrypt(self, mac: Optional[str]) -> bool:
        if not mac:
            return False
        with self._lock:
            return mac.strip().lower().replace("-", ":") in self.decrypt_macs


# ── Per-(device, domain) decrypt circuit breaker ──────────────────────────────
#
# Some apps (Hotstar, Disney+, etc.) pin their own certificate/key and will
# NEVER accept mitmproxy's CA regardless of device trust settings — every
# single connection to those domains would otherwise retry a doomed decrypt
# handshake forever (the app itself hammers a rejected endpoint with fresh
# connections). But a domain rejecting the cert on ONE device says nothing
# about whether it'll reject it on a DIFFERENT device — a device with the CA
# genuinely trusted (system-level, or an app without pinning) should still
# get a real attempt at that same domain. So this is keyed by (mac, domain),
# not domain alone — the earlier all-devices-share-one-blocklist version
# meant a single failure from any device silently killed decryption for that
# domain everywhere, including devices that would have succeeded.
#
# 3 consecutive failures for a given (mac, domain) trips the breaker for 10
# minutes (falls back to passthrough), then automatically allows one more
# attempt — self-healing in case the CA/app situation changed (a newly
# installed CA, an app update that stopped pinning, etc.) — rather than
# either retrying forever (retry-storms an app that will never accept the
# cert) or staying blocked until someone manually intervenes.
#
# Deliberately in-memory only (not persisted) — a restart gives every
# (mac, domain) pair a fresh start.

_DECRYPT_FAIL_THRESHOLD = 3
_DECRYPT_COOLDOWN_SECS = 600

_decrypt_breaker: dict[tuple[str, str], dict] = {}
_decrypt_breaker_lock = threading.Lock()


def _breaker_key(mac: str, host: str) -> tuple[str, str]:
    return (mac.strip().lower().replace("-", ":"), host)


def _domain_blocked_from_decrypt(mac: str, host: str) -> bool:
    key = _breaker_key(mac, host)
    now = time.time()
    with _decrypt_breaker_lock:
        state = _decrypt_breaker.get(key)
        if not state:
            return False
        if state["fails"] < _DECRYPT_FAIL_THRESHOLD:
            return False
        if now - state["tripped_at"] >= _DECRYPT_COOLDOWN_SECS:
            # Cooldown elapsed — allow exactly one more attempt. If it fails
            # again, note_decrypt_failure() below re-trips the breaker with a
            # fresh tripped_at, restarting the cooldown.
            state["fails"] = 0
            return False
        return True


def _note_decrypt_failure(mac: str, host: str) -> None:
    key = _breaker_key(mac, host)
    with _decrypt_breaker_lock:
        state = _decrypt_breaker.setdefault(key, {"fails": 0, "tripped_at": 0.0})
        state["fails"] += 1
        if state["fails"] >= _DECRYPT_FAIL_THRESHOLD:
            state["tripped_at"] = time.time()


def _note_decrypt_success(mac: str, host: str) -> None:
    key = _breaker_key(mac, host)
    with _decrypt_breaker_lock:
        _decrypt_breaker.pop(key, None)


# IP -> MAC resolution — MUST NEVER BLOCK, because tls_clienthello is a
# synchronous hook that mitmproxy calls directly from its asyncio event
# loop, not something we can `await` an executor future from. The previous
# version called backend.services.resolve_mac() inline on every cache miss —
# harmless for the dnsmasq-leases path (a plain file read) but its ARP
# fallback shells out to `ip -4 neigh show` via subprocess.run(), which
# blocks the ENTIRE event loop (every other in-flight TLS handshake on
# every device) for however long that subprocess takes. Confirmed as the
# actual cause of a burst of "client disconnected during the handshake"
# failures (as opposed to real "does not trust the proxy's certificate"
# rejections) — 7+ failures within a 16ms window, consistent with a stalled
# event loop losing races against a device (iOS in particular) that opens
# many parallel speculative connections and kills whichever don't respond
# in time. That failure mode has nothing to do with CA trust and was made
# worse, not better, by retrying — the stall was the cause of the retries.
#
# Fix: a background thread refreshes a full ip->mac snapshot on its own
# schedule (mirrors RulesWatcher/DnsLogTailer's poll-loop pattern already
# used elsewhere in this file); _resolve_mac() only ever reads that
# snapshot in-line, synchronously, with no I/O of its own. Worst case this
# is a few seconds stale (a device's MAC changing mid-session is rare on a
# live hotspot lease anyway); that staleness is a fully acceptable trade for
# never stalling the proxy's entire event loop again.

_mac_snapshot: dict[str, str] = {}
_mac_snapshot_lock = threading.Lock()
_MAC_SNAPSHOT_REFRESH_SECS = 3.0
# Set by _resolve_mac() on a miss so the refresher re-reads immediately
# instead of sleeping out the rest of its interval. Bounded below by
# _MAC_SNAPSHOT_MIN_SECS so a burst of unknown IPs can't turn the refresh
# into a hot loop shelling out to `ip neigh` continuously.
_mac_refresh_now = threading.Event()
_MAC_SNAPSHOT_MIN_SECS = 0.5


def _resolve_mac(ip: str) -> Optional[str]:
    with _mac_snapshot_lock:
        mac = _mac_snapshot.get(ip)
    if mac is None:
        # A device that has only just joined isn't in the snapshot yet, so
        # its first connections resolve to no MAC and silently fall through
        # to passthrough — even when it IS on the decrypt allowlist. Those
        # early connections (app launch, login) are often the ones worth
        # capturing, so ask the refresher to re-read now rather than waiting
        # out the rest of the poll interval.
        #
        # Only a nudge: this stays non-blocking (setting an event, no I/O on
        # the proxy's event loop), so this connection still goes through as
        # passthrough. It shortens the blind window for the ones behind it
        # from up to _MAC_SNAPSHOT_REFRESH_SECS to roughly one refresh.
        _mac_refresh_now.set()
        _note_unresolved_mac(ip)
    return mac


# IPs seen with no MAC, logged once each. Without this the only symptom of a
# device never being decrypted is silence — no error, no row, nothing to
# distinguish "not on the allowlist" from "we couldn't identify it".
_unresolved_macs: set = set()
_unresolved_lock = threading.Lock()


def _note_unresolved_mac(ip: str) -> None:
    with _unresolved_lock:
        if ip in _unresolved_macs:
            return
        _unresolved_macs.add(ip)
    _log.info("[proxygate] no MAC known for %s yet — decryption cannot be "
              "evaluated for it until the device table refreshes. If this "
              "persists, the device may not have a DHCP lease or ARP entry "
              "on the hotspot interface.", ip)


class MacSnapshotRefresher:
    """Background-only IP->MAC table refresh — see _resolve_mac's docstring
    for why this can never run inline from tls_clienthello."""
    def __init__(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="mac-snapshot-refresher"
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                from backend.services import list_hotspot_devices
                devices = list_hotspot_devices()
                snapshot = {d["ip"]: d["mac"] for d in devices if d.get("ip") and d.get("mac")}
                with _mac_snapshot_lock:
                    _mac_snapshot.clear()
                    _mac_snapshot.update(snapshot)
            except Exception:
                # Logged at debug, not silently swallowed to nothing — an
                # import/subprocess failure here means MAC resolution goes
                # stale (old snapshot keeps serving) rather than never
                # working at all, which is a much softer failure mode than
                # the old inline version's "decryption silently never
                # engages for ANY device" when resolution broke.
                _log.debug(f"[proxygate] MacSnapshotRefresher: {traceback.format_exc()}")

            # Wake early when _resolve_mac() saw an IP it couldn't identify
            # (a device that just joined), so its next connections can be
            # evaluated for decryption instead of waiting out the interval.
            # The floor keeps a stream of unknown IPs from spinning this.
            if _mac_refresh_now.wait(timeout=_MAC_SNAPSHOT_REFRESH_SECS):
                _mac_refresh_now.clear()
                time.sleep(_MAC_SNAPSHOT_MIN_SECS)


# ── Watcher ───────────────────────────────────────────────────────────────────

RELOAD_SIGNAL = os.getenv("PROXYGATE_RELOAD_SIGNAL", "/tmp/proxygate-reload")


class RulesWatcher:
    """Polls rules.yaml + devices.yaml mtimes + reload-signal file; hot-reloads
    without restarting mitmdump."""
    def __init__(self, rules: RulesEngine, devices: DevicesEngine) -> None:
        self._rules   = rules
        self._devices = devices
        self._thread  = threading.Thread(target=self._run, daemon=True, name="rules-watcher")

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        last_mtime         = 0.0
        last_devices_mtime = 0.0
        last_signal        = 0.0
        while True:
            try:
                mtime = os.stat(RULES_PATH).st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    self._rules.load()
            except FileNotFoundError:
                pass
            except Exception:
                pass
            try:
                dmtime = os.stat(DEVICES_PATH).st_mtime
                if dmtime != last_devices_mtime:
                    last_devices_mtime = dmtime
                    self._devices.load()
            except FileNotFoundError:
                pass
            except Exception:
                pass
            try:
                sig = os.stat(RELOAD_SIGNAL).st_mtime
                if sig != last_signal:
                    last_signal = sig
                    self._rules.load()
                    self._devices.load()
                    print("[proxygate] rules/devices force-reloaded via signal", flush=True)
            except FileNotFoundError:
                pass
            except Exception:
                pass
            time.sleep(0.25)


# ── dnsmasq log tailer ────────────────────────────────────────────────────────

class DnsLogTailer:
    def __init__(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="dns-log-tailer"
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                self._tail()
            except Exception:
                time.sleep(5)

    def _tail(self) -> None:
        while not os.path.exists(DNSMASQ_LOG):
            time.sleep(2)
        with open(DNSMASQ_LOG, "r") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                m = _DNS_REPLY_RE.search(line)
                if m:
                    _upsert_dns(m.group(2), m.group(1))


# ── QUIC-blocked-attempt log tailer ───────────────────────────────────────────
#
# QUIC/HTTP3 runs over UDP/443, which never reaches mitmproxy — all UDP from
# the hotspot is dropped at the firewall (see apply_iptables() in
# services.py; there's no UDP proxy path). Logging these as their own
# "QUIC (blocked)" traffic-table rows, rather than silently dropping them
# with no visibility at all, is what the "--dport 443 -j LOG" rule added
# there is for. This only ever produces informational rows (no proxy/rule
# was applied, nothing was actually forwarded) — the connection itself was
# dropped, exactly as it always was; this tailer doesn't change that.

class QuicLogTailer:
    def __init__(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="quic-log-tailer"
        )

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                self._tail()
            except Exception:
                time.sleep(5)

    def _tail(self) -> None:
        while not os.path.exists(KERN_LOG):
            time.sleep(2)
        with open(KERN_LOG, "r") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                m = _QUIC_LOG_RE.search(line)
                if not m:
                    continue
                src_ip, dst_ip, dst_port = m.group(1), m.group(2), int(m.group(3))
                display_host = resolve_host(dst_ip)
                _insert_connection(
                    source_ip    = src_ip,
                    dest_host    = display_host,
                    dest_port    = dst_port,
                    method       = None,
                    status_code  = None,
                    bytes_xfer   = 0,
                    rule_matched = "—",
                    proxy_used   = "BLOCKED",
                    protocol     = "QUIC (blocked)",
                )


# ── mitmproxy addon ───────────────────────────────────────────────────────────

class ProxyGateAddon:
    def __init__(self) -> None:
        _init_db()
        self.rules    = RulesEngine()
        self.devices  = DevicesEngine()
        self._watcher = RulesWatcher(self.rules, self.devices)
        self._watcher.start()
        self._tailer  = DnsLogTailer()
        self._tailer.start()
        self._quic_tailer = QuicLogTailer()
        self._quic_tailer.start()
        self._mac_refresher = MacSnapshotRefresher()
        self._mac_refresher.start()
        _log.info("[proxygate] addon loaded")

    def running(self) -> None:
        ctx.log.info("[proxygate] running in transparent mode")

    def configure(self, updated: set) -> None:
        if "scripts" in updated or not updated:
            self.rules.load()
            self.devices.load()

    # ── TLS passthrough / decrypt ──────────────────────────────────────────────

    def tls_clienthello(self, data) -> None:
        try:
            context     = data.context
            server_addr = context.server.address
            if not server_addr:
                data.ignore_connection = True
                return

            dest_ip, dest_port = server_addr[0], server_addr[1]
            src_ip       = context.client.peername[0] if context.client.peername else "?"
            sni          = data.client_hello.sni if data.client_hello else None
            display_host = sni or resolve_host(dest_ip)

            rule_name, target = self.rules.match(display_host)
            proxy_cfg = self.rules.resolve_proxy(target)

            # Swap server.address to SNI so the proxy receives a domain name.
            connect_host = sni or dest_ip
            if sni and context.server.address[0] != sni:
                try:
                    context.server.address = (sni, dest_port)
                except Exception:
                    pass

            if target == "BLOCK":
                data.ignore_connection = True
                return

            # Register the proxy for this destination so open_connection picks it up.
            _register_proxy(connect_host, dest_port, proxy_cfg)
            print(f"[proxygate] rule={rule_name} proxy={target} → {connect_host}:{dest_port}", flush=True)

            # Per-device decrypt opt-in: only a device whose MAC is flagged in
            # devices.yaml (via the web UI) gets its TLS actually terminated by
            # mitmproxy's own CA — every other device keeps the original raw-TLS
            # passthrough. See DevicesEngine's docstring for the full rationale.
            #
            # Per-(device, domain) circuit breaker: a domain that has already
            # failed 3 times in a row for THIS SPECIFIC device (cert pinning,
            # typically) skips straight to passthrough for 10 minutes instead
            # of repeating a handshake we already know will fail — then
            # allows one more attempt automatically. A different device
            # hitting the same domain is unaffected; see
            # _domain_blocked_from_decrypt's docstring.
            mac = _resolve_mac(src_ip)
            decrypt = self.devices.should_decrypt(mac) and mac and not _domain_blocked_from_decrypt(mac, display_host)
            data.ignore_connection = not decrypt
            if decrypt:
                print(f"[proxygate] decrypting {src_ip} (mac={mac}) → {connect_host}:{dest_port}", flush=True)

            protocol = _classify_protocol(dest_port, decrypted=decrypt, is_tls=True)

            _insert_connection(
                source_ip    = src_ip,
                dest_host    = display_host,
                dest_port    = dest_port,
                method       = "CONNECT",
                status_code  = None,
                bytes_xfer   = 0,
                rule_matched = rule_name,
                proxy_used   = target,
                protocol     = protocol,
            )

        except Exception:
            _log.debug(f"[proxygate] tls_clienthello: {traceback.format_exc()}")
            try:
                data.ignore_connection = True
            except Exception:
                pass

    # ── TLS decrypt outcome (per-device, per-domain circuit breaker) ───────────
    #
    # Fires once per failed handshake. If the client rejected our cert (as
    # opposed to some other TLS error), note a failure for THIS (mac, domain)
    # pair — after 3 in a row it falls back to passthrough for 10 minutes,
    # then gets one more attempt automatically. Scoped to the device that
    # actually failed: a different device is never affected by this.
    #
    # Key must match tls_clienthello's `display_host` exactly, or the
    # breaker silently never applies. tls_clienthello uses
    # `sni or resolve_host(dest_ip)` — a bare-IP connection (no SNI at all,
    # e.g. some CDN edge/app traffic) still gets a real key there (the IP
    # itself, since resolve_host() is a no-op when there's no PTR record).
    # Reading only `data.conn.sni` here missed that case entirely: dest was
    # None for every IP-literal connection, so those never tripped the
    # breaker and kept retrying a doomed decrypt handshake forever —
    # confirmed happening in practice against 146.70.15.2 / 173.239.200.129
    # (both reachable, both just don't have a PTR record, so they never
    # carry an SNI to key on).

    def tls_failed_client(self, data) -> None:
        try:
            err = getattr(data.conn, "error", None) or ""
            peername = getattr(data.conn, "peername", None)
            src_ip = peername[0] if peername else None
            mac = _resolve_mac(src_ip) if src_ip else None
            if not mac:
                return
            sni = getattr(data.conn, "sni", None)
            if sni:
                dest = sni
            else:
                # No SNI: data.conn is the CLIENT connection, so its peername
                # is the phone, not the destination — the destination server
                # address lives on the context instead. Same fallback
                # tls_clienthello uses (resolve_host, a no-op when there's no
                # PTR record — the IP string itself becomes the stable key).
                server_addr = getattr(getattr(data, "context", None), "server", None)
                server_addr = getattr(server_addr, "address", None) if server_addr else None
                dest = resolve_host(server_addr[0]) if server_addr else None
            if not dest:
                return
            if "does not trust the proxy" not in err and "certificate unknown" not in err:
                return  # some other TLS failure — not a cert-pinning/trust rejection
            _note_decrypt_failure(mac, dest)
            print(f"[proxygate] {dest} rejected our CA for mac={mac} "
                  f"(strike toward this device+domain's retry breaker)", flush=True)
        except Exception:
            _log.debug(f"[proxygate] tls_failed_client: {traceback.format_exc()}")

    def tls_established_client(self, data) -> None:
        """A decrypted handshake actually succeeded — clear any prior failure
        streak for this (mac, domain) so it doesn't carry stale strikes."""
        try:
            peername = getattr(data.conn, "peername", None)
            src_ip = peername[0] if peername else None
            if not src_ip:
                return
            mac = _resolve_mac(src_ip)
            if not mac:
                return
            sni = getattr(data.conn, "sni", None)
            if sni:
                _note_decrypt_success(mac, sni)
        except Exception:
            _log.debug(f"[proxygate] tls_established_client: {traceback.format_exc()}")

    # ── HTTP request ──────────────────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            raw_host     = flow.request.pretty_host or flow.request.host
            display_host = resolve_host(raw_host)
            dest_port    = flow.request.port
            rule_name, target = self.rules.match(display_host)
            proxy_cfg = self.rules.resolve_proxy(target)

            flow.metadata["rule_matched"] = rule_name
            flow.metadata["proxy_used"]   = target
            flow.metadata["display_host"] = display_host
            flow.metadata["source_ip"]    = (
                flow.client_conn.peername[0] if flow.client_conn.peername else "?"
            )

            if target == "BLOCK":
                flow.kill()
                return

            # For HTTP, server_conn may already be open (keep-alive reuse).
            # Only register if the connection isn't established yet.
            from mitmproxy.connection import ConnectionState
            if (flow.server_conn.state is ConnectionState.CLOSED
                    or flow.server_conn.address is None):
                connect_host = raw_host if not _is_ip(raw_host) else display_host
                _register_proxy(connect_host, dest_port, proxy_cfg)
                print(f"[proxygate] rule={rule_name} proxy={target} → {connect_host}:{dest_port}", flush=True)

                # Swap address to hostname so the proxy gets a domain name.
                if flow.server_conn.address and flow.server_conn.address[0] != connect_host:
                    try:
                        flow.server_conn.address = (connect_host, dest_port)
                    except Exception:
                        pass

        except Exception:
            _log.debug(f"[proxygate] request: {traceback.format_exc()}")

    # ── HTTP response / error — log completed transaction ─────────────────────

    def response(self, flow: http.HTTPFlow) -> None:
        self._log_flow(flow, is_error=False)

    def error(self, flow: http.HTTPFlow) -> None:
        self._log_flow(flow, is_error=True)

    def _log_flow(self, flow: http.HTTPFlow, is_error: bool) -> None:
        try:
            meta   = flow.metadata
            src    = meta.get("source_ip") or (
                flow.client_conn.peername[0] if flow.client_conn.peername else "?"
            )
            host   = meta.get("display_host") or flow.request.pretty_host
            port   = flow.request.port

            method      = flow.request.method if flow.request else None
            status_code = (
                flow.response.status_code if flow.response
                else (0 if is_error else None)
            )

            req_size  = len(flow.request.content)  if flow.request  and flow.request.content  else 0
            resp_size = len(flow.response.content) if flow.response and flow.response.content else 0

            # This hook fires for BOTH plain HTTP and decrypted HTTPS flows
            # (mitmproxy only calls request()/response() once TLS is actually
            # terminated — a raw-passthrough flow never reaches here at all,
            # which is exactly why it never had status codes before). scheme
            # tells them apart for the Type column.
            is_https = flow.request.scheme == "https" if flow.request else False
            protocol = _classify_protocol(port, decrypted=is_https, is_tls=is_https)

            connection_id = _insert_connection(
                source_ip    = src,
                dest_host    = host,
                dest_port    = port,
                method       = method,
                status_code  = status_code,
                bytes_xfer   = req_size + resp_size,
                rule_matched = meta.get("rule_matched", "default"),
                proxy_used   = meta.get("proxy_used",   "DIRECT"),
                protocol     = protocol,
            )

            # Full request/response capture — Charles/Burp-style detail view.
            # Only meaningful for flows we actually had visibility into
            # (i.e. every flow that reaches this hook at all); a plain HTTP
            # flow always did, a decrypted HTTPS flow only reaches here
            # because DevicesEngine + the circuit breaker allowed decryption.
            if flow.request:
                req_headers = "\n".join(f"{k}: {v}" for k, v in flow.request.headers.items())
                req_body = bytes(flow.request.content) if flow.request.content else None
            else:
                req_headers = None
                req_body = None
            if flow.response:
                resp_headers = "\n".join(f"{k}: {v}" for k, v in flow.response.headers.items())
                resp_body = bytes(flow.response.content) if flow.response.content else None
            else:
                resp_headers = None
                resp_body = None
            _insert_flow_details(connection_id, req_headers, req_body, resp_headers, resp_body)
        except Exception:
            ctx.log.debug(f"[proxygate] log error: {traceback.format_exc()}")


# ── Register addon ────────────────────────────────────────────────────────────
addons = [ProxyGateAddon()]
