"""
backend/devices.py — one answer to "what devices are on the hotspot?".

WHY THIS EXISTS
---------------
Seven functions used to answer this question, each reading a different source
with different staleness and different failure modes:

    get_connected_devices  _read_leases      _dnsmasq_leases  _associated_stations
    _neighbor_table        resolve_mac       list_hotspot_devices

Every device bug we hit was two of them disagreeing:

  * ARP keeps a row long after a device leaves (REACHABLE → STALE → … → FAILED),
    so stale rows read as "connected" — the "ghost devices".
  * A device discovered via ARP was inserted with no hostname even when a DHCP
    lease for the same MAC had one, so it rendered as a bare IP and MAC.
  * A lease expiring made a device that was still present lose its name.
  * A device that had just joined was in none of the caches yet, so its first
    connections could not be identified at all.

The cure is a single merge with EXPLICIT PROVENANCE. Each source contributes
what only it knows, we record which source said what, and nothing silently
overwrites better information with worse:

    radio (iw station dump) — authoritative for "associated right now"
    DHCP leases             — authoritative for IP and hostname
    ARP/neighbour table     — fallback reachability for non-DHCP devices

A device is reported if ANY source sees it; `associated` says whether the radio
currently has it. That union is deliberate: a phone that has just rotated its
MAC appears on the radio under the old address while the new one carries
traffic, so intersecting the sources would hide the device that is actually
working.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# Neighbour states meaning "really on the network now". The kernel keeps a row
# with a valid lladdr long after a device is gone, decaying
# REACHABLE → STALE → DELAY → PROBE → FAILED — treating STALE as present is
# what produced ghost devices. PERMANENT covers a static neighbour.
LIVE_NEIGH_STATES = frozenset({"REACHABLE", "PERMANENT"})


@dataclass
class Device:
    """One physical device, keyed by MAC."""
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    client_id: Optional[str] = None
    vendor: Optional[str] = None
    associated: Optional[bool] = None     # None = radio could not be read
    sources: set[str] = field(default_factory=set)

    @property
    def display_name(self) -> str:
        return self.hostname or self.vendor or self.ip or self.mac

    def as_dict(self) -> dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "client_id": self.client_id,
            "vendor": self.vendor,
            "associated": self.associated,
            "display_name": self.display_name,
            "sources": sorted(self.sources),
        }


def norm_mac(mac) -> str:
    """
    Canonical lowercase colon form, tolerant of junk.

    Non-string input becomes "" rather than raising: this feeds decrypt and
    block decisions, and a malformed value in a YAML file must degrade to
    "no match", never to an exception inside the proxy's request path.
    """
    if not isinstance(mac, str):
        return ""
    return mac.strip().lower().replace("-", ":")


def is_randomized(mac: str) -> bool:
    """
    Locally-administered bit — the device is using a randomized MAC that WILL
    rotate. Identity keyed on it is inherently temporary.
    """
    try:
        return bool(int(norm_mac(mac).split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def clean_client_id(client_id: str, mac: str) -> Optional[str]:
    """
    A DHCP client-id worth using as identity, or None.

    RFC 2132 type-01 ids are just `01:` + the hardware address — which is what
    essentially every device sends. That rotates exactly when the MAC rotates,
    so it is the MAC wearing a hat, not an independent identifier. Only an id
    NOT derived from the MAC can survive a rotation, so only that is kept.
    """
    cid = (client_id or "").strip().lower()
    if not cid or cid == "*":
        return None
    m = norm_mac(mac)
    if cid == f"01:{m}":
        return None
    flat = cid.replace(":", "")
    if flat in (f"01{m.replace(':', '')}", m.replace(":", "")):
        return None
    return cid


# ── Sources ───────────────────────────────────────────────────────────────────

class Sources:
    """
    Where device facts come from. A class so tests can substitute it wholesale
    instead of monkeypatching module functions one at a time — the pattern that
    previously let tests accidentally hit the real radio.
    """

    def __init__(self, hotspot_if: str, lease_paths: tuple[str, ...] = ()):
        self.hotspot_if = hotspot_if
        self.lease_paths = lease_paths

    # These are local, always-fast commands (`iw station dump`, `ip neigh`).
    # A short timeout is deliberate: if one wedges, the caller must get a
    # stale-but-quick answer rather than blocking. 5s was long enough that a
    # single hung call visibly starved the snapshot refresher.
    TIMEOUT = 2.0

    def _run(self, *cmd: str) -> tuple[int, str]:
        try:
            r = subprocess.run(list(cmd), capture_output=True, text=True,
                               timeout=self.TIMEOUT)
            return r.returncode, r.stdout or ""
        except Exception:
            return 1, ""

    def _iface_ok(self) -> bool:
        """
        Refuse to query an unresolved interface.

        "ap0" is the placeholder meaning "not resolved". Running an
        interface-scoped command with it fails, and an UNSCOPED fallback would
        dump the host's entire ARP table — docker bridges, the LAN gateway —
        into the hotspot device list.
        """
        hi = self.hotspot_if
        return bool(hi) and hi != "ap0" and os.path.isdir(f"/sys/class/net/{hi}")

    def stations(self) -> tuple[set[str], bool]:
        """
        (MACs associated to the radio, whether the query worked).

        The second value matters: an empty set means "nobody is connected" only
        if the command succeeded. Otherwise it means "cannot tell", and callers
        must not conclude the hotspot is empty.
        """
        if not self._iface_ok():
            return set(), False
        rc, out = self._run("iw", "dev", self.hotspot_if, "station", "dump")
        if rc != 0:
            return set(), False
        macs = {
            norm_mac(line.split()[1])
            for line in (l.strip() for l in out.splitlines())
            if line.startswith("Station ") and len(line.split()) >= 2
        }
        return macs, True

    def leases(self) -> list[tuple[str, str, Optional[str], Optional[str]]]:
        """(mac, ip, hostname, client_id) from the hotspot's DHCP lease file."""
        for path in self.lease_paths:
            rows = []
            try:
                with open(path) as f:
                    for line in f:
                        parts = line.split()
                        # <expiry> <mac> <ip> <hostname> <client-id>
                        if len(parts) < 3:
                            continue
                        mac = norm_mac(parts[1])
                        ip = parts[2]
                        hostname = parts[3] if len(parts) >= 4 and parts[3] != "*" else None
                        cid = clean_client_id(parts[4], mac) if len(parts) >= 5 else None
                        rows.append((mac, ip, hostname, cid))
            except Exception:
                continue
            if rows:
                return rows
        return []

    def neighbours(self) -> dict[str, str]:
        """{ip: mac} for genuinely-live neighbours on the hotspot interface."""
        if not self._iface_ok():
            return {}
        rc, out = self._run("ip", "-4", "neigh", "show", "dev", self.hotspot_if)
        if rc != 0:
            return {}
        found: dict[str, str] = {}
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" not in parts:
                continue
            i = parts.index("lladdr")
            if i + 1 >= len(parts):
                continue
            # Allowlist, not denylist: previously only FAILED/INCOMPLETE were
            # skipped, so STALE (a departed device) counted as present.
            if not LIVE_NEIGH_STATES.intersection(parts):
                continue
            found[parts[0]] = norm_mac(parts[i + 1])
        return found


# ── The registry: one merged view ─────────────────────────────────────────────

class Registry:
    """
    The single source of truth for hotspot devices.

    Replaces seven overlapping functions. Everything that needs to know about
    devices — the UI, the decrypt gate, the block list, MAC resolution — reads
    from here, so they can no longer disagree with each other.
    """

    def __init__(self, sources: Sources, subnet: Optional[str] = None,
                 vendor_lookup=None, clock=None):
        self._sources = sources
        self._subnet = self._parse_subnet(subnet)
        self._vendor_lookup = vendor_lookup or (lambda mac: None)
        self._lock = threading.RLock()
        # MAC -> last hostname ever seen. A lease file holds only CURRENT
        # leases, so a device keeps its name when its lease rolls instead of
        # degrading to a bare IP mid-session. Only ever added to; a device that
        # never sent a hostname stays nameless rather than borrowing one.
        self._hostname_memo: dict[str, str] = {}
        self._client_id_memo: dict[str, str] = {}
        # Short-lived caches so the event-loop path never does real I/O more
        # than once every _CACHE_TTL seconds. See by_ip().
        self._lease_cache: Optional[list] = None
        self._lease_cache_at: float = 0.0
        self._lookup_cache: dict[str, tuple] = {}
        self._clock = clock or time.monotonic

    @staticmethod
    def _parse_subnet(subnet: Optional[str]):
        if not subnet:
            return None
        try:
            return ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return None

    def _in_subnet(self, ip: Optional[str]) -> bool:
        """
        Confine the view to the hotspot subnet.

        Without this a docker bridge peer or the host's own LAN gateway shows
        up looking like a connected client — the neighbour table is host-wide
        by nature and a system-wide lease file can be shared.
        """
        if self._subnet is None or not ip:
            return True
        try:
            return ipaddress.ip_address(ip) in self._subnet
        except ValueError:
            return False

    def snapshot(self) -> list[Device]:
        """
        Every device currently known, merged from all sources.

        Union, never intersection: a device is included if ANY source sees it,
        and `associated` records whether the radio has it right now. Filtering
        on association would hide a device that is genuinely present but whose
        radio entry is stale — most importantly right after a MAC rotation,
        where the OLD address is still listed while the NEW one carries the
        traffic.
        """
        # Gather OUTSIDE the lock. These three calls run subprocesses and read
        # files; holding the lock across them would block by_ip() — which runs
        # on mitmproxy's event loop — for as long as `iw` and `ip neigh` take
        # to return, stalling every connection the proxy is handling.
        leases = self._sources.leases()
        stations, radio_ok = self._sources.stations()
        neighbours = self._sources.neighbours()

        with self._lock:
            # The lease read above is fresh, so let the event-loop path reuse
            # it instead of doing its own I/O.
            self._lease_cache = leases
            self._lease_cache_at = self._now()

            # Remember names/ids across lease expiry.
            for mac, _ip, hostname, cid in leases:
                if hostname:
                    self._hostname_memo[mac] = hostname
                if cid:
                    self._client_id_memo[mac] = cid

            devices: dict[str, Device] = {}

            def slot(mac: str) -> Device:
                return devices.setdefault(mac, Device(mac=mac))

            # DHCP leases: the only source of IP + hostname.
            for mac, ip, hostname, cid in leases:
                if not self._in_subnet(ip):
                    continue
                d = slot(mac)
                d.ip = d.ip or ip
                d.hostname = d.hostname or hostname
                d.client_id = d.client_id or cid
                d.sources.add("lease")

            # ARP: catches devices with no DHCP lease (static IP).
            for ip, mac in neighbours.items():
                if not self._in_subnet(ip):
                    continue
                d = slot(mac)
                d.ip = d.ip or ip
                d.sources.add("neighbour")

            # Radio: authoritative for "here right now", and the only source
            # that sees a device which has joined but not yet done DHCP.
            for mac in stations:
                d = slot(mac)
                d.sources.add("radio")

            for mac, d in devices.items():
                if d.associated is None:
                    d.associated = (mac in stations) if radio_ok else None
                # Fill from memo only where the live sources said nothing.
                if not d.hostname:
                    d.hostname = self._hostname_memo.get(mac)
                if not d.client_id:
                    d.client_id = self._client_id_memo.get(mac)
                d.vendor = self._vendor_lookup(mac)

            return sorted(devices.values(), key=lambda d: (_ip_key(d.ip), d.mac))

    # ── Lookups ───────────────────────────────────────────────────────────────

    def by_ip(self, ip: str, allow_slow: bool = False) -> Optional[Device]:
        """
        The device at `ip`, or None. SAFE TO CALL FROM AN EVENT LOOP.

        This runs in mitmproxy's synchronous `tls_clienthello` hook, which is
        driven directly from its asyncio loop — there is nothing to await on.
        Anything slow here stalls EVERY connection the proxy is handling, not
        just this one, which shows up as the proxy lagging, pausing, and
        intermittently appearing dead.

        So the fast path is memory-only, backed by a short-lived cache of the
        lease file. Two cheap reads at most:

          * the per-IP cache, refreshed at most every _CACHE_TTL seconds;
          * a lease-file re-read, but only when the cache has expired.

        The neighbour table is NEVER consulted here, because reading it means
        spawning `ip neigh` — a subprocess on the event loop. That is the
        precise mistake that used to stall the proxy, and it is why a device
        with no DHCP lease is reported as unknown rather than being waited for.
        `allow_slow=True` opts into the full lookup, for callers that are not
        on the event loop.
        """
        cached = self._lookup_cache_get(ip)
        if cached is not None:
            return cached or None          # cached negative is False

        device = None
        for mac, lease_ip, hostname, cid in self._leases_cached():
            if lease_ip == ip:
                with self._lock:
                    if hostname:
                        self._hostname_memo[mac] = hostname
                    if cid:
                        self._client_id_memo[mac] = cid
                    hostname = hostname or self._hostname_memo.get(mac)
                    cid = cid or self._client_id_memo.get(mac)
                device = Device(mac=mac, ip=ip, hostname=hostname,
                                client_id=cid, sources={"lease"})
                break

        if device is None and allow_slow:
            # Off the event loop only — this spawns a subprocess.
            for n_ip, mac in self._sources.neighbours().items():
                if n_ip == ip:
                    with self._lock:
                        device = Device(mac=mac, ip=ip,
                                        hostname=self._hostname_memo.get(mac),
                                        client_id=self._client_id_memo.get(mac),
                                        sources={"neighbour"})
                    break

        self._lookup_cache_put(ip, device)
        return device

    # ── Event-loop-safe caching ───────────────────────────────────────────────
    #
    # A negative result is cached too, and deliberately: an unknown IP would
    # otherwise re-read the lease file on every single connection, which is the
    # worst case exactly when the device is generating the most traffic.

    _CACHE_TTL = 2.0
    _NEG_TTL = 1.0

    def _now(self) -> float:
        return self._clock()

    def _leases_cached(self):
        """Lease rows, re-read at most every _CACHE_TTL seconds."""
        now = self._now()
        with self._lock:
            if self._lease_cache is not None and now - self._lease_cache_at < self._CACHE_TTL:
                return self._lease_cache
        rows = self._sources.leases()
        with self._lock:
            self._lease_cache = rows
            self._lease_cache_at = now
        return rows

    def _lookup_cache_get(self, ip: str):
        """Device, False (known-absent), or None (not cached)."""
        now = self._now()
        with self._lock:
            hit = self._lookup_cache.get(ip)
            if hit is None:
                return None
            device, at = hit
            ttl = self._CACHE_TTL if device else self._NEG_TTL
            if now - at >= ttl:
                self._lookup_cache.pop(ip, None)
                return None
            return device

    def _lookup_cache_put(self, ip: str, device) -> None:
        with self._lock:
            # Bounded: a busy hotspot must not grow this without limit.
            if len(self._lookup_cache) > 512:
                self._lookup_cache.clear()
            self._lookup_cache[ip] = (device or False, self._now())

    def invalidate(self) -> None:
        """Drop cached lookups — call when leases are known to have changed."""
        with self._lock:
            self._lease_cache = None
            self._lookup_cache.clear()

    def mac_for_ip(self, ip: str) -> Optional[str]:
        d = self.by_ip(ip)
        return d.mac if d else None

    def associated_macs(self) -> set[str]:
        macs, _ok = self._sources.stations()
        return macs

    def connected_count(self) -> int:
        """
        Devices associated to the radio right now.

        Counts stations, not leases or ARP rows: both of those persist long
        after a device leaves and would over-count.
        """
        macs, ok = self._sources.stations()
        return len(macs) if ok else 0


def _ip_key(ip: Optional[str]) -> tuple:
    """Sort IPs numerically ('.9' before '.101'), with unknowns last."""
    if not ip:
        return (1, 0)
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)
