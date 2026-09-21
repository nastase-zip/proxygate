"""
backend/services.py — Start / stop / status for ProxyGate services.

Gateway lifecycle is managed as a state machine (IDLE → CONNECTING → CONNECTED
→ DISCONNECTING → IDLE).  connect_gateway() / disconnect_gateway() run in
background threads so the GUI stays responsive.

All network-affecting operations (iptables, hotspot, mitmproxy) happen ONLY
when the user explicitly connects.  Disconnecting removes every rule so normal
host networking is unaffected.
"""

from __future__ import annotations

import enum
import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

# conntrack is needed to flush existing connections when the proxy target
# changes; without it a toggle leaves established flows on the old route.
#
# Bounded and non-fatal on purpose. This runs at IMPORT time, so an
# unbounded apt-get would hang every process that imports this module —
# the web UI, the CLI, a test run — indefinitely on a held dpkg lock or a
# dead network, with no output explaining why. Installation is setup.sh's
# job; this is only a convenience fallback.
if not shutil.which("conntrack"):
    try:
        subprocess.run(["apt-get", "install", "-y", "-q", "conntrack"],
                       capture_output=True, timeout=60)
    except Exception as _e:   # timeout, apt missing, no permissions, …
        log.warning("conntrack is not installed and could not be installed "
                    "automatically (%s) — connection flushing on proxy "
                    "switch will be skipped. Install it manually: "
                    "apt-get install conntrack", _e)

# ── Paths ─────────────────────────────────────────────────────────────────────
#
# Everything ProxyGate reads/writes lives under this checkout by default
# (<repo>/etc/proxygate, <repo>/var/lib/proxygate, <repo>/var/log/proxygate)
# instead of the real /etc, /var/lib, /var/log — keeps the whole project
# self-contained so a fresh clone/copy never picks up another machine's
# config, rules, or device state. Override any single path with its
# PROXYGATE_* env var if a real system-wide install is ever needed.

_HERE          = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT   = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))

CONFIG_PATH  = os.getenv("PROXYGATE_CONFIG", os.path.join(PROJECT_ROOT, "etc/proxygate/config.yaml"))
RULES_PATH   = os.getenv("PROXYGATE_RULES",  os.path.join(PROJECT_ROOT, "etc/proxygate/rules.yaml"))

ADDON_PATH  = os.getenv("PROXYGATE_ADDON", os.path.join(_HERE, "mitm_logger.py"))


# ── Default config ────────────────────────────────────────────────────────────

_DEFAULT_CONFIG: dict = {
    "wan_if":         "",
    "ap_con_name":    "proxygate-ap",
    "ap_wifi_if":     "*",
    "ap_ssid":        "ProxyGate",
    "ap_password":    "proxygate123",
    "ap_band":        "",                   # "" → auto; "a" → 5 GHz; "bg" → 2.4 GHz
    "hotspot_subnet": "192.168.100.0/24",
    "hotspot_gw":     "192.168.100.1",
    "mitm_port":      8080,
}

_DEFAULT_RULES_YAML = """\
proxies:
  - name: XVPN
    type: http
    host: 127.0.0.1
    port: 8893

  - name: CGVPN
    type: http
    host: 127.0.0.1
    port: 8894

  - name: PIAVPN
    type: http
    host: 127.0.0.1
    port: 8895

rules:
  - name: IP Info
    pattern: "*.ipinfo.io"
    proxy: XVPN
    enabled: true

  - name: Google
    pattern: "google.com"
    proxy: XVPN
    enabled: true

default: DIRECT
"""

# ── Runtime state — updated after AP comes up ─────────────────────────────────

HOTSPOT_IF: str = "ap0"

# ── Config I/O ────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if _yaml is None:
        return dict(_DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH) as f:
            data = _yaml.safe_load(f) or {}
        return {**_DEFAULT_CONFIG, **data}
    except FileNotFoundError:
        return dict(_DEFAULT_CONFIG)
    except Exception:
        return dict(_DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    if _yaml is None:
        return
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(CONFIG_PATH))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            _yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
        os.replace(tmp_path, CONFIG_PATH)
        from backend.rules import _restore_owner
        _restore_owner(CONFIG_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


# ── Network interface helpers ─────────────────────────────────────────────────

def _default_route_devs() -> list[str]:
    """
    Return every interface currently holding a default route, ordered by
    routing metric (best/lowest first — the one the kernel actually uses).
    A machine can have several default routes at once (WiFi + Ethernet both
    DHCP'd); whichever has the lowest metric wins and is what `ip route get`
    would report. We need the whole ordered list, not just the winner, so we
    can skip over one that turns out to be the AP interface.
    """
    try:
        r = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        routes = []  # (metric, dev)
        for line in r.stdout.splitlines():
            parts = line.split()
            dev = metric = None
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    dev = parts[idx + 1]
            if "metric" in parts:
                idx = parts.index("metric")
                if idx + 1 < len(parts):
                    try:
                        metric = int(parts[idx + 1])
                    except ValueError:
                        metric = 0
            if dev:
                routes.append((metric if metric is not None else 0, dev))
        routes.sort(key=lambda t: t[0])
        # de-dupe while preserving order (a dev can appear once per route table entry)
        seen: set = set()
        ordered = []
        for _metric, dev in routes:
            if dev not in seen:
                seen.add(dev)
                ordered.append(dev)
        return ordered
    except Exception:
        return []


def list_wifi_interfaces() -> list[str]:
    """Return names of interfaces NetworkManager reports as type 'wifi'."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"],
            capture_output=True, text=True, timeout=5,
        )
        ifaces = []
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "wifi":
                ifaces.append(parts[0])
        return ifaces
    except Exception:
        return []


def resolve_ap_wifi_if() -> str:
    """
    Return the physical interface the hotspot AP will actually bind to.

    `ap_wifi_if` in config is either a literal interface name or "*" (let NM
    pick any WiFi adapter). When it's "*", resolve it to a concrete name so
    detect_wan_if() can positively exclude it — "let NM decide" is exactly
    the ambiguity that let the WAN detector and the AP land on the same NIC.

    Always excludes IPV6_CLIENT_IF: once that virtual interface exists,
    `nmcli ... ifname "*"` becomes ambiguous between two real WiFi devices,
    and NetworkManager choosing the client-link interface for the AP profile
    is a genuine failure mode that's been observed directly — the AP then
    tries to activate on an interface that's mid-(re)association with a
    different network entirely, and fails outright.
    """
    cfg = load_config()
    configured = (cfg.get("ap_wifi_if") or "*").strip()
    if configured and configured != "*" and configured != IPV6_CLIENT_IF:
        return configured
    wifi_ifaces = [i for i in list_wifi_interfaces() if i != IPV6_CLIENT_IF]
    return wifi_ifaces[0] if wifi_ifaces else ""


def detect_wan_if() -> str:
    """
    Return the interface that should carry upstream/internet traffic for the
    hotspot's MASQUERADE rule.

    Dynamic and re-evaluated on every call (not cached) so it tracks router
    swaps, cables being moved, or WiFi reconnecting with a different metric,
    instead of freezing on whatever was true the first time it ran.

    Never returns the interface the WiFi AP is using — that NIC is committed
    to broadcasting the hotspot and can't simultaneously be the egress path.
    If the *lowest-metric* default route happens to be the AP interface
    (e.g. a laptop's only WiFi card also has a stale default route from
    before it became the AP), the next-best default-routed interface is
    used instead, so a WiFi-vs-Ethernet metric race can't silently point
    the gateway at itself.
    """
    ap_if = resolve_ap_wifi_if()
    for dev in _default_route_devs():
        if dev and dev != ap_if:
            return dev
    return ""


def _has_global_ipv6(iface: str) -> bool:
    """True if iface has a real (non-link-local) IPv6 address AND a default route."""
    try:
        addr = subprocess.run(
            ["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global"],
            capture_output=True, text=True, timeout=5,
        )
        if "inet6" not in addr.stdout:
            return False
        route = subprocess.run(
            ["ip", "-6", "route", "show", "default", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        return bool(route.stdout.strip())
    except Exception:
        return False


def list_network_interfaces() -> list[str]:
    try:
        r = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5,
        )
        ifaces = []
        for line in r.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0].strip()
                if name and name != "lo":
                    ifaces.append(name)
        return ifaces
    except Exception:
        return []


# ── AP interface helpers ──────────────────────────────────────────────────────

def _get_ap_if() -> str:
    """Query NM for the live interface of the AP connection."""
    con_name = load_config().get("ap_con_name", "proxygate-ap")
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "GENERAL.IP-IFACE", "con", "show", con_name],
            capture_output=True, text=True, timeout=5,
        )
        val = r.stdout.strip().split(":", 1)[-1].strip()
        if val:
            return val
    except Exception:
        pass
    return "ap0"


# ── Systemd helpers ───────────────────────────────────────────────────────────

def _systemctl(action: str, unit: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["systemctl", action, unit],
        capture_output=True, text=True, timeout=15,
    )
    ok  = result.returncode == 0
    msg = (result.stdout + result.stderr).strip()
    return ok, msg


def _is_active(unit: str) -> bool:
    r = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        capture_output=True, timeout=5,
    )
    return r.returncode == 0


def start_service(unit: str) -> tuple[bool, str]:
    if unit == "hostapd":
        return _nmcli_ap("up")
    if unit == "dnsmasq":
        _nmcli_ap("down"); time.sleep(1)
        return _nmcli_ap("up")
    return _systemctl("start", unit)


def stop_service(unit: str) -> tuple[bool, str]:
    if unit == "hostapd":
        return _nmcli_ap("down")
    if unit == "dnsmasq":
        return True, "dnsmasq is managed by NM (stops with the AP)"
    return _systemctl("stop", unit)


def restart_service(unit: str) -> tuple[bool, str]:
    if unit in ("hostapd", "dnsmasq"):
        _nmcli_ap("down"); time.sleep(1)
        return _nmcli_ap("up")
    return _systemctl("restart", unit)


def service_status(unit: str) -> str:
    if unit == "hostapd":
        return _nmcli_ap_status()
    if unit == "dnsmasq":
        r = subprocess.run(
            ["pgrep", "-af", "dnsmasq"],
            capture_output=True, text=True, timeout=5,
        )
        return "running" if r.returncode == 0 and "dnsmasq" in r.stdout else "stopped"
    try:
        return "running" if _is_active(unit) else "stopped"
    except Exception:
        return "unknown"


def _nmcli_ap(action: str) -> tuple[bool, str]:
    global HOTSPOT_IF
    con_name = load_config().get("ap_con_name", "proxygate-ap")
    result = subprocess.run(
        ["nmcli", "con", action, con_name],
        capture_output=True, text=True, timeout=30,
    )
    ok  = result.returncode == 0
    msg = (result.stdout + result.stderr).strip()
    if ok and action == "up":
        HOTSPOT_IF = _get_ap_if()
    return ok, msg


def _nmcli_ap_status() -> str:
    con_name = load_config().get("ap_con_name", "proxygate-ap")
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "GENERAL.STATE", "con", "show", con_name],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and "activated" in r.stdout.lower():
            return "running"
        return "stopped"
    except Exception:
        return "unknown"


# ── IPv6 client link (second virtual interface, same phy as the AP) ──────────
#
# Problem: an upstream proxy may be IPv6-only and IP-allowlisted — a tunnel
# (WireGuard/WARP was tried and reverted) can't satisfy that, since a
# tunnel's outbound packets always carry the tunnel's own address, never
# this machine's. There's no way around that for a tunnel; a proxy that
# authorizes by source IP will just silently reject a tunnel's identity.
#
# Fix: this specific WiFi chipset supports a second *virtual* interface on
# the same physical radio as the hotspot AP — confirmed via
# `iw phy phy0 info`'s "valid interface combinations": up to 2 managed
# (client) interfaces plus 1 AP interface simultaneously, as long as they
# all share one WiFi channel. So instead of tunneling anywhere, this
# machine directly joins whatever WiFi network it's ALREADY connected to
# (before that radio becomes the AP) using a second interface, while the
# first interface keeps broadcasting the hotspot exactly as before. Traffic
# out that second interface carries no third-party identity at all — it's
# a completely ordinary WiFi client connection, on the same terms any
# device joining that network would get.
#
# Fully automatic, nothing to configure: detect_current_wifi_network() pulls
# the SSID and saved password straight from NetworkManager for whatever
# network is currently active — the same credentials already used to join
# it normally. If the radio isn't a WiFi client of anything right now (e.g.
# freshly booted with no saved WiFi connection), this cleanly no-ops and the
# hotspot proceeds on IPv4 only, exactly as it always has.
#
# The one hard constraint: virtual interfaces on one radio must share a
# channel, AND (confirmed on real hardware) a second interface's scan is
# unreliable while the first is already transmitting as an AP — so the
# client link must associate FIRST, while the radio is still fully idle,
# and the AP is created afterward, pinned to whatever channel the client
# link actually landed on (read back from the driver, not guessed).

IPV6_CLIENT_IF = "wlan-ipv6"
_IPV6_CLIENT_CON = "proxygate-ipv6-client"

# 5GHz channels that require radar (DFS) detection in most regdomains. The AP
# and the IPv6 client link must share one channel (see hard constraint above),
# and this hardware's hostapd refuses to start an AP on any of these outright
# ("Frequency ... not allowed for AP mode, flags: ... RADAR") rather than
# performing a Channel Availability Check — so if the client link associates
# on one of these, the AP can never come up. Avoided at client-link join time
# by preferring a same-SSID BSSID that's off this list when one is in range.
_DFS_CHANNELS = frozenset(
    list(range(52, 145, 4))  # UNII-2 / UNII-2-Extended: 52-64, 100-144
)


def _band_of_freq(freq: Optional[float]) -> Optional[str]:
    """nmcli's band name for a frequency in MHz: "a" (5 GHz) or "bg" (2.4 GHz)."""
    if not freq:
        return None
    return "a" if freq > 4000 else "bg"


def _non_dfs_bssid_for_ssid(iface: str, ssid: str,
                            prefer_band: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """
    Scan for the strongest same-SSID BSS on `iface` that sits on a non-DFS
    channel, so the client link (and therefore the AP, which must share its
    channel) never lands somewhere the AP can't legally/technically start on.

    prefer_band ("a"/"bg") is the band configured in Settings. Because the AP
    and this client link share one radio and therefore one channel, the ONLY
    way to honour that setting is to pick a BSS on that band here — pinning
    the AP's band afterwards can't move it. A BSS on the requested band wins
    over a stronger one on the other band; if the network has nothing on the
    requested band, the strongest non-DFS BSS is used regardless so the link
    still comes up.

    Returns (bssid, band_of_that_bssid). bssid is None if no non-DFS BSS of
    that SSID is in range — caller should then fall back to normal (unpinned)
    association.
    """
    try:
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", iface, "scan"], capture_output=True, text=True, timeout=20)
        r = subprocess.run(["iw", "dev", iface, "scan", "dump"],
                            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None, None

        def consider(bssid, freq, ssid_seen, signal):
            nonlocal best_bssid, best_signal, best_band
            nonlocal pref_bssid, pref_signal
            if not bssid or ssid_seen != ssid:
                return
            band = _band_of_freq(freq)
            if band is None:
                return
            # DFS only exists in 5 GHz; a 2.4 GHz BSS is always AP-capable.
            # (This used to compute a channel for 5 GHz only and drop every
            # 2.4 GHz BSS as "channel is None", which is why a 2.4 GHz
            # preference could never be satisfied.)
            if band == "a":
                channel = int(round((freq - 5000) / 5))
                if channel in _DFS_CHANNELS:
                    return
            if best_signal is None or (signal is not None and signal > best_signal):
                best_bssid, best_signal, best_band = bssid, signal, band
            if prefer_band and band == prefer_band:
                if pref_signal is None or (signal is not None and signal > pref_signal):
                    pref_bssid, pref_signal = bssid, signal

        best_bssid = best_signal = best_band = None
        pref_bssid = pref_signal = None
        cur_bssid = cur_freq = cur_ssid = cur_signal = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                consider(cur_bssid, cur_freq, cur_ssid, cur_signal)
                cur_bssid = line.split()[1].split("(")[0]
                cur_freq = cur_ssid = cur_signal = None
            elif line.startswith("freq:"):
                cur_freq = float(line.split(":", 1)[1].strip())
            elif line.startswith("SSID:"):
                cur_ssid = line.split(":", 1)[1].strip()
            elif line.startswith("signal:"):
                try:
                    cur_signal = float(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    cur_signal = None
        consider(cur_bssid, cur_freq, cur_ssid, cur_signal)
        if pref_bssid:
            return pref_bssid, prefer_band
        return best_bssid, best_band
    except Exception as e:
        log.warning(f"_non_dfs_bssid_for_ssid: {e}")
        return None, None


def detect_current_wifi_network(ap_if: str) -> tuple[str, str]:
    """
    Return (ssid, psk) for whatever WiFi network `ap_if` is normally/currently
    connected to as a client, BEFORE it becomes the hotspot AP — pulled
    straight from NetworkManager's own saved connection secrets via
    `nmcli -s`, so nothing needs to be typed in or configured anywhere.
    Returns ("", "") if the interface isn't currently a WiFi client of
    anything (e.g. it's already the AP, or never connected to begin with).

    This is deliberately dynamic, not cached/hardcoded to one SSID: whatever
    network this machine happens to be joined to at connect time is what
    gets reused for the IPv6 client link, so it keeps working automatically
    if the machine moves to a different WiFi network later.
    """
    try:
        con_name_r = subprocess.run(
            ["nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", ap_if],
            capture_output=True, text=True, timeout=5,
        )
        con_name = con_name_r.stdout.strip().split(":", 1)[-1].strip()
        if not con_name or con_name == "--":
            return "", ""

        # Hard exclusion: never treat ProxyGate's own AP profile (or a
        # leftover one from a run that didn't clean up) as "the network to
        # copy credentials from" — its "SSID" is the hotspot's own name
        # (e.g. "ProxyGate"), not an upstream network with real IPv6.
        ap_con_name = load_config().get("ap_con_name", "proxygate-ap")
        if con_name == ap_con_name:
            return "", ""

        mode_r = subprocess.run(
            ["nmcli", "-t", "-f", "802-11-wireless.mode", "connection", "show", con_name],
            capture_output=True, text=True, timeout=5,
        )
        mode = mode_r.stdout.strip().split(":", 1)[-1].strip()
        if mode and mode != "infrastructure":
            # "ap", "adhoc", etc — not a normal client connection to copy
            # credentials from (infrastructure is nmcli's name for a plain
            # client-mode WiFi connection; empty is also treated as client
            # since that's nmcli's default when the mode was never set).
            return "", ""

        ssid_r = subprocess.run(
            ["nmcli", "-t", "-f", "802-11-wireless.ssid", "connection", "show", con_name],
            capture_output=True, text=True, timeout=5,
        )
        ssid = ssid_r.stdout.strip().split(":", 1)[-1].strip()
        if not ssid:
            return "", ""

        psk_r = subprocess.run(
            ["nmcli", "-s", "-t", "-f", "802-11-wireless-security.psk", "connection", "show", con_name],
            capture_output=True, text=True, timeout=5,
        )
        psk = psk_r.stdout.strip().split(":", 1)[-1].strip()
        return ssid, psk
    except Exception as e:
        log.warning(f"detect_current_wifi_network: {e}")
        return "", ""


def ensure_ipv6_client_link() -> tuple[bool, str, Optional[str], Optional[int]]:
    """
    Bring up a second virtual WiFi interface (IPV6_CLIENT_IF) on the same
    physical radio as the hotspot, joined to whatever WiFi network this
    machine is currently connected to (see detect_current_wifi_network) —
    giving this machine a real, non-tunneled IPv6 route with its own network
    identity. Fully automatic: no SSID/password to configure anywhere: it's
    pulled live from NetworkManager's own saved credentials for whatever
    network is already in use. No-op (returns True, ..., None, None) if the
    radio isn't currently a WiFi client of anything, or that network turns
    out to have no real IPv6.

    Returns (ok, msg, band, channel) — band/channel are the REAL values read
    back from the driver after a successful association (see
    _actual_channel_of), for the caller to pin the AP to.

    MUST be called BEFORE the AP exists on this radio (i.e. before
    create_nm_ap_connection()/_nmcli_ap("up")). Pre-connect scanning for the
    target SSID's channel while a second interface on the same radio is
    already transmitting as an AP does not work reliably on real hardware —
    confirmed directly: wlan-ipv6 scanned repeatedly for 25+ seconds and
    never saw a network that was verifiably on-air the whole time on the
    expected channel, because the radio's receive path was busy servicing
    the AP role. Associating first, while the radio is still a fully free
    client with nothing else running, works because there's no competing
    AP traffic — the trade-off is the AP now has to wait for the client link
    to be up before it can be created with a known-correct channel.
    """
    ap_if = resolve_ap_wifi_if()
    if not ap_if:
        return False, "no WiFi adapter found", None, None

    ssid, password = detect_current_wifi_network(ap_if)
    if not ssid:
        return True, f"{ap_if} isn't currently a WiFi client of any network — skipping IPv6 client link", None, None

    phy = _phy_for_iface(ap_if)
    if not phy:
        return False, f"could not determine phy for {ap_if}", None, None

    # Recreate the virtual interface fresh each connect — cheap, and avoids
    # inheriting a stale/wedged state from a previous run.
    subprocess.run(["ip", "link", "set", IPV6_CLIENT_IF, "down"], capture_output=True)
    subprocess.run(["iw", "dev", IPV6_CLIENT_IF, "del"], capture_output=True)
    r = subprocess.run(
        ["iw", "phy", phy, "interface", "add", IPV6_CLIENT_IF, "type", "managed"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        return False, f"could not create {IPV6_CLIENT_IF}: {r.stderr.strip()}", None, None

    subprocess.run(["nmcli", "device", "set", IPV6_CLIENT_IF, "managed", "yes"],
                    capture_output=True, timeout=5)

    # The configured band can only be honoured through the BSS chosen here:
    # the AP shares this radio and therefore this channel, so whatever band
    # the client link lands on is the band the AP gets.
    want_band = (load_config().get("ap_band") or "").strip().lower()
    if want_band not in ("a", "bg"):
        want_band = ""

    non_dfs_bssid, got_band = _non_dfs_bssid_for_ssid(
        IPV6_CLIENT_IF, ssid, prefer_band=want_band or None)
    if non_dfs_bssid:
        log.info(f"ensure_ipv6_client_link: pinning to non-DFS BSS {non_dfs_bssid} for {ssid!r} "
                  f"on band={got_band!r} (AP mode can't start on a DFS channel on this hardware)")
        if want_band and got_band and got_band != want_band:
            log.warning(
                f"ensure_ipv6_client_link: configured WiFi band {want_band!r} is not available on "
                f"{ssid!r} (nothing in range on that band), using {got_band!r} instead — the hotspot "
                f"shares this radio's channel, so it will also be on {got_band!r}")
    else:
        log.warning(f"ensure_ipv6_client_link: no non-DFS BSS of {ssid!r} in range — "
                     f"letting NM pick; AP activation may fail if it lands on a DFS channel")

    subprocess.run(["nmcli", "con", "delete", _IPV6_CLIENT_CON],
                    capture_output=True, timeout=10)
    cmd = [
        "nmcli", "con", "add",
        "type", "wifi",
        "ifname", IPV6_CLIENT_IF,
        "con-name", _IPV6_CLIENT_CON,
        "autoconnect", "no",
        "ssid", ssid,
        "ipv6.method", "auto",
    ]
    if non_dfs_bssid:
        cmd += ["802-11-wireless.bssid", non_dfs_bssid]
    if password:
        cmd += [
            "wifi-sec.key-mgmt", "wpa-psk",
            "wifi-sec.psk", password,
        ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return False, f"could not configure client connection: {(r.stdout + r.stderr).strip()}", None, None

    r = subprocess.run(["nmcli", "con", "up", _IPV6_CLIENT_CON],
                        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return False, f"could not join {ssid!r}: {(r.stdout + r.stderr).strip()}", None, None

    band, channel = _actual_channel_of(IPV6_CLIENT_IF)
    log.info(f"ensure_ipv6_client_link: associated to {ssid!r} on band={band!r} channel={channel!r}")

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _has_global_ipv6(IPV6_CLIENT_IF):
            return True, f"joined {ssid!r} on {IPV6_CLIENT_IF} — real IPv6 active", band, channel
        time.sleep(0.5)
    return False, f"joined {ssid!r} but no global IPv6 address appeared within 15s", band, channel


def teardown_ipv6_client_link() -> None:
    subprocess.run(["nmcli", "con", "down", _IPV6_CLIENT_CON], capture_output=True, timeout=10)
    subprocess.run(["nmcli", "con", "delete", _IPV6_CLIENT_CON], capture_output=True, timeout=10)
    subprocess.run(["ip", "link", "set", IPV6_CLIENT_IF, "down"], capture_output=True)
    subprocess.run(["iw", "dev", IPV6_CLIENT_IF, "del"], capture_output=True)


def _actual_channel_of(iface: str) -> tuple[Optional[str], Optional[int]]:
    """
    Read the REAL channel/band an already-associated interface landed on,
    straight from the driver (`iw dev <iface> info`) — not a pre-connect
    scan guess. Scanning from a second virtual interface while the first is
    busy transmitting as an AP is unreliable in practice on real hardware
    (confirmed: wlan-ipv6 scanned repeatedly for 25+s and never saw a
    network that was verifiably on-air on the expected channel the whole
    time) — reading back the channel AFTER a successful association sidesteps
    that problem entirely, since the association itself already proves the
    channel is right.
    """
    try:
        r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("channel "):
                # e.g. "channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz"
                parts = line.split()
                chan = int(parts[1])
                freq_mhz = int(parts[2].lstrip("("))
                band = "a" if freq_mhz > 4000 else "bg"
                return band, chan
    except Exception:
        pass
    return None, None


def _phy_for_iface(iface: str) -> Optional[str]:
    try:
        r = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("wiphy "):
                return f"phy{line.split()[1]}"
    except Exception:
        pass
    return None


# ── NM AP connection creation ─────────────────────────────────────────────────

def create_nm_ap_connection(force_band: Optional[str] = None, force_channel: Optional[int] = None) -> tuple[bool, str]:
    """
    Create (or recreate) the NM WiFi AP connection in a single nmcli call.

    Single-call creation is important: two-step (add then modify) leaves a
    window where the profile exists without a password, causing phones to fail
    WPA authentication and give up connecting.

    ipv4.gateway and ipv4.never-default are intentionally omitted — setting
    them breaks NM's internal dnsmasq and prevents DHCP from handing out IPs.

    force_band/force_channel override ap_band/config when set — used by
    _connect_worker to pin the AP to whatever channel the auto-detected
    IPv6 client link actually landed on, since the AP and the IPv6 client
    link share one physical radio and MUST use the same channel (see
    ensure_ipv6_client_link).
    """
    cfg      = load_config()
    con_name = cfg["ap_con_name"]
    ssid     = cfg["ap_ssid"]
    password = cfg["ap_password"]
    gw       = cfg["hotspot_gw"]
    wifi_if  = cfg.get("ap_wifi_if") or "*"
    want_band = cfg.get("ap_band", "").strip().lower()
    # force_band/force_channel come from the IPv6 client link, which already
    # shares this radio — its channel is a hard constraint, so it wins over
    # the configured band (ensure_ipv6_client_link steers the client link
    # toward want_band in the first place, and logs when it can't).
    band = force_band or want_band

    subprocess.run(["nmcli", "con", "delete", con_name],
                   capture_output=True, timeout=10)

    cmd = [
        "nmcli", "con", "add",
        "type",                 "wifi",
        "ifname",               wifi_if,
        "con-name",             con_name,
        "autoconnect",          "no",
        "ssid",                 ssid,
        "802-11-wireless.mode", "ap",
        "wifi-sec.key-mgmt",    "wpa-psk",
        "wifi-sec.proto",       "rsn",
        "wifi-sec.pairwise",    "CCMP",
        "wifi-sec.group",       "CCMP",
        "wifi-sec.psk",         password,
        "ipv4.method",          "shared",
        "ipv4.addresses",       f"{gw}/24",
        "ipv6.method",          "disabled",
    ]

    if force_channel:
        # The channel is the authority here: NM rejects the profile if the
        # band doesn't match the channel, so derive it from the channel
        # rather than trusting a possibly-stale band string.
        chan_band = "a" if force_channel > 14 else "bg"
        cmd += ["802-11-wireless.band", chan_band]
        cmd += ["802-11-wireless.channel", str(force_channel)]
        log.info(f"create_nm_ap_connection: pinned to band={chan_band} channel={force_channel} "
                 f"(shared with the IPv6 client link)")
    elif band in ("a", "bg"):
        cmd += ["802-11-wireless.band", band]
        if band == "bg":
            cmd += ["802-11-wireless.channel", "6"]
        log.info(f"create_nm_ap_connection: band={band} from settings "
                 f"(no IPv6 client link pinning this radio)")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

    if result.returncode != 0:
        return False, (result.stdout + result.stderr).strip()

    return True, f"AP connection '{con_name}' created (SSID: {ssid}, IP: {gw})"


# ── iptables rules ────────────────────────────────────────────────────────────

def _routing_target() -> str:
    """Return the catch-all routing target from rules.yaml: DIRECT, BLOCK, or proxy name."""
    try:
        from backend.rules import load_rules, _effective_target
        return _effective_target(load_rules())
    except Exception:
        return "DIRECT"


def _blocked_mac_set() -> set[str]:
    """MAC addresses currently kicked/banned from the hotspot (blocked_devices.yaml)."""
    try:
        from backend.rules import load_blocked_devices, blocked_mac_set
        return blocked_mac_set(load_blocked_devices())
    except Exception:
        return set()


def apply_iptables() -> tuple[bool, str]:
    """
    Apply all ProxyGate iptables/ip6tables rules — IPv4 and IPv6 in parallel,
    both redirected into the same mitmproxy instance (mitm_logger.py's
    upstream proxy layer handles both address families natively).

    All TCP from the hotspot is redirected to mitmproxy, which:
      - Intercepts and logs HTTP (full request/response).
      - Logs HTTPS via SNI, passes raw TLS through (no decryption, no CA needed).
      - Passes other TCP through as raw streams.

    Upstream proxy routing (SOCKS5/HTTP) is handled natively inside
    mitm_logger.py's asyncio.open_connection patch — every outgoing connect()
    is tunnelled transparently. No redsocks. No OUTPUT chain (that would break
    host internet).

    BLOCK mode: all hotspot TCP is dropped in FORWARD; mitmproxy still sees
    HTTP and kills those flows for logging, but never forwards them.
    """
    cfg      = load_config()
    hi       = HOTSPOT_IF
    ap_if    = resolve_ap_wifi_if()
    wan_cfg  = (cfg.get("wan_if") or "").strip()
    # A pinned wan_if is honoured only if it doesn't collide with the AP NIC —
    # a stale value saved from before a router/adapter swap (or a bad manual
    # override) must not silently re-create the same-NIC deadlock every time.
    wan      = wan_cfg if wan_cfg and wan_cfg != ap_if else detect_wan_if() or "eth0"
    gw     = cfg["hotspot_gw"]
    sub    = cfg["hotspot_subnet"]
    mp     = str(cfg["mitm_port"])
    target = _routing_target()
    block  = target == "BLOCK"

    def _r(*cmd: str) -> None:
        subprocess.run(list(cmd), capture_output=True)

    def _must(*cmd: str) -> None:
        r = subprocess.run(list(cmd), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)}\n{r.stderr.strip()}")

    try:
        _must("sysctl", "-qw", "net.ipv4.ip_forward=1")
        _r   ("sysctl", "-qw", "net.ipv4.conf.all.route_localnet=1")
        # Increase listen backlog so mitmproxy's accept queue never overflows
        # under burst traffic (prevents SYN drops that cause UDP fallback leaks).
        _r   ("sysctl", "-qw", "net.core.somaxconn=4096")
        _r   ("sysctl", "-qw", "net.ipv4.tcp_max_syn_backlog=4096")

        # IPv6 forwarding — the upstream proxy layer (mitm_logger.py) now speaks
        # native SOCKS5/HTTP CONNECT for both address families, so IPv6 TCP from
        # the hotspot is redirected into mitmproxy the same way IPv4 is, instead
        # of being unconditionally dropped. UDP (including IPv6) is still
        # dropped below — mitmproxy has no UDP proxy path for either family.
        _r   ("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")

        # ── NAT PREROUTING ────────────────────────────────────────────────────
        _r   ("iptables", "-t", "nat", "-N", "PROXYGATE_REDIRECT")
        _must("iptables", "-t", "nat", "-F", "PROXYGATE_REDIRECT")

        # Skip traffic originating from the gateway itself
        for skip in ("127.0.0.1", gw):
            _must("iptables", "-t", "nat", "-A", "PROXYGATE_REDIRECT",
                  "-s", skip, "-j", "RETURN")
        for skip in ("127.0.0.0/8", gw):
            _must("iptables", "-t", "nat", "-A", "PROXYGATE_REDIRECT",
                  "-d", skip, "-j", "RETURN")

        # DNS → NM's internal dnsmasq on the gateway
        for proto in ("udp", "tcp"):
            _must("iptables", "-t", "nat", "-A", "PROXYGATE_REDIRECT",
                  "-i", hi, "-p", proto, "--dport", "53",
                  "-j", "DNAT", "--to-destination", f"{gw}:53")

        if not block:
            # ALL TCP from hotspot → mitmproxy.
            # Port 80:  HTTP full interception + logging.
            # Port 443: HTTPS — SNI logging, raw TLS passthrough.
            # Other TCP: raw passthrough (logged as TCP flows).
            # Proxychains handles upstream proxy routing for all of the above.
            _must("iptables", "-t", "nat", "-A", "PROXYGATE_REDIRECT",
                  "-i", hi, "-p", "tcp",
                  "-j", "REDIRECT", "--to-port", mp)

        _r   ("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "PROXYGATE_REDIRECT")
        _must("iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PROXYGATE_REDIRECT")

        # ── NAT POSTROUTING ───────────────────────────────────────────────────
        _r   ("iptables", "-t", "nat", "-N", "PROXYGATE_MASQ")
        _must("iptables", "-t", "nat", "-F", "PROXYGATE_MASQ")
        _must("iptables", "-t", "nat", "-A", "PROXYGATE_MASQ",
              "-s", sub, "-o", wan, "-j", "MASQUERADE")
        _r   ("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "PROXYGATE_MASQ")
        _must("iptables", "-t", "nat", "-A", "POSTROUTING",  "-j", "PROXYGATE_MASQ")

        # ── FILTER FORWARD ────────────────────────────────────────────────────
        _r   ("iptables", "-N", "PROXYGATE_FORWARD")
        _must("iptables", "-F", "PROXYGATE_FORWARD")

        if block:
            # Drop all forwarded traffic from hotspot (REDIRECT'd TCP goes to
            # INPUT/mitmproxy and is killed there; FORWARD catches everything else).
            _must("iptables", "-A", "PROXYGATE_FORWARD",
                  "-i", hi, "-j", "DROP")
        else:
            # Log UDP/443 specifically (almost always a QUIC/HTTP3 attempt)
            # before it hits the blanket DROP below — purely for traffic-table
            # visibility (see QuicLogTailer in mitm_logger.py), not a policy
            # change: the packet is still dropped either way, LOG doesn't
            # terminate the chain. A distinct prefix keeps this grep-able
            # without picking up the kernel's routine noise or other dropped
            # UDP (DNS-over-UDP to a non-GW target, etc.) that we don't want
            # surfaced as "QUIC" in the UI.
            _r   ("iptables", "-A", "PROXYGATE_FORWARD",
                  "-i", hi, "-p", "udp", "--dport", "443",
                  "-j", "LOG", "--log-prefix", "PGQUIC: ", "--log-level", "6")
            # Drop ALL UDP from hotspot — UDP cannot go through mitmproxy so
            # any UDP that reaches FORWARD would bypass the proxy entirely.
            # This covers QUIC/HTTP3 (UDP 443), DNS-over-UDP to non-GW (already
            # DNAT'd above), and any other UDP. DNS still works via the DNAT rule.
            _must("iptables", "-A", "PROXYGATE_FORWARD",
                  "-i", hi, "-p", "udp", "-j", "DROP")
            _must("iptables", "-A", "PROXYGATE_FORWARD",
                  "-i", hi, "-o", wan, "-j", "ACCEPT")
            _must("iptables", "-A", "PROXYGATE_FORWARD",
                  "-i", wan, "-o", hi, "-m", "state",
                  "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

        _r   ("iptables", "-D", "FORWARD", "-j", "PROXYGATE_FORWARD")
        _must("iptables", "-I", "FORWARD", "1", "-j", "PROXYGATE_FORWARD")

        # ── Blocked devices (status dropdown's kick/ban list) ─────────────────
        # A blocked MAC is dropped in BOTH filter chains: INPUT (so it can't
        # even reach the gateway itself — DNS, DHCP renewal, the web UI) and
        # FORWARD (so it gets no internet even if it somehow still has an
        # IP). `DROP` is only a valid verdict in the filter table — NOT nat,
        # which is why this isn't done in PROXYGATE_REDIRECT above. Combined
        # with the immediate `iw station del` kick (services.py's
        # block_device()), a blocked device is disconnected right away AND
        # gets nothing even if it immediately reassociates.
        #
        # Inserted at FORWARD position 1 AFTER PROXYGATE_FORWARD above (not
        # before) so it ends up evaluated FIRST — two "-I FORWARD 1" inserts
        # in sequence means whichever runs second ends up actually at
        # position 1, pushing the other to position 2.
        _r   ("iptables", "-N", "PROXYGATE_BLOCKDEV")
        _must("iptables", "-F", "PROXYGATE_BLOCKDEV")
        for mac in _blocked_mac_set():
            # _r, not _must: a single unusable MAC must not abort the entire
            # iptables setup. blocked_mac_set() already filters malformed
            # entries, but this is the call that actually decides whether the
            # gateway comes up at all — failing one DROP rule costs one
            # device's block, failing the whole chain costs the hotspot.
            _r("iptables", "-A", "PROXYGATE_BLOCKDEV",
               "-i", hi, "-m", "mac", "--mac-source", mac, "-j", "DROP")
        _r   ("iptables", "-D", "INPUT",   "-j", "PROXYGATE_BLOCKDEV")
        _must("iptables", "-I", "INPUT",   "1", "-j", "PROXYGATE_BLOCKDEV")
        _r   ("iptables", "-D", "FORWARD", "-j", "PROXYGATE_BLOCKDEV")
        _must("iptables", "-I", "FORWARD", "1", "-j", "PROXYGATE_BLOCKDEV")

        # ── IPv6 mirror of the above ───────────────────────────────────────────
        # The hotspot's own DHCP (NM "shared" mode) is IPv4-only, but a device
        # can still pick up an IPv6 address via SLAAC/router-advertisement if
        # the WAN side provides one — so IPv6 traffic from the hotspot is a
        # real possibility even though ProxyGate doesn't manage IPv6 addressing
        # itself. Matched by interface (not subnet, since there's no IPv6
        # hotspot_subnet equivalent in config) exactly like PROXYGATE_FORWARD's
        # interface-based rules above.
        # No IPv6 DNS DNAT here: ProxyGate's hotspot (NM "shared" mode) only
        # runs an IPv4 dnsmasq — there is no IPv6 gateway address to redirect
        # DNS-over-IPv6 to. Devices resolve names over the IPv4 DNS path
        # (already DNAT'd above) regardless of which family they browse over.
        _r   ("ip6tables", "-t", "nat", "-N", "PROXYGATE_REDIRECT6")
        _must("ip6tables", "-t", "nat", "-F", "PROXYGATE_REDIRECT6")
        _must("ip6tables", "-t", "nat", "-A", "PROXYGATE_REDIRECT6",
              "-s", "::1", "-j", "RETURN")
        if not block:
            _must("ip6tables", "-t", "nat", "-A", "PROXYGATE_REDIRECT6",
                  "-i", hi, "-p", "tcp",
                  "-j", "REDIRECT", "--to-port", mp)
        _r   ("ip6tables", "-t", "nat", "-D", "PREROUTING", "-j", "PROXYGATE_REDIRECT6")
        _must("ip6tables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PROXYGATE_REDIRECT6")

        _r   ("ip6tables", "-t", "nat", "-N", "PROXYGATE_MASQ6")
        _must("ip6tables", "-t", "nat", "-F", "PROXYGATE_MASQ6")
        _must("ip6tables", "-t", "nat", "-A", "PROXYGATE_MASQ6",
              "-i", hi, "-o", wan, "-j", "MASQUERADE")
        _r   ("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-j", "PROXYGATE_MASQ6")
        _must("ip6tables", "-t", "nat", "-A", "POSTROUTING",  "-j", "PROXYGATE_MASQ6")

        _r   ("ip6tables", "-N", "PROXYGATE_FORWARD6")
        _must("ip6tables", "-F", "PROXYGATE_FORWARD6")
        if block:
            _must("ip6tables", "-A", "PROXYGATE_FORWARD6", "-i", hi, "-j", "DROP")
        else:
            # Same UDP-drop rationale as the IPv4 FORWARD chain — mitmproxy has
            # no UDP proxy path for IPv6 either, so QUIC/HTTP3 must be blocked
            # here rather than allowed to bypass the proxy over IPv6.
            _must("ip6tables", "-A", "PROXYGATE_FORWARD6",
                  "-i", hi, "-p", "udp", "-j", "DROP")
            _must("ip6tables", "-A", "PROXYGATE_FORWARD6",
                  "-i", hi, "-o", wan, "-j", "ACCEPT")
            _must("ip6tables", "-A", "PROXYGATE_FORWARD6",
                  "-i", wan, "-o", hi, "-m", "state",
                  "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
        _r   ("ip6tables", "-D", "FORWARD", "-j", "PROXYGATE_FORWARD6")
        _must("ip6tables", "-I", "FORWARD", "1", "-j", "PROXYGATE_FORWARD6")

        # Kill all existing conntrack entries from the hotspot subnet.
        # This forces HTTP/2 keep-alive and any pre-existing direct TCP
        # connections to reconnect, hitting the REDIRECT rule immediately.
        _r("conntrack", "-D", "-s", sub)
        _r("conntrack", "-D", "-d", sub)

        return True, f"iptables applied (mode: {target})"

    except RuntimeError as e:
        return False, str(e)
    except Exception as e:
        return False, f"iptables error: {e}"


def flush_iptables() -> tuple[bool, str]:
    """
    Remove every PROXYGATE_* iptables rule and chain.
    Safe to call even when rules don't exist.
    Restores ip_forward=0 so the host stops acting as a router.
    """
    def _r(*cmd: str) -> None:
        subprocess.run(list(cmd), capture_output=True)

    _r("iptables", "-t", "nat", "-D", "PREROUTING",  "-j", "PROXYGATE_REDIRECT")
    _r("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "PROXYGATE_MASQ")
    _r("iptables",             "-D", "FORWARD",      "-j", "PROXYGATE_FORWARD")
    _r("iptables",             "-D", "INPUT",        "-j", "PROXYGATE_BLOCKDEV")
    _r("iptables",             "-D", "FORWARD",      "-j", "PROXYGATE_BLOCKDEV")

    # Clean up legacy chains from older versions just in case
    _r("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "PROXYGATE_OUTPUT")

    for chain in ("PROXYGATE_REDIRECT", "PROXYGATE_MASQ", "PROXYGATE_OUTPUT"):
        _r("iptables", "-t", "nat", "-F", chain)
        _r("iptables", "-t", "nat", "-X", chain)

    _r("iptables", "-F", "PROXYGATE_FORWARD")
    _r("iptables", "-X", "PROXYGATE_FORWARD")
    _r("iptables", "-F", "PROXYGATE_BLOCKDEV")
    _r("iptables", "-X", "PROXYGATE_BLOCKDEV")

    # IPv6 mirror
    _r("ip6tables", "-t", "nat", "-D", "PREROUTING",  "-j", "PROXYGATE_REDIRECT6")
    _r("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-j", "PROXYGATE_MASQ6")
    _r("ip6tables",             "-D", "FORWARD",      "-j", "PROXYGATE_FORWARD6")
    for chain in ("PROXYGATE_REDIRECT6", "PROXYGATE_MASQ6"):
        _r("ip6tables", "-t", "nat", "-F", chain)
        _r("ip6tables", "-t", "nat", "-X", chain)
    _r("ip6tables", "-F", "PROXYGATE_FORWARD6")
    _r("ip6tables", "-X", "PROXYGATE_FORWARD6")

    # Clean up the old unconditional-DROP rule from before IPv6 was supported,
    # in case this host still has it from a previous ProxyGate version.
    _r("ip6tables", "-D", "FORWARD", "-i", HOTSPOT_IF, "-j", "DROP")

    _r("sysctl", "-qw", "net.ipv4.ip_forward=0")
    _r("sysctl", "-qw", "net.ipv6.conf.all.forwarding=0")

    # Flush conntrack so the phone reconnects fresh after proxy is off
    cfg = load_config()
    sub = cfg.get("hotspot_subnet", "192.168.100.0/24")
    _r("conntrack", "-D", "-s", sub)
    _r("conntrack", "-D", "-d", sub)

    return True, "iptables rules removed"


# ── mitmproxy subprocess ──────────────────────────────────────────────────────

@dataclass
class MitmproxyManager:
    _process: Optional[subprocess.Popen] = field(default=None, repr=False)
    _lock:    threading.Lock             = field(default_factory=threading.Lock, repr=False)

    def start(self) -> tuple[bool, str]:
        with self._lock:
            if self.is_running():
                return True, "already running"
            # Kill any orphaned mitmdump from a previous session so the port is free.
            self._kill_orphans()
            ok, msg = self._launch()
        if ok:
            self._start_watchdog()
        return ok, msg

    @staticmethod
    def _kill_orphans() -> None:
        """Kill any mitmdump process not owned by this manager."""
        subprocess.run(["pkill", "-f", "mitmdump"], capture_output=True)
        time.sleep(0.8)   # allow the port to release before re-binding

    def _launch(self) -> tuple[bool, str]:
        """Must be called with _lock held."""
        cfg = load_config()
        venv_bin     = os.path.dirname(os.path.abspath(sys.executable))
        mitmdump_bin = os.path.join(venv_bin, "mitmdump")
        if not os.path.isfile(mitmdump_bin):
            mitmdump_bin = shutil.which("mitmdump") or "mitmdump"

        cmd = [
            mitmdump_bin,
            "--mode",        "transparent",
            "--listen-port", str(cfg["mitm_port"]),
            "-s",            ADDON_PATH,
            "--ssl-insecure",
            "--set",         "block_global=false",
            "--set",         "connection_strategy=lazy",
            "--set",         "http2=false",
            "--set",         "listen_queue=4096",
        ]

        try:
            _log_path = "/tmp/proxygate-mitm.log"
            _log_fh   = open(_log_path, "a")
            self._process = subprocess.Popen(
                cmd,
                stdout=_log_fh,
                stderr=_log_fh,
            )
            # Wait up to 2 s — if process exits immediately it failed to start
            try:
                self._process.wait(timeout=2)
                self._process = None
                return False, f"mitmdump exited immediately — check {_log_path}"
            except subprocess.TimeoutExpired:
                pass  # still running — good
            return True, f"started (pid {self._process.pid})"
        except FileNotFoundError:
            return False, f"mitmdump not found at {mitmdump_bin}"
        except Exception as e:
            return False, str(e)

    def _start_watchdog(self) -> None:
        t = threading.Thread(target=self._watchdog, daemon=True, name="mitm-watchdog")
        t.start()

    def _watchdog(self) -> None:
        while True:
            time.sleep(5)
            # Check if process died without holding the lock during the relaunch sleep
            with self._lock:
                if self._process is None:
                    return
                dead = self._process.poll() is not None
                if dead:
                    self._process = None
            if dead:
                with self._lock:
                    ok, _ = self._launch()
                if ok:
                    continue
                return

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            if not self._process:
                return True, "not running"
            try:
                self._process.terminate()
                self._process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self._process.kill()
            finally:
                self._process = None
            return True, "stopped"

    def restart(self) -> tuple[bool, str]:
        self.stop()
        time.sleep(0.5)
        return self.start()

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def status(self) -> str:
        return "running" if self.is_running() else "stopped"

    def pid(self) -> Optional[int]:
        return self._process.pid if self.is_running() else None


mitm = MitmproxyManager()


# ── Gateway state machine ─────────────────────────────────────────────────────

class GatewayState(enum.Enum):
    IDLE          = "idle"
    CONNECTING    = "connecting"
    CONNECTED     = "connected"
    DISCONNECTING = "disconnecting"
    ERROR         = "error"


_gw_state: GatewayState   = GatewayState.IDLE
_gw_msg:   str             = ""
_gw_lock:  threading.Lock  = threading.Lock()


def get_gateway_state() -> tuple[GatewayState, str]:
    with _gw_lock:
        return _gw_state, _gw_msg


def _set_gw(state: GatewayState, msg: str = "") -> None:
    global _gw_state, _gw_msg
    with _gw_lock:
        _gw_state = state
        _gw_msg   = msg


# ── Connect / disconnect ──────────────────────────────────────────────────────

def connect_gateway(on_done=None) -> None:
    _set_gw(GatewayState.CONNECTING, "Starting…")
    t = threading.Thread(
        target=_connect_worker, args=(on_done,),
        daemon=True, name="pg-connect",
    )
    t.start()


def disconnect_gateway(on_done=None) -> None:
    _set_gw(GatewayState.DISCONNECTING, "Stopping…")
    t = threading.Thread(
        target=_disconnect_worker, args=(on_done,),
        daemon=True, name="pg-disconnect",
    )
    t.start()


def _preflight_check() -> Optional[str]:
    """
    Return an error message if connecting would be doomed, or None if OK.

    Catches the one class of misconfiguration that otherwise hangs
    indefinitely instead of failing: the WAN (egress) interface and the
    WiFi AP interface resolving to the *same* physical NIC. That happens
    when a laptop's only WiFi card still holds a lower-metric default route
    than Ethernet (e.g. right after a router swap) — detect_wan_if() already
    excludes the AP interface when possible, but if literally no other
    default-routed interface exists, there is nothing left to fall back to
    and connecting would try to make one NIC broadcast the hotspot and
    masquerade traffic out through itself at the same time.
    """
    ap_if = resolve_ap_wifi_if()
    if not ap_if:
        return "No WiFi adapter found to host the hotspot. Plug in / enable a WiFi card."

    cfg = load_config()
    wan_cfg = (cfg.get("wan_if") or "").strip()
    wan = wan_cfg if wan_cfg and wan_cfg != ap_if else detect_wan_if()

    if not wan:
        return (
            f"No usable WAN interface found — every default route currently goes "
            f"through '{ap_if}', which is also the WiFi adapter the hotspot needs. "
            f"Connect this machine to the internet via Ethernet (or a second WiFi "
            f"adapter) before starting the gateway."
        )
    if wan == ap_if:
        return (
            f"WAN and hotspot would both use '{ap_if}' — refusing to connect. "
            f"Set the WAN interface explicitly in Settings, or free up a "
            f"separate interface for the hotspot."
        )
    return None


def _connect_worker(on_done) -> None:
    global HOTSPOT_IF
    try:
        _set_gw(GatewayState.CONNECTING, "Checking network interfaces…")
        preflight_err = _preflight_check()
        if preflight_err:
            _set_gw(GatewayState.ERROR, preflight_err)
            if on_done: on_done(False, preflight_err)
            return

        # Detect + join whatever WiFi network this machine is already on,
        # BEFORE the radio becomes the AP — see ensure_ipv6_client_link's
        # docstring for why this has to happen first and fully automatically
        # (no SSID/password configured anywhere; pulled live from whatever
        # network is currently active). With the radio still fully free (no
        # AP yet), the client link can associate normally, and its REAL
        # landed-on channel is read back afterward to pin the AP to.
        _set_gw(GatewayState.CONNECTING, "Checking current network for IPv6…")
        force_band = force_channel = None
        ipv6_ok, ipv6_msg, force_band, force_channel = ensure_ipv6_client_link()
        if ipv6_ok and force_channel:
            _set_gw(GatewayState.CONNECTING, f"IPv6 available — creating helper network ({ipv6_msg})")
            log.info(f"IPv6 client link: {ipv6_msg}")
        elif ipv6_ok:
            _set_gw(GatewayState.CONNECTING, "Current network has no IPv6 — skipping IPv6 helper network")
            log.info(f"IPv6 client link: {ipv6_msg}")
        else:
            _set_gw(GatewayState.CONNECTING, "IPv6 helper network setup failed — continuing on IPv4 only")
            log.warning(f"IPv6 client link: {ipv6_msg}")

        _set_gw(GatewayState.CONNECTING, "Creating hotspot connection…")
        ok, msg = create_nm_ap_connection(force_band=force_band, force_channel=force_channel)
        if not ok:
            _set_gw(GatewayState.ERROR, f"AP config: {msg}")
            if on_done: on_done(False, msg)
            return

        _set_gw(GatewayState.CONNECTING, "Starting WiFi hotspot…")
        ok, msg = _nmcli_ap("up")
        if not ok:
            _set_gw(GatewayState.ERROR, f"Hotspot: {msg}")
            if on_done: on_done(False, msg)
            return

        # Poll until the AP interface has an IPv4 address (up to 10s).
        # We also re-query the interface name here because _get_ap_if() may have
        # returned the "ap0" fallback before NM had assigned the real name.
        _set_gw(GatewayState.CONNECTING, "Waiting for hotspot interface…")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            iface = _get_ap_if()
            if iface and iface != "ap0":
                HOTSPOT_IF = iface
            r = subprocess.run(
                ["ip", "-4", "addr", "show", HOTSPOT_IF],
                capture_output=True, text=True, timeout=5,
            )
            if "inet " in r.stdout:
                break
            time.sleep(0.75)
        # Extra second for NM's dnsmasq to bind its socket
        time.sleep(1)

        _set_gw(GatewayState.CONNECTING, "Applying traffic rules…")
        ok, msg = apply_iptables()
        if not ok:
            _nmcli_ap("down")
            _set_gw(GatewayState.ERROR, f"iptables: {msg}")
            if on_done: on_done(False, msg)
            return

        _set_gw(GatewayState.CONNECTING, "Writing proxy config…")
        from backend.rules import reload_rules
        rs_ok, rs_msg = reload_rules()
        if not rs_ok:
            log.warning(f"reload_rules: {rs_msg}")

        _set_gw(GatewayState.CONNECTING, "Starting mitmproxy…")
        ok, msg = mitm.start()
        if not ok:
            _set_gw(GatewayState.ERROR, f"mitmproxy: {msg}")
            if on_done: on_done(False, msg)
            return

        _set_gw(GatewayState.CONNECTED, "Gateway active")
        _start_iptables_watchdog()
        if on_done: on_done(True, "Connected")

    except Exception as e:
        _set_gw(GatewayState.ERROR, str(e))
        if on_done: on_done(False, str(e))


def _disconnect_worker(on_done) -> None:
    try:
        _set_gw(GatewayState.DISCONNECTING, "Stopping mitmproxy…")
        mitm.stop()

        _set_gw(GatewayState.DISCONNECTING, "Disconnecting IPv6 client link…")
        teardown_ipv6_client_link()

        _set_gw(GatewayState.DISCONNECTING, "Stopping WiFi hotspot…")
        _nmcli_ap("down")

        _set_gw(GatewayState.DISCONNECTING, "Removing traffic rules…")
        flush_iptables()

        _set_gw(GatewayState.IDLE, "")
        if on_done: on_done(True, "Disconnected")

    except Exception as e:
        _set_gw(GatewayState.ERROR, str(e))
        if on_done: on_done(False, str(e))


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def _ensure_rules_yaml() -> None:
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
    if not os.path.exists(RULES_PATH):
        with open(RULES_PATH, "w") as f:
            f.write(_DEFAULT_RULES_YAML)
        from backend.rules import _restore_owner
        _restore_owner(RULES_PATH)



def _iptables_chain_exists() -> bool:
    """Return True if our NAT chain is still in place (quick health check)."""
    # Bounded and non-raising: this runs on the watchdog's 5s timer, whose
    # loop has no exception handling of its own — an escaping error would
    # kill the watchdog thread for the rest of the process's life, silently
    # ending iptables self-healing. A wedged iptables (xtables lock
    # contention) is reported as "chain missing", and the next tick retries.
    try:
        r = subprocess.run(
            ["iptables", "-t", "nat", "-L", "PROXYGATE_REDIRECT", "-n"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0
    except Exception as e:
        log.warning(f"iptables chain check failed: {e}")
        return False


def _active_masq_out_if() -> Optional[str]:
    """Return the -o interface currently baked into PROXYGATE_MASQ, if any."""
    try:
        r = subprocess.run(
            ["iptables", "-t", "nat", "-S", "PROXYGATE_MASQ"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            if "-o" in parts:
                idx = parts.index("-o")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    return None


def _iptables_watchdog() -> None:
    """
    Every 5s while connected: reapply iptables if the chains were cleared by
    an external process, OR if the WAN interface has changed since the rules
    were last applied (cable moved to a different router, WiFi reconnected
    on a different NIC, etc). The chain existing is not enough on its own —
    a MASQUERADE rule baked with the wrong -o interface silently blackholes
    traffic instead of erroring, so this actively compares what's live in
    iptables against what detect_wan_if() resolves right now.
    """
    while True:
        time.sleep(5)
        # The whole body is guarded: this thread is the only thing that
        # re-heals iptables, and apply_iptables() raises RuntimeError from
        # _must() whenever any single command fails. Letting that escape
        # would end the thread for the lifetime of the process, silently
        # disabling self-healing — exactly when it's most needed. Log and
        # retry on the next tick instead.
        try:
            state, _ = get_gateway_state()
            if state != GatewayState.CONNECTED:
                return

            if not _iptables_chain_exists():
                log.warning("PROXYGATE_REDIRECT chain missing — reapplying iptables.")
                apply_iptables()
                continue

            cfg = load_config()
            ap_if = resolve_ap_wifi_if()
            wan_cfg = (cfg.get("wan_if") or "").strip()
            expected_wan = wan_cfg if wan_cfg and wan_cfg != ap_if else detect_wan_if()
            active_wan = _active_masq_out_if()
            if expected_wan and active_wan and expected_wan != active_wan:
                log.warning(
                    f"WAN interface changed ({active_wan} -> {expected_wan}) — "
                    f"reapplying iptables so traffic routes out the current one."
                )
                apply_iptables()
        except Exception as e:
            log.error(f"iptables watchdog tick failed ({e}) — retrying in 5s")


def _start_iptables_watchdog() -> None:
    t = threading.Thread(target=_iptables_watchdog, daemon=True,
                         name="iptables-watchdog")
    t.start()


def _clear_stale_network_state() -> None:
    """
    Clean up traces of an unclean shutdown (crash, kill -9, power loss) where
    the hotspot AP is NOT running but leftover PROXYGATE_* iptables chains or
    net.ipv4.ip_forward=1 survived anyway — flush_iptables() never got to run.

    Only acts when the AP is confirmed down; if it's up, _detect_initial_state()
    takes the "gateway was already active" path instead and this must not
    interfere with that traffic.
    """
    if _nmcli_ap_status() == "running":
        return
    if not (_iptables_chain_exists() or _read_ip_forward()):
        return
    log.warning(
        "Found leftover ProxyGate network state with no active hotspot "
        "(likely an unclean shutdown) — flushing it before startup."
    )
    flush_iptables()


def _read_ip_forward() -> bool:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


def _detect_initial_state() -> None:
    global HOTSPOT_IF
    if _nmcli_ap_status() == "running":
        HOTSPOT_IF = _get_ap_if()
        # Hotspot was already up (e.g. app restarted without disconnect).
        # Reapply iptables — they don't survive reboots or Docker iptables flushes.
        apply_iptables()
        _set_gw(GatewayState.CONNECTED, "Gateway active")
        _start_iptables_watchdog()
    else:
        _clear_stale_network_state()


def bootstrap() -> None:
    """
    Called once at app startup — creates dirs and config files only.
    No network changes beyond clearing state proven stale from a previous
    unclean shutdown; connect_gateway() / disconnect_gateway() own everything else.
    """
    from backend.rules import _restore_owner
    for d in (
        os.path.join(PROJECT_ROOT, "etc/proxygate"),
        os.path.join(PROJECT_ROOT, "var/lib/proxygate"),
        os.path.join(PROJECT_ROOT, "var/log/proxygate"),
    ):
        os.makedirs(d, exist_ok=True)
        _restore_owner(d, is_dir=True)

    _ensure_rules_yaml()

    if not os.path.exists(CONFIG_PATH):
        save_config(dict(_DEFAULT_CONFIG))

    _detect_initial_state()


# ── Status helpers ────────────────────────────────────────────────────────────

def check_all_services() -> dict[str, str]:
    return {
        "hostapd":       service_status("hostapd"),
        "dnsmasq":       service_status("dnsmasq"),
        "mitmproxy":     mitm.status(),
    }


def get_interface_ip(iface: str) -> str:
    """Return the first IPv4 address bound to `iface`, or '—' if it has none
    (down, not yet configured, or doesn't exist)."""
    if not iface:
        return "—"
    try:
        r = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "—"


def get_hotspot_ip() -> str:
    return get_interface_ip(HOTSPOT_IF)


def get_connected_devices() -> int:
    try:
        r = subprocess.run(
            ["iw", "dev", HOTSPOT_IF, "station", "dump"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.count("Station ")
    except Exception:
        pass
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


# ── Device identity (IP -> MAC) ───────────────────────────────────────────────
#
# Used to key the TLS-decrypt allowlist by MAC instead of IP — a MAC survives
# a DHCP lease renewal, so a device flagged once in the UI stays flagged even
# if its IP changes on the hotspot subnet.

_OUI_PATHS = (
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/misc/oui.txt",
)

# Parsed lazily on first use and cached — the file is ~6MB, so it's read
# once per process rather than on every device-list poll.
_oui_cache: Optional[dict[str, str]] = None


def _load_oui() -> dict[str, str]:
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    table: dict[str, str] = {}
    for path in _OUI_PATHS:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    # "10-E9-92   (hex)\t\tINGRAM MICRO SERVICES"
                    if "(hex)" not in line:
                        continue
                    prefix, _, vendor = line.partition("(hex)")
                    prefix = prefix.strip().replace("-", ":").lower()
                    vendor = vendor.strip()
                    if len(prefix) == 8 and vendor:
                        table[prefix] = vendor
            if table:
                break
        except Exception:
            continue
    _oui_cache = table
    return table


def _mac_vendor(mac: str) -> Optional[str]:
    """
    Vendor name for a MAC's OUI prefix, or None.

    Returns None for locally-administered addresses (the second-least
    significant bit of the first octet is set) — that's MAC randomization,
    which phones do by default on unknown networks. Those bytes are random,
    so any OUI "match" would be meaningless rather than merely missing.
    """
    parts = mac.split(":")
    if len(parts) < 3:
        return None
    try:
        first = int(parts[0], 16)
    except ValueError:
        return None
    if first & 0x02:
        return None
    vendor = _load_oui().get(":".join(parts[:3]).lower())
    if not vendor:
        return None
    # The IEEE file shouts every name in caps; title-case the shouty ones
    # but leave mixed-case entries ("Cyklop Fastjet…") alone.
    return vendor.title() if vendor.isupper() else vendor


def _lease_file_candidates() -> list[str]:
    """
    Where the hotspot's DHCP leases might live, best match first.

    NetworkManager's shared-mode dnsmasq writes per-interface to
    /var/lib/NetworkManager/dnsmasq-<iface>.leases — NOT to
    /var/lib/misc/dnsmasq.leases, which is a system-wide dnsmasq's default
    and simply doesn't exist on an NM-managed hotspot. Only the last of
    these was being read, so leases (and therefore every device hostname)
    were never found on this setup.
    """
    iface = current_hotspot_if()
    paths = []
    if iface:
        paths.append(f"/var/lib/NetworkManager/dnsmasq-{iface}.leases")
    paths.append("/var/lib/misc/dnsmasq.leases")
    return paths


def _read_leases() -> list[tuple[str, str, Optional[str]]]:
    """
    Parse the hotspot's DHCP lease file into (mac, ip, hostname) tuples.
    dnsmasq writes "*" for a client that sent no hostname; that becomes None.
    """
    for path in _lease_file_candidates():
        rows: list[tuple[str, str, Optional[str]]] = []
        try:
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    # format: <expiry> <mac> <ip> <hostname> <client-id>
                    if len(parts) >= 4:
                        mac, ip, hostname = parts[1].lower(), parts[2], parts[3]
                        rows.append((mac, ip, None if hostname == "*" else hostname))
                    elif len(parts) >= 3:
                        rows.append((parts[1].lower(), parts[2], None))
        except Exception:
            continue
        if rows:
            return rows
    return []


def _dnsmasq_leases() -> dict[str, str]:
    """Return {ip: mac} from NM's internal dnsmasq lease file (hotspot's DHCP)."""
    return {ip: mac for mac, ip, _ in _read_leases()}


def current_hotspot_if() -> str:
    """
    The live hotspot interface name, re-resolving it if the cached
    HOTSPOT_IF is stale.

    HOTSPOT_IF is only assigned when THIS process brings the AP up
    (_nmcli_ap) or detects it at startup (_detect_initial_state). If the AP
    was already running and that startup detection didn't land — the web
    UI restarted on its own, or NM hadn't finished activating yet — the
    module default "ap0" stays, and every command scoped to `dev ap0`
    fails with "Cannot find device". That silently emptied the hotspot
    device list, since the failure is swallowed as an exception.
    """
    global HOTSPOT_IF
    if HOTSPOT_IF and HOTSPOT_IF != "ap0":
        return HOTSPOT_IF
    resolved = _get_ap_if()
    if resolved and resolved != "ap0":
        HOTSPOT_IF = resolved
    return HOTSPOT_IF


def _neighbor_table() -> dict[str, str]:
    """Return {ip: mac} from the kernel's IPv4 neighbor (ARP) table, scoped to
    the hotspot interface only — as a fallback for devices dnsmasq hasn't
    leased directly (e.g. static IP). Unscoped `ip neigh show` dumps every
    interface's ARP table (host LAN, Docker bridges, etc.), which would leak
    unrelated neighbors (e.g. a Docker container's gateway) into the hotspot
    device list."""
    neighbors: dict[str, str] = {}
    try:
        r = subprocess.run(
            ["ip", "-4", "neigh", "show", "dev", current_hotspot_if()],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            parts = line.split()
            # Scoped to an interface, `ip neigh show dev X` omits the "dev X"
            # field its unscoped form prints, so the line is just
            # "<ip> lladdr <mac> <state>". Parse off "lladdr" rather than a
            # fixed field count, which handles both shapes.
            if "lladdr" not in parts:
                continue
            idx = parts.index("lladdr")
            if idx + 1 >= len(parts):
                continue
            # FAILED/INCOMPLETE entries are stale: the device is gone but the
            # kernel keeps the row around for a while.
            if "FAILED" in parts or "INCOMPLETE" in parts:
                continue
            neighbors[parts[0]] = parts[idx + 1].lower()
    except Exception:
        pass
    return neighbors


def resolve_mac(ip: str) -> Optional[str]:
    """Best-effort IP -> MAC lookup on the hotspot subnet: dnsmasq leases
    first (authoritative for DHCP'd devices), then the ARP/neighbor table."""
    mac = _dnsmasq_leases().get(ip)
    if mac:
        return mac
    return _neighbor_table().get(ip)


def list_hotspot_devices() -> list[dict]:
    """
    Return every device currently known on the hotspot subnet, merging
    dnsmasq leases (has hostname) with the live neighbor table (catches
    devices dnsmasq hasn't necessarily leased itself, e.g. right after
    reconnecting). Used by the web UI's device picker for the decrypt
    allowlist — the source of truth for the allowlist itself is
    devices.yaml (backend/rules.py), this is just "what's out there".

    Filtered to the configured hotspot_subnet — /var/lib/misc/dnsmasq.leases
    can be shared by more than just NM's hotspot dnsmasq instance on some
    setups, and the neighbor table (see _neighbor_table()) is host-wide by
    nature, so without this a Docker bridge peer or the host's own LAN
    gateway can otherwise show up looking like a connected hotspot client.
    """
    try:
        subnet = ipaddress.ip_network(load_config()["hotspot_subnet"], strict=False)
    except (ValueError, KeyError):
        subnet = None

    def _in_subnet(ip: str) -> bool:
        if subnet is None:
            return True
        try:
            return ipaddress.ip_address(ip) in subnet
        except ValueError:
            return False

    seen: dict[str, dict] = {}
    for mac, ip, hostname in _read_leases():
        if _in_subnet(ip):
            seen[mac] = {"mac": mac, "ip": ip, "hostname": hostname}
    for ip, mac in _neighbor_table().items():
        if _in_subnet(ip):
            seen.setdefault(mac, {"mac": mac, "ip": ip, "hostname": None})

    # A device that never sent a DHCP hostname still has a MAC, whose OUI
    # names the vendor ("Apple", "Samsung") — far easier to pick out of a
    # list than a bare MAC.
    for dev in seen.values():
        dev["vendor"] = _mac_vendor(dev["mac"])
        dev["display_name"] = dev["hostname"] or dev["vendor"] or dev["ip"]

    return sorted(seen.values(), key=lambda d: d["ip"])


def kick_device(mac: str) -> None:
    """
    Immediately deauthenticate `mac` from the hotspot radio (`iw station
    del`) — an instant disconnect, separate from the persistent iptables
    block in apply_iptables()/PROXYGATE_BLOCKDEV. Used both by block_device()
    (kick + ban) and standalone (kick without banning, if ever wanted) — best
    effort: if the device isn't currently associated, `iw` just reports
    nothing to delete, which is fine, not an error.
    """
    subprocess.run(["iw", "dev", HOTSPOT_IF, "station", "del", mac],
                    capture_output=True, timeout=5)


def block_device(mac: str, label: str = "") -> tuple[bool, str]:
    """
    Kick `mac` off the hotspot right now AND ban it from reconnecting —
    persisted to blocked_devices.yaml, enforced by apply_iptables()'s
    PROXYGATE_BLOCKDEV chain (INPUT + FORWARD) on every future connect,
    not just this instant. The entry stays in blocked_devices.yaml even
    after later being toggled off — see set_device_blocked().
    """
    from backend.rules import load_blocked_devices, add_blocked_device, reload_blocked_devices
    data = load_blocked_devices()
    data = add_blocked_device(data, mac, label)
    ok, msg = reload_blocked_devices(data)
    if ok:
        kick_device(mac)
    return ok, msg


def set_device_blocked(mac: str, blocked: bool) -> tuple[bool, str]:
    """
    The on/off toggle: flip enforcement for an EXISTING blocked_devices.yaml
    entry without removing it, so a device can be found and re-blocked later
    even after it's dropped off /api/devices/seen (which only lists devices
    currently associated — exactly what being blocked makes them stop being).
    Turning it back on doesn't retroactively kick the device; it only starts
    enforcing again from the next apply_iptables() (the device may already
    be off the network from the original kick, or may need to be kicked
    again if it reconnected while this was toggled off — call block_device()
    for that, not this).
    """
    from backend.rules import load_blocked_devices, set_blocked_device, reload_blocked_devices
    data = load_blocked_devices()
    data = set_blocked_device(data, mac, blocked)
    return reload_blocked_devices(data)


def delete_blocked_device(mac: str) -> tuple[bool, str]:
    """Fully remove `mac` from blocked_devices.yaml — unlike
    set_device_blocked(mac, False), the entry itself is gone, not just
    disabled. It can rejoin the hotspot again (does NOT retroactively
    reconnect it; the device has to rejoin itself)."""
    from backend.rules import load_blocked_devices, remove_blocked_device, reload_blocked_devices
    data = load_blocked_devices()
    data = remove_blocked_device(data, mac)
    return reload_blocked_devices(data)


def check_proxy_latency(host: str, port: int, timeout: float = 3.0) -> Optional[float]:
    """
    TCP-connect latency check. Resolves via getaddrinfo (AF_UNSPEC) instead
    of hardcoding AF_INET — an IPv6-addressed proxy host (or an IPv4-only
    hostname that also has an AAAA record) would otherwise fail this check
    immediately every time, showing no latency in the UI at all, regardless
    of whether the proxy itself is actually reachable. For an IPv6 address,
    this naturally routes over whatever the kernel's IPv6 route table says
    (nothing, unless this machine's own WAN connection has real IPv6).
    """
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        return None
    for family, socktype, proto, _canon, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            err = sock.connect_ex(sockaddr)
            elapsed = (time.monotonic() - start) * 1000
            sock.close()
            if err == 0:
                return round(elapsed, 1)
        except Exception:
            continue
    return None
