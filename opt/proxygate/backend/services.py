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
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from backend import devices as devices_mod
from backend import firewall

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

# mitmproxy's config dir, holding the CA. Absolute and project-local on
# purpose: the default (~/.mitmproxy) depends on $HOME at launch, and a
# different HOME makes mitmproxy generate a brand-new CA, invalidating the
# certificate already installed and trusted on every device.
MITM_CONF_DIR = os.getenv("PROXYGATE_MITM_CONFDIR",
                          os.path.join(PROJECT_ROOT, "var/lib/proxygate/mitmproxy"))


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

default: XVPN
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
            nonlocal a_bssid, a_signal
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
            # Track the best 5 GHz BSS separately, for the no-preference
            # default below. 5 GHz is not merely "another band" here: the AP
            # shares this radio, so landing on 2.4 GHz puts the hotspot on a
            # crowded 20 MHz channel alongside every neighbouring network,
            # which is materially worse for clients than an empty 5 GHz one.
            if band == "a":
                if a_signal is None or (signal is not None and signal > a_signal):
                    a_bssid, a_signal = bssid, signal

        best_bssid = best_signal = best_band = None
        pref_bssid = pref_signal = None
        a_bssid = a_signal = None
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
        # No band configured: prefer 5 GHz when the SSID offers it, instead of
        # taking whichever BSS happens to be loudest.
        #
        # Signal strength alone made this choice NON-DETERMINISTIC across
        # restarts — the same SSID's 2.4 GHz and 5 GHz radios trade places as
        # RSSI fluctuates by a few dBm, so consecutive restarts landed on
        # band=a/channel=44 and then band=bg/channel=1 with no config change.
        # Because the AP inherits this channel, the hotspot silently moved
        # bands between runs and clients that were happy on 5 GHz suddenly
        # found a congested 2.4 GHz network. 2.4 GHz remains the fallback
        # when there is genuinely no 5 GHz BSS in range.
        if a_bssid:
            return a_bssid, "a"
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

    # Do this immediately after the interface appears and BEFORE we activate
    # our own profile on it. Any of the user's saved networks pinned to this
    # interface name becomes eligible the moment it exists, and NM will retry
    # it every ~25s — each attempt failing with 'ssid-not-found' (the radio is
    # an AP on a fixed channel and cannot associate elsewhere) and each failure
    # raising a desktop notification.
    quiesce_foreign_profiles(IPV6_CLIENT_IF)

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


def _foreign_connections_bound_to(iface: str) -> list[str]:
    """
    Saved NM profiles — not ours — pinned to `iface` by interface-name.

    ProxyGate creates a virtual interface (IPV6_CLIENT_IF) on the shared
    radio. Any of the user's own saved WiFi profiles that happens to be bound
    to that interface name, with autoconnect on, becomes eligible the instant
    the interface appears. NM then tries to activate it, fails, and retries
    forever — one desktop "network activation failed" popup per attempt.

    It can never succeed: the radio is already an AP on a fixed channel, and a
    single radio cannot associate elsewhere at the same time. So NM reports
    'ssid-not-found' even for an SSID that is plainly in range.
    """
    found: list[str] = []
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,UUID", "con", "show"],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            name = parts[0]
            if name in (_IPV6_CLIENT_CON, load_config().get("ap_con_name", "proxygate-ap")):
                continue
            d = subprocess.run(
                ["nmcli", "-t", "-f",
                 "connection.interface-name,connection.autoconnect",
                 "con", "show", name],
                capture_output=True, text=True, timeout=10,
            )
            fields = dict(
                l.split(":", 1) for l in d.stdout.splitlines() if ":" in l
            )
            if (fields.get("connection.interface-name", "").strip() == iface
                    and fields.get("connection.autoconnect", "").strip() == "yes"):
                found.append(name)
    except Exception:
        log.debug("could not enumerate NM connections", exc_info=True)
    return found


def quiesce_foreign_profiles(iface: str) -> list[str]:
    """
    Stop other saved profiles from fighting over ProxyGate's virtual interface.

    Turns OFF autoconnect for any foreign profile pinned to `iface` — it
    cannot work while the radio is an AP, and every retry is a failure popup.
    The profile itself is left intact so the user keeps their network; only
    the automatic-retry flag is cleared, and only for a profile bound to an
    interface that exists solely because ProxyGate created it.
    """
    disabled: list[str] = []
    for name in _foreign_connections_bound_to(iface):
        r = subprocess.run(
            ["nmcli", "con", "modify", name, "connection.autoconnect", "no"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            disabled.append(name)
            log.info(
                "disabled autoconnect for %r: it is pinned to %s, which only "
                "exists because ProxyGate created it, and cannot associate "
                "while the radio is hosting the AP (every retry raised a "
                "'network activation failed' notification)", name, iface)
    return disabled


def teardown_ipv6_client_link() -> None:
    """
    Remove the virtual client interface and everything attached to it.

    Deleting the INTERFACE matters as much as the connection: while it exists,
    any saved profile bound to that name stays eligible for activation, so NM
    keeps retrying and the user keeps getting failure popups long after
    ProxyGate has stopped.
    """
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
    Apply ProxyGate's packet path.

    Thin wrapper over backend.firewall, which owns the rules as data and
    verifies that what it wrote actually landed. This used to be a 404-line
    function that shelled out to iptables 44 times and checked nothing — which
    is how rules scoped to a nonexistent interface got installed silently,
    matching zero packets forever while the gateway reported "connected".
    firewall.apply() refuses that case up front instead.
    """
    cfg = load_config()
    ap_if = resolve_ap_wifi_if()
    wan_cfg = (cfg.get("wan_if") or "").strip()
    # A pinned wan_if is honoured only if it doesn't collide with the AP NIC —
    # a stale value from before an adapter swap must not recreate the
    # same-NIC deadlock on every connect.
    wan = wan_cfg if wan_cfg and wan_cfg != ap_if else detect_wan_if() or "eth0"

    target = _routing_target()
    ruleset = firewall.build(
        hotspot_if=current_hotspot_if(),
        wan_if=wan,
        gateway_ip=cfg["hotspot_gw"],
        subnet=cfg["hotspot_subnet"],
        mitm_port=int(cfg["mitm_port"]),
        block=(target == "BLOCK"),
        blocked_macs=_blocked_mac_set(),
    )

    try:
        firewall.apply(ruleset)
    except firewall.FirewallError as e:
        return False, str(e)
    except Exception as e:
        return False, f"iptables error: {e}"

    return True, f"iptables applied (mode: {target})"


def current_ruleset() -> "firewall.Ruleset":
    """The packet path this configuration implies — for verification."""
    cfg = load_config()
    ap_if = resolve_ap_wifi_if()
    wan_cfg = (cfg.get("wan_if") or "").strip()
    wan = wan_cfg if wan_cfg and wan_cfg != ap_if else detect_wan_if() or "eth0"
    return firewall.build(
        hotspot_if=current_hotspot_if(),
        wan_if=wan,
        gateway_ip=cfg["hotspot_gw"],
        subnet=cfg["hotspot_subnet"],
        mitm_port=int(cfg["mitm_port"]),
        block=(_routing_target() == "BLOCK"),
        blocked_macs=_blocked_mac_set(),
    )


_registry_lock = threading.Lock()
_registry: Optional["devices_mod.Registry"] = None
_registry_iface: Optional[str] = None


def device_registry() -> "devices_mod.Registry":
    """
    The process-wide device registry — the ONE source of truth for what is on
    the hotspot.

    Rebuilt when the hotspot interface changes, so it can never keep answering
    for an interface that no longer exists. Its hostname/client-id memos are
    deliberately preserved for the life of an interface: a lease file holds
    only CURRENT leases, and a device must not lose its name the moment its
    lease rolls.
    """
    global _registry, _registry_iface
    iface = current_hotspot_if()
    with _registry_lock:
        if _registry is None or _registry_iface != iface:
            _registry = devices_mod.Registry(
                devices_mod.Sources(iface, lease_paths=tuple(_lease_file_candidates())),
                subnet=load_config().get("hotspot_subnet"),
                vendor_lookup=_mac_vendor,
            )
            _registry_iface = iface
        return _registry


def _migrate_existing_ca() -> None:
    """
    Move a CA generated under the old default location into MITM_CONF_DIR.

    Pinning confdir would otherwise be a breaking change: mitmproxy would find
    the pinned directory empty, mint a fresh CA, and every device that already
    trusts the old one would start failing TLS — the exact "reinstall the CA
    again" problem the pin exists to prevent.

    Copies (never moves) so the original stays as a fallback, and never
    overwrites a CA already present in the pinned directory.
    """
    dest_ca = os.path.join(MITM_CONF_DIR, "mitmproxy-ca.pem")
    if os.path.exists(dest_ca):
        return

    for home in (os.path.expanduser("~root"), os.path.expanduser("~")):
        src_dir = os.path.join(home, ".mitmproxy")
        if not os.path.isfile(os.path.join(src_dir, "mitmproxy-ca.pem")):
            continue
        copied = []
        for name in os.listdir(src_dir):
            if not name.startswith("mitmproxy-"):
                continue
            try:
                shutil.copy2(os.path.join(src_dir, name),
                             os.path.join(MITM_CONF_DIR, name))
                copied.append(name)
            except Exception:
                pass
        if copied:
            log.info("migrated existing mitmproxy CA from %s — certificates already "
                     "installed on devices stay valid", src_dir)
        return


# dnsmasq's query log is what turns raw destination IPs into hostnames in the
# traffic table. NM's shared-mode dnsmasq is configured through drop-ins here.
DNSMASQ_DROPIN_DIR = "/etc/NetworkManager/dnsmasq-shared.d"
DNSMASQ_LOG_PATH = "/var/log/proxygate/dnsmasq.log"
# Rotate at 32 MB. Left unmanaged this grew to 59 MB and climbing — dnsmasq
# logs every query and every cache hit, so on a busy hotspot it fills a disk
# with no upper bound and nothing to stop it.
DNSMASQ_LOG_MAX_BYTES = 32 * 1024 * 1024


# Upstream resolvers for the hotspot's dnsmasq.
#
# A hand-placed drop-in on this machine pinned a SINGLE upstream with
# `no-resolv`, and that server later went dark (100% packet loss). With no
# fallback, every lookup on the hotspot hung until it timed out — which is
# indistinguishable from "the whole proxy is slow", because nothing resolves
# until DNS does. Multiple resolvers plus `all-servers` means one dead
# upstream costs nothing.
DNS_UPSTREAMS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def dns_upstream_healthy(server: str, timeout: float = 2.0) -> bool:
    """Does `server` actually answer a query? Cheap liveness probe."""
    try:
        r = subprocess.run(
            ["dig", "+short", f"+time={int(max(1, timeout))}", "+tries=1",
             f"@{server}", "github.com"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        return r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        return False


def ensure_dns_upstreams() -> tuple[bool, str]:
    """
    Own the hotspot's DNS configuration instead of inheriting whatever was
    left in /etc by hand.

    Replaces any stale ProxyGate drop-in that pins a dead resolver. Writes
    several upstreams and drops `no-resolv`'s single point of failure, so a
    resolver going down degrades latency instead of breaking the hotspot
    entirely.
    """
    conf_path = os.path.join(DNSMASQ_DROPIN_DIR, "proxygate-dns.conf")
    lines = [f"server={s}" for s in DNS_UPSTREAMS]
    # Query every upstream and take the first answer: a dead resolver then
    # costs nothing rather than stalling until it times out.
    lines.append("all-servers")
    desired = "\n".join(lines) + "\n"
    try:
        os.makedirs(DNSMASQ_DROPIN_DIR, exist_ok=True)
        existing = ""
        if os.path.isfile(conf_path):
            with open(conf_path) as f:
                existing = f.read()
        if existing.strip() == desired.strip():
            return True, "dns upstreams already configured"
        with open(conf_path, "w") as f:
            f.write(desired)
        log.info("rewrote dnsmasq upstreams to %s (was: %r)",
                 ", ".join(DNS_UPSTREAMS), existing.strip().replace("\n", " "))
        return True, "dns upstreams configured"
    except Exception as e:
        return False, f"could not configure dns upstreams: {e}"


def _restore_owner(path: str, *, is_dir: bool = False) -> None:
    """
    Hand a file/dir this process created back to the user who ran `sudo
    proxygate`.

    ProxyGate needs root for iptables, the hotspot and NM — but everything it
    writes lives inside the user's own checkout, so leaving it root-owned locks
    them out of their own project directory. rules.py already does this for the
    YAML config; these paths were simply missed, which is why
    var/lib/proxygate/mitmproxy and var/log/proxygate ended up root:root while
    every config file beside them is user-owned.

    Best-effort: SUDO_UID is unset when run directly as root, and then there is
    no invoking user to restore to.
    """
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid is not None and gid is not None:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass
    try:
        os.chmod(path, 0o755 if is_dir else 0o644)
    except OSError:
        pass


def restart_hotspot_dns() -> tuple[bool, str]:
    """
    Restart NM's shared-mode dnsmasq so config changes take effect.

    dnsmasq re-reads its conf-dir only on SIGHUP (cache/config) — but a
    changed `server=` list needs a full restart, and NM owns the process.
    SIGHUP first (cheap, keeps leases), then fall back to bouncing the
    connection, which NM restarts dnsmasq for.
    """
    pid_file = "/run/nm-dnsmasq-%s.pid" % current_hotspot_if()
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGHUP)
        return True, f"sent SIGHUP to dnsmasq (pid {pid})"
    except Exception as e:
        return False, f"could not signal dnsmasq: {e}"


def ensure_dns_logging() -> tuple[bool, str]:
    """
    Make sure dnsmasq logs queries where the tailer can read them.

    Without this the traffic table shows bare IPs instead of hostnames. The
    config previously had to be placed by hand, which meant a fresh install
    silently had no DNS capture at all — and nothing ever rotated the file.
    """
    conf_path = os.path.join(DNSMASQ_DROPIN_DIR, "proxygate-logging.conf")
    desired = f"log-queries\nlog-facility={DNSMASQ_LOG_PATH}\n"
    try:
        os.makedirs(DNSMASQ_DROPIN_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(DNSMASQ_LOG_PATH), exist_ok=True)
        existing = ""
        if os.path.isfile(conf_path):
            with open(conf_path) as f:
                existing = f.read()
        if existing.strip() != desired.strip():
            with open(conf_path, "w") as f:
                f.write(desired)
            return True, "dns logging configured (dnsmasq restart required)"
        return True, "dns logging already configured"
    except Exception as e:
        return False, f"could not configure dns logging: {e}"


def rotate_dns_log() -> bool:
    """
    Truncate the dnsmasq query log once it exceeds DNSMASQ_LOG_MAX_BYTES.

    Truncate in place rather than rename+recreate: dnsmasq holds the file open
    and will not reopen it without a signal, so renaming would leave it
    writing to a deleted inode — the log would appear to stop forever. The
    tailer detects the size going backwards and reseeks.
    """
    try:
        if os.path.getsize(DNSMASQ_LOG_PATH) < DNSMASQ_LOG_MAX_BYTES:
            return False
        with open(DNSMASQ_LOG_PATH, "r+") as f:
            f.truncate(0)
        log.info("rotated dnsmasq query log (exceeded %d MB)",
                 DNSMASQ_LOG_MAX_BYTES // (1024 * 1024))
        return True
    except Exception:
        return False


def _resync_associated_clients() -> int:
    """
    Deauth every associated station so it rejoins cleanly.

    Bringing the gateway up recreates the AP and reprograms NAT beneath any
    device already on the radio. That device keeps a lease, ARP entry and TCP
    sessions referencing the PREVIOUS state, so it sits there associated and
    silent until someone toggles its WiFi by hand. One deauth makes it
    reassociate, re-DHCP and reopen its connections automatically.

    Blocked devices are skipped — they are meant to stay off.
    """
    try:
        blocked = _blocked_mac_set()
    except Exception:
        blocked = set()

    kicked = 0
    for mac in _associated_stations():
        if mac in blocked:
            continue
        kick_device(mac)
        kicked += 1
    if kicked:
        log.info("resynced %d associated client(s) so they re-DHCP against the "
                 "new gateway state", kicked)
    return kicked


def iptables_diagnostics() -> dict:
    """
    What the gateway actually sees on the wire.

    Delegates the packet-path check to firewall.verify(), which compares the
    declared ruleset against the kernel and reports counters — the only signal
    that distinguishes "installed and working" from "installed and matching
    nothing". Device facts come from the registry so this cannot disagree with
    what the UI shows.
    """
    try:
        report = firewall.verify(current_ruleset())
    except Exception as e:
        report = {"problems": [f"could not read firewall state: {e}"],
                  "healthy": False, "chains": {}}

    try:
        reg = device_registry()
        devices = [d.as_dict() for d in reg.snapshot()]
        stations = sorted(reg.associated_macs())
    except Exception as e:
        devices, stations = [], []
        report.setdefault("problems", []).append(f"could not read devices: {e}")

    hi = current_hotspot_if()
    return {
        **report,
        "hotspot_if": hi,
        "hotspot_if_exists": bool(hi) and hi != "ap0"
                             and os.path.isdir(f"/sys/class/net/{hi}"),
        "routing_target": _routing_target(),
        "stations": stations,
        "devices": devices,
    }


def flush_iptables() -> tuple[bool, str]:
    """
    Remove every PROXYGATE_* iptables rule and chain.
    Safe to call even when rules don't exist.
    Restores ip_forward=0 so the host stops acting as a router.
    """
    def _r(*cmd: str) -> None:
        subprocess.run(list(cmd), capture_output=True)

    # Delete jumps REPEATEDLY, not once.
    #
    # `iptables -D` removes a single matching rule. A duplicate jump — which
    # any interrupted connect/reconnect can leave behind — therefore survives
    # a flush, and the leftover keeps sending packets into a chain this
    # function is about to delete (or, worse, into a stale chain from an older
    # version whose rules no longer match the current interface). Looping
    # until the delete fails is the only way to guarantee none remain.
    def _r_all(*cmd: str, limit: int = 16) -> None:
        for _ in range(limit):
            r = subprocess.run(list(cmd), capture_output=True)
            if r.returncode != 0:
                return

    _r_all("iptables", "-t", "nat", "-D", "PREROUTING",  "-j", "PROXYGATE_REDIRECT")
    _r_all("iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "PROXYGATE_MASQ")
    _r_all("iptables",             "-D", "FORWARD",      "-j", "PROXYGATE_FORWARD")
    _r_all("iptables",             "-D", "INPUT",        "-j", "PROXYGATE_BLOCKDEV")
    _r_all("iptables",             "-D", "FORWARD",      "-j", "PROXYGATE_BLOCKDEV")

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
    _r_all("ip6tables", "-t", "nat", "-D", "PREROUTING",  "-j", "PROXYGATE_REDIRECT6")
    _r_all("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-j", "PROXYGATE_MASQ6")
    _r_all("ip6tables",             "-D", "FORWARD",      "-j", "PROXYGATE_FORWARD6")
    for chain in ("PROXYGATE_REDIRECT6", "PROXYGATE_MASQ6"):
        _r("ip6tables", "-t", "nat", "-F", chain)
        _r("ip6tables", "-t", "nat", "-X", chain)
    _r("ip6tables", "-F", "PROXYGATE_FORWARD6")
    _r("ip6tables", "-X", "PROXYGATE_FORWARD6")

    # Clean up the old unconditional-DROP rule from before IPv6 was supported,
    # in case this host still has it from a previous ProxyGate version.
    _r("ip6tables", "-D", "FORWARD", "-i", current_hotspot_if(), "-j", "DROP")

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

        # Pin mitmproxy's config directory, and therefore its CA.
        #
        # Without an explicit confdir, mitmproxy uses ~/.mitmproxy — resolved
        # from $HOME at launch. Whenever that differs (sudo with/without -H,
        # a systemd unit, a different invoking user) mitmproxy finds no CA
        # there and silently GENERATES A NEW ONE. Every device that trusted
        # the old certificate then fails TLS, which presents as "the CA
        # stopped working and has to be reinstalled" — and reinstalling only
        # holds until the next launch that resolves HOME differently.
        #
        # Pinning it to an absolute path inside the project makes the CA
        # stable for the life of the install: install it on a device once.
        os.makedirs(MITM_CONF_DIR, exist_ok=True)
        _restore_owner(MITM_CONF_DIR, is_dir=True)
        _migrate_existing_ca()
        # The CA cert is meant to be downloaded and installed on devices, so it
        # must stay readable by the user. The PRIVATE key deliberately keeps
        # its restrictive mode — see below.
        for name in ("mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer",
                     "mitmproxy-ca-cert.p12"):
            cert = os.path.join(MITM_CONF_DIR, name)
            if os.path.isfile(cert):
                _restore_owner(cert)

        cmd = [
            mitmdump_bin,
            "--mode",        "transparent",
            "--listen-port", str(cfg["mitm_port"]),
            "-s",            ADDON_PATH,
            "--ssl-insecure",
            "--set",         f"confdir={MITM_CONF_DIR}",
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

        # Before NM starts the hotspot's dnsmasq, so it picks up query logging
        # on first launch rather than needing a second connect.
        ok_dns, dns_msg = ensure_dns_logging()
        if not ok_dns:
            log.warning("dns logging: %s", dns_msg)
        ok_up, up_msg = ensure_dns_upstreams()
        if not ok_up:
            log.warning("dns upstreams: %s", up_msg)

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
                ["ip", "-4", "addr", "show", current_hotspot_if()],
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

        # Force every already-associated client to rejoin.
        #
        # Bringing the gateway up recreates the AP and reprograms NAT beneath
        # any device that was already on the radio. Such a device keeps a
        # lease, ARP entry and TCP sessions that all reference the PREVIOUS
        # state — so it sits there associated, sending nothing that we route,
        # until a human toggles its WiFi off and on. That manual step is the
        # "figure out why there's no traffic" tax, and it is entirely avoidable:
        # one deauth makes the client reassociate, re-DHCP and reopen its
        # connections against the gateway that now exists.
        #
        # Non-fatal by design: the gateway is already CONNECTED and working at
        # this point, so a failed kick must never downgrade that.
        try:
            _resync_associated_clients()
        except Exception:
            log.debug("client resync after connect failed", exc_info=True)

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

            rotate_dns_log()

            if not _iptables_chain_exists():
                log.warning("PROXYGATE_REDIRECT chain missing — reapplying iptables.")
                apply_iptables()
                continue

            # The chain existing is not the same as it WORKING. Rules scoped to
            # a stale interface install cleanly and match nothing, forever —
            # the failure that presented as "the proxy is dead" with no error
            # anywhere. Verify against the kernel and re-apply if the packet
            # path is broken.
            try:
                report = firewall.verify(current_ruleset())
                if not report["healthy"]:
                    log.warning("packet path unhealthy (%s) — reapplying iptables",
                                "; ".join(report["problems"])[:200])
                    apply_iptables()
                    continue
            except Exception:
                log.debug("packet-path verification failed", exc_info=True)

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
    return get_interface_ip(current_hotspot_if())


def get_connected_devices() -> int:
    """Devices associated to the radio right now (not leases or ARP, which
    both persist long after a device leaves and would over-count)."""
    return device_registry().connected_count()


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


def _clean_client_id(client_id: str, mac: str) -> Optional[str]:
    """
    A DHCP client-id worth using as a device identity, or None.

    RFC 2132 type-01 client-ids are just `01:` + the hardware address, which
    is what every device on this hotspot actually sends:

        d2:b6:62:ff:9a:12  ->  01:d2:b6:62:ff:9a:12

    That is the MAC wearing a hat: it rotates exactly when the MAC rotates,
    so keying identity on it would be no more stable than keying on the MAC.
    Those are rejected here.

    A client-id that is NOT derived from the MAC (dnsmasq writes these
    verbatim — e.g. an RFC 4361 DUID, or an operator-configured id) is a
    genuinely independent identifier that CAN survive a MAC rotation, so it
    is kept and preferred over the hostname.
    """
    cid = (client_id or "").strip().lower()
    # Whitespace-only must normalize to None, not "" — an empty string would
    # read as a present-but-blank identity downstream.
    if not cid or cid == "*":
        return None
    mac = mac.strip().lower()
    # Type-01 ("01:" + MAC), and the same thing with separators stripped.
    if cid == f"01:{mac}":
        return None
    if cid.replace(":", "") == f"01{mac.replace(':', '')}":
        return None
    if cid.replace(":", "") == mac.replace(":", ""):
        return None
    return cid


def _read_leases() -> list[tuple[str, str, Optional[str]]]:
    """
    Parse the hotspot's DHCP lease file into (mac, ip, hostname) tuples.
    dnsmasq writes "*" for a client that sent no hostname; that becomes None.

    Kept at 3-tuples for every existing caller; the client-id is exposed
    separately by _read_lease_rows() so this signature stays stable.
    """
    return [(mac, ip, hostname) for mac, ip, hostname, _cid in _read_lease_rows()]


def _read_lease_rows() -> list[tuple[str, str, Optional[str], Optional[str]]]:
    """
    Full lease rows: (mac, ip, hostname, client_id).

    dnsmasq lease format is:
        <expiry> <mac> <ip> <hostname> <client-id>
    with "*" meaning "the client sent none" for both hostname and client-id.
    """
    for path in _lease_file_candidates():
        rows: list[tuple[str, str, Optional[str], Optional[str]]] = []
        try:
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        mac, ip, hostname = parts[1].lower(), parts[2], parts[3]
                        raw_cid = parts[4] if len(parts) >= 5 else ""
                        rows.append((
                            mac, ip,
                            None if hostname == "*" else hostname,
                            _clean_client_id(raw_cid, mac),
                        ))
                    elif len(parts) >= 3:
                        rows.append((parts[1].lower(), parts[2], None, None))
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


def _associated_stations() -> set[str]:
    """
    MACs currently associated to the hotspot radio, from `iw station dump`.

    This is the ONLY authoritative answer to "is this device connected right
    now". DHCP leases persist for the whole lease time (an hour here) and ARP
    rows linger in STALE for minutes-to-hours after a device is gone, so a
    list built from either keeps showing devices that already left — the
    "ghost devices" this guards against.

    An empty set is ambiguous: it means either "nothing associated" or "the
    command failed / iw is missing". Callers must distinguish those, so
    failure is reported separately by _stations_available().
    """
    stations: set[str] = set()
    iface = current_hotspot_if()
    if not iface or iface == "ap0":
        return stations
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "station", "dump"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return stations
        for line in r.stdout.splitlines():
            line = line.strip()
            # "Station aa:bb:cc:dd:ee:ff (on wlp2s0)"
            if line.startswith("Station "):
                parts = line.split()
                if len(parts) >= 2:
                    stations.add(parts[1].lower())
    except Exception:
        pass
    return stations


def _stations_available() -> bool:
    """
    True if `iw station dump` actually works on the hotspot interface.

    Used to decide whether an empty station list means "nobody is connected"
    (trust it, and show nothing) or "we cannot tell" (fall back to leases and
    ARP rather than wrongly showing an empty device list). Without this, a
    missing `iw` binary or a down interface would silently empty the UI.
    """
    iface = current_hotspot_if()
    if not iface or iface == "ap0":
        return False
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "station", "dump"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


# Neighbour states that mean "this device is actually on the network right
# now". PERMANENT is included for a statically-configured neighbour; STALE and
# friends deliberately are not (see _neighbor_table).
_LIVE_NEIGH_STATES = {"REACHABLE", "PERMANENT"}


def _neighbor_table() -> dict[str, str]:
    """Return {ip: mac} from the kernel's IPv4 neighbor (ARP) table, scoped to
    the hotspot interface only — as a fallback for devices dnsmasq hasn't
    leased directly (e.g. static IP). Unscoped `ip neigh show` dumps every
    interface's ARP table (host LAN, Docker bridges, etc.), which would leak
    unrelated neighbors (e.g. a Docker container's gateway) into the hotspot
    device list."""
    neighbors: dict[str, str] = {}
    iface = current_hotspot_if()
    # Never fall back to an unscoped dump. If the hotspot interface can't be
    # resolved, current_hotspot_if() returns the "ap0" placeholder, and
    # `ip neigh show dev ap0` errors out — but an empty/!=0 run used to be
    # swallowed below, and any code path that dropped the `dev` scoping would
    # dump br-*/enp3s0/docker neighbours straight into the hotspot list.
    # No interface means no devices, not "every device on the host".
    if not iface or iface == "ap0":
        return neighbors
    try:
        r = subprocess.run(
            ["ip", "-4", "neigh", "show", "dev", iface],
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
            # Only genuinely-live neighbour states count. The kernel keeps a
            # row long after a device leaves: it decays
            # REACHABLE -> STALE -> DELAY -> PROBE -> FAILED, and a device
            # that has been off the network for hours still sits there as
            # STALE with a valid lladdr. Treating STALE as present is what
            # produced "ghost" devices that no longer exist.
            #
            # An allowlist, not a denylist: previously only FAILED and
            # INCOMPLETE were skipped, so every other state (STALE, DELAY,
            # PROBE, NOARP, and rows with no state word at all) leaked in.
            if not _LIVE_NEIGH_STATES.intersection(parts):
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


# MAC -> last DHCP hostname ever seen, for the lifetime of the process.
#
# A lease file only holds CURRENT leases: when a lease expires or is rewritten,
# the hostname vanishes even though the device is still associated and still
# the same device. Without this, a device that had a perfectly good name
# ("iPhone") silently degrades to a bare IP mid-session — the other half of
# "a device shows only its IP and MAC". Names are only ever added here, never
# invented: a MAC with no hostname stays nameless.
_hostname_memo: dict[str, str] = {}
_hostname_memo_lock = threading.Lock()


def _remember_hostnames(rows: list[tuple[str, str, Optional[str]]]) -> None:
    with _hostname_memo_lock:
        for mac, _ip, hostname in rows:
            if hostname:
                _hostname_memo[mac] = hostname


def _recall_hostname(mac: str) -> Optional[str]:
    with _hostname_memo_lock:
        return _hostname_memo.get(mac)


def _ip_sort_key(ip: Optional[str]) -> tuple:
    """Sort IPs numerically, not lexically ('192.168.100.9' before '.101')."""
    if not ip:
        return (0,)
    try:
        return (int(ipaddress.ip_address(ip)),)
    except ValueError:
        return (0,)


def list_hotspot_devices() -> list[dict]:
    """
    Every device known on the hotspot — from the single registry, so the UI,
    the decrypt gate and the block list can no longer disagree about what
    exists. See backend/devices.py for why that mattered.
    """
    return [d.as_dict() for d in device_registry().snapshot()]


def _associated_stations() -> set[str]:
    """MACs associated to the radio right now."""
    return device_registry().associated_macs()


def resolve_mac(ip: str) -> Optional[str]:
    """IP -> MAC, resolved live so a just-joined device is identified on its
    first connection rather than after the next refresh."""
    return device_registry().mac_for_ip(ip)


def kick_device(mac: str) -> None:
    """
    Immediately deauthenticate `mac` from the hotspot radio (`iw station
    del`) — an instant disconnect, separate from the persistent iptables
    block in apply_iptables()/PROXYGATE_BLOCKDEV. Used both by block_device()
    (kick + ban) and standalone (kick without banning, if ever wanted) — best
    effort: if the device isn't currently associated, `iw` just reports
    nothing to delete, which is fine, not an error.
    """
    subprocess.run(["iw", "dev", current_hotspot_if(), "station", "del", mac],
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


def _deauth_for_clean_rejoin(mac: str) -> None:
    """
    Deauthenticate `mac` so it reassociates from scratch.

    Used when UNBLOCKING, which is counter-intuitive but necessary. While a
    device is blocked its packets are DROPped in INPUT, so it cannot renew
    its DHCP lease, cannot resolve DNS, and its TCP sessions die — but it
    often stays *associated* to the radio. Removing the DROP rule alone
    leaves it sitting there with a dead lease and half-open sockets that
    nothing will ever answer, which is why a device could appear "unblocked"
    and still have no traffic until it was manually toggled off and on.

    Forcing one deauth makes the client rejoin, re-DHCP and re-open its
    connections immediately, so unblocking takes effect without the user
    touching the device.
    """
    kick_device(mac)


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
    ok, msg = reload_blocked_devices(data)
    if ok:
        # Both directions need a deauth. Blocking: the DROP rule stops new
        # packets but an already-associated device keeps its radio link, so
        # kick it off now rather than waiting for it to notice. Unblocking:
        # see _deauth_for_clean_rejoin — the device must rejoin to get a
        # working lease back.
        _deauth_for_clean_rejoin(mac)
    return ok, msg


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
