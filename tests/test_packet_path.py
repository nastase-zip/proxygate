"""
The packet path: interface binding, rule hygiene, and self-diagnosis.

THE regression this covers: apply_iptables() scoped every rule with
`-i HOTSPOT_IF`, reading the raw module global rather than resolving the
interface live. HOTSPOT_IF defaults to the placeholder "ap0" and is only
assigned when THIS process brings the AP up — so whenever the AP was already
running (a web-UI restart, a reconnect, NM activating late), every REDIRECT,
DNAT and FORWARD rule was installed against a nonexistent interface.

iptables accepts that without complaint. The result is total and silent:
rules present, counters frozen at zero, gateway reporting "connected", and not
one packet redirected to mitmproxy. Indistinguishable from "the proxy is
broken", with nothing in any log to say otherwise.
"""
import types

import pytest

from backend import services


@pytest.fixture
def recorder(monkeypatch):
    """Capture every iptables invocation instead of running it."""
    calls = []

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    monkeypatch.setattr(services, "load_config", lambda: {
        "hotspot_gw": "192.168.100.1",
        "hotspot_subnet": "192.168.100.0/24",
        "mitm_port": 8080,
        "wan_if": "enp3s0",
    })
    monkeypatch.setattr(services, "resolve_ap_wifi_if", lambda: "wlp2s0")
    monkeypatch.setattr(services, "detect_wan_if", lambda: "enp3s0")
    monkeypatch.setattr(services, "_routing_target", lambda: "XVPN")
    monkeypatch.setattr(services, "_blocked_mac_set", lambda: set())
    monkeypatch.setattr(services.os.path, "isdir", lambda p: True)
    return calls


# ── The regression: rules must bind to the LIVE interface ─────────────────────

def test_rules_bind_to_resolved_interface_not_stale_global(recorder, monkeypatch):
    """HOTSPOT_IF is the stale 'ap0' placeholder, but the AP is really on
    wlp2s0. Every rule must use the resolved name."""
    monkeypatch.setattr(services, "HOTSPOT_IF", "ap0")
    monkeypatch.setattr(services, "_get_ap_if", lambda: "wlp2s0")

    ok, msg = services.apply_iptables()
    assert ok, msg

    iface_args = [c[c.index("-i") + 1] for c in recorder if "-i" in c]
    assert iface_args, "no interface-scoped rules were installed at all"
    assert "ap0" not in iface_args, "rules bound to the placeholder interface"
    # wlp2s0 is the hotspot; enp3s0 is the WAN side (legitimately referenced
    # by return-path rules). Neither may ever be the placeholder.
    assert "wlp2s0" in iface_args
    assert set(iface_args) <= {"wlp2s0", "enp3s0"}


def test_redirect_rule_targets_the_mitm_port(recorder, monkeypatch):
    monkeypatch.setattr(services, "HOTSPOT_IF", "wlp2s0")
    monkeypatch.setattr(services, "_get_ap_if", lambda: "wlp2s0")
    services.apply_iptables()
    redirects = [c for c in recorder if "REDIRECT" in c]
    assert redirects, "no REDIRECT rule installed — nothing would reach mitmproxy"
    assert any("8080" in c for c in redirects)


def test_refuses_to_install_against_missing_interface(recorder, monkeypatch):
    """A silent no-op is the worst outcome — fail loudly instead."""
    monkeypatch.setattr(services, "HOTSPOT_IF", "ap0")
    monkeypatch.setattr(services, "_get_ap_if", lambda: "ap0")
    monkeypatch.setattr(services.os.path, "isdir", lambda p: False)

    ok, msg = services.apply_iptables()
    assert ok is False
    assert "does not exist" in msg
    assert not any("REDIRECT" in c for c in recorder), \
        "rules were installed despite the interface being absent"


# ── Rule hygiene: no stale/duplicate state from older versions ────────────────

def test_jump_is_deleted_repeatedly_before_insert(recorder, monkeypatch):
    """`iptables -D` removes ONE match. A duplicate jump left by an
    interrupted run would otherwise survive and keep routing packets."""
    monkeypatch.setattr(services, "HOTSPOT_IF", "wlp2s0")
    monkeypatch.setattr(services, "_get_ap_if", lambda: "wlp2s0")
    services.apply_iptables()

    deletes = [c for c in recorder
               if "-D" in c and "PREROUTING" in c and "PROXYGATE_REDIRECT" in c]
    assert len(deletes) > 1, "jump deleted only once — duplicates would persist"


def test_flush_removes_every_duplicate_jump(monkeypatch):
    """Simulate three stacked jumps; the flush must clear all of them."""
    remaining = {"jumps": 3}
    calls = []

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        if "-D" in cmd and "PROXYGATE_REDIRECT" in cmd and "PREROUTING" in cmd:
            if remaining["jumps"] > 0:
                remaining["jumps"] -= 1
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return types.SimpleNamespace(returncode=1, stdout="", stderr="no match")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(services.subprocess, "run", fake_run)
    monkeypatch.setattr(services, "current_hotspot_if", lambda: "wlp2s0")
    services.flush_iptables()
    assert remaining["jumps"] == 0, "duplicate jumps survived the flush"


def test_legacy_chains_are_cleaned_up(monkeypatch):
    """State from older ProxyGate versions must not linger."""
    calls = []
    monkeypatch.setattr(services.subprocess, "run",
                        lambda cmd, **kw: (calls.append(list(cmd)),
                                           types.SimpleNamespace(returncode=0, stdout="", stderr=""))[1])
    monkeypatch.setattr(services, "current_hotspot_if", lambda: "wlp2s0")
    services.flush_iptables()
    flat = [" ".join(c) for c in calls]
    assert any("PROXYGATE_OUTPUT" in f for f in flat), "legacy OUTPUT chain not cleaned"
    assert any("PROXYGATE_REDIRECT6" in f for f in flat), "IPv6 chain not cleaned"


# ── Self-diagnosis ────────────────────────────────────────────────────────────

PREROUTING_DEAD = """Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 PROXYGATE_REDIRECT  all  --  *      *       0.0.0.0/0            0.0.0.0/0
"""

PREROUTING_LIVE = """Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1     4213 9999 PROXYGATE_REDIRECT  all  --  *      *       0.0.0.0/0            0.0.0.0/0
"""

REDIRECT_DEAD = """Chain PROXYGATE_REDIRECT (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 REDIRECT   tcp  --  wlp2s0 *       0.0.0.0/0            0.0.0.0/0
"""

REDIRECT_LIVE = """Chain PROXYGATE_REDIRECT (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1     1201 5000 REDIRECT   tcp  --  wlp2s0 *       0.0.0.0/0            0.0.0.0/0
"""


@pytest.fixture
def diag_env(monkeypatch):
    """Drive services.iptables_diagnostics() without root or a live network."""
    def apply(prerouting, redirect, hotspot_if="wlp2s0"):
        def fake_run(cmd, **kw):
            joined = " ".join(cmd)
            out = ""
            if "-L PREROUTING" in joined:
                out = prerouting
            elif "-L PROXYGATE_REDIRECT " in joined or joined.endswith("-L PROXYGATE_REDIRECT"):
                out = redirect
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

        monkeypatch.setattr(services.subprocess, "run", fake_run)
        monkeypatch.setattr(services.firewall.subprocess, "run", fake_run)
        monkeypatch.setattr(services, "current_hotspot_if", lambda: hotspot_if)
        monkeypatch.setattr(services, "resolve_ap_wifi_if", lambda: "wlp2s0")
        monkeypatch.setattr(services, "detect_wan_if", lambda: "enp3s0")
        monkeypatch.setattr(services, "_routing_target", lambda: "XVPN")
        monkeypatch.setattr(services, "_blocked_mac_set", lambda: set())
        monkeypatch.setattr(services, "load_config", lambda: {
            "hotspot_gw": "192.168.100.1",
            "hotspot_subnet": "192.168.100.0/24",
            "mitm_port": 8080,
            "wan_if": "enp3s0",
        })
        monkeypatch.setattr(services, "device_registry", lambda: _EmptyRegistry())
        monkeypatch.setattr(services.os.path, "isdir", lambda p: True)
    return apply


class _EmptyRegistry:
    def snapshot(self):
        return []
    def associated_macs(self):
        return set()


def test_diagnostics_flags_a_dead_redirect_path(diag_env):
    """0 packets on the redirect is the signature of rules bound to an
    interface that does not exist — it must be reported in words."""
    diag_env(PREROUTING_DEAD, REDIRECT_DEAD)
    d = services.iptables_diagnostics()
    assert d["healthy"] is False
    assert any("0 packets" in p for p in d["problems"])


def test_diagnostics_reports_counters_when_packets_flow(diag_env):
    diag_env(PREROUTING_LIVE, REDIRECT_LIVE)
    d = services.iptables_diagnostics()
    assert not any("0 packets" in p for p in d["problems"])
    assert d["hotspot_if"] == "wlp2s0"


def test_diagnostics_flags_unresolved_interface(diag_env):
    """'ap0' is the placeholder meaning the interface was never resolved."""
    diag_env(PREROUTING_LIVE, REDIRECT_LIVE, hotspot_if="ap0")
    d = services.iptables_diagnostics()
    assert d["healthy"] is False
    assert d["hotspot_if_exists"] is False


def test_diagnostics_never_raises(monkeypatch):
    """A diagnostic that throws is worse than useless."""
    def boom(*a, **kw):
        raise OSError("nope")
    monkeypatch.setattr(services.subprocess, "run", boom)
    monkeypatch.setattr(services.firewall.subprocess, "run", boom)
    monkeypatch.setattr(services, "current_hotspot_if", lambda: "wlp2s0")
    d = services.iptables_diagnostics()
    assert isinstance(d, dict)
    assert d["healthy"] is False
