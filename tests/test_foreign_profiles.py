"""
Foreign NM profiles bound to ProxyGate's virtual interface.

ProxyGate creates a virtual WiFi interface (IPV6_CLIENT_IF) on the shared
radio. Any of the USER'S OWN saved WiFi profiles pinned to that interface name
with autoconnect enabled becomes eligible the instant the interface appears —
and NetworkManager then retries it forever.

It can never succeed: the radio is already hosting the AP on a fixed channel,
and a single radio cannot associate to another network at the same time. NM
reports 'ssid-not-found' even for an SSID plainly in range, roughly every 26
seconds, and every failure raises a desktop "network activation failed"
notification. Observed live with a profile named POLYMOONDEV.

Nothing is actually broken, which is what makes it so misleading: the user's
network is fine, so the notification sends them looking in the wrong place.
"""
import types

import pytest

from backend import services


def _nmcli(connections, per_conn):
    """Fake nmcli: `con show` lists connections, `con show <name>` details."""
    calls = []

    def run(cmd, **kw):
        calls.append(list(cmd))
        if cmd[:4] == ["nmcli", "-t", "-f", "NAME,UUID"]:
            out = "\n".join(f"{n}:uuid-{i}" for i, n in enumerate(connections))
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
        if "con" in cmd and "show" in cmd and cmd[-1] in per_conn:
            iface, auto = per_conn[cmd[-1]]
            out = (f"connection.interface-name:{iface}\n"
                   f"connection.autoconnect:{auto}\n")
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    return run, calls


@pytest.fixture
def cfg(monkeypatch):
    monkeypatch.setattr(services, "load_config",
                        lambda: {"ap_con_name": "proxygate-ap"})


def test_foreign_profile_on_our_interface_is_found(cfg, monkeypatch):
    run, _ = _nmcli(["POLYMOONDEV", "HomeWiFi"],
                    {"POLYMOONDEV": ("wlan-ipv6", "yes"),
                     "HomeWiFi": ("wlp3s0", "yes")})
    monkeypatch.setattr(services.subprocess, "run", run)
    assert services._foreign_connections_bound_to("wlan-ipv6") == ["POLYMOONDEV"]


def test_autoconnect_is_disabled_for_the_offender(cfg, monkeypatch):
    run, calls = _nmcli(["POLYMOONDEV"], {"POLYMOONDEV": ("wlan-ipv6", "yes")})
    monkeypatch.setattr(services.subprocess, "run", run)
    assert services.quiesce_foreign_profiles("wlan-ipv6") == ["POLYMOONDEV"]
    assert any(c[:3] == ["nmcli", "con", "modify"]
               and "connection.autoconnect" in c and "no" in c
               for c in calls), "autoconnect was never turned off"


def test_profile_is_not_deleted_only_quiesced(cfg, monkeypatch):
    """The user keeps their network — only the automatic-retry flag is cleared."""
    run, calls = _nmcli(["POLYMOONDEV"], {"POLYMOONDEV": ("wlan-ipv6", "yes")})
    monkeypatch.setattr(services.subprocess, "run", run)
    services.quiesce_foreign_profiles("wlan-ipv6")
    assert not any("delete" in c for c in calls), "must never delete a user profile"


def test_profiles_on_other_interfaces_are_untouched(cfg, monkeypatch):
    """Only a profile pinned to the interface WE created is our business."""
    run, calls = _nmcli(["HomeWiFi"], {"HomeWiFi": ("wlp3s0", "yes")})
    monkeypatch.setattr(services.subprocess, "run", run)
    assert services.quiesce_foreign_profiles("wlan-ipv6") == []
    assert not any(c[:3] == ["nmcli", "con", "modify"] for c in calls)


def test_already_disabled_profiles_are_left_alone(cfg, monkeypatch):
    """Nothing to fix — it will not be retried."""
    run, calls = _nmcli(["POLYMOONDEV"], {"POLYMOONDEV": ("wlan-ipv6", "no")})
    monkeypatch.setattr(services.subprocess, "run", run)
    assert services.quiesce_foreign_profiles("wlan-ipv6") == []


def test_our_own_connections_are_never_touched(cfg, monkeypatch):
    """ProxyGate's own profiles are managed deliberately elsewhere; treating
    them as foreign would fight our own setup."""
    run, _ = _nmcli([services._IPV6_CLIENT_CON, "proxygate-ap"],
                    {services._IPV6_CLIENT_CON: ("wlan-ipv6", "yes"),
                     "proxygate-ap": ("wlan-ipv6", "yes")})
    monkeypatch.setattr(services.subprocess, "run", run)
    assert services._foreign_connections_bound_to("wlan-ipv6") == []


def test_nmcli_failure_never_raises(cfg, monkeypatch):
    """This runs during connect; a diagnostic convenience must not abort it."""
    def boom(*a, **kw):
        raise OSError("nmcli missing")
    monkeypatch.setattr(services.subprocess, "run", boom)
    assert services._foreign_connections_bound_to("wlan-ipv6") == []
    assert services.quiesce_foreign_profiles("wlan-ipv6") == []
