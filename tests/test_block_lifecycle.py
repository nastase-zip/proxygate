"""
Block / unblock lifecycle — must take effect immediately, in both directions,
without restarting the proxy or touching the device.

The failure this covers: unblocking rewrote iptables (removing the DROP) but
left the device associated to the radio with a dead DHCP lease and half-open
sockets, because while blocked its packets were DROPped in INPUT — so it could
not renew DHCP or resolve DNS. The device looked unblocked in the UI and still
had no traffic until it was manually toggled off and on.

Both directions therefore force one deauth so the client rejoins cleanly.
"""
import pytest

from backend import rules as rules_mod
from backend import services


@pytest.fixture
def blocklist(tmp_path, monkeypatch):
    """Isolated blocked_devices.yaml + recorded side effects."""
    path = tmp_path / "blocked.yaml"
    monkeypatch.setattr(rules_mod, "BLOCKED_DEVICES_PATH", str(path))

    calls = {"kicked": [], "iptables": 0}
    monkeypatch.setattr(services, "kick_device", lambda mac: calls["kicked"].append(mac))

    def fake_apply():
        calls["iptables"] += 1
        return True, "ok"
    monkeypatch.setattr(services, "apply_iptables", fake_apply)
    monkeypatch.setattr(services, "get_gateway_state",
                        lambda: (services.GatewayState.CONNECTED, ""))
    return calls


MAC = "20:ef:bd:65:a3:30"


def test_blocking_persists_kicks_and_reapplies_iptables(blocklist):
    ok, _ = services.block_device(MAC, "Roku")
    assert ok
    assert MAC in rules_mod.blocked_mac_set(rules_mod.load_blocked_devices())
    # Kicked immediately rather than left associated until it notices.
    assert blocklist["kicked"] == [MAC]
    assert blocklist["iptables"] == 1


def test_unblocking_kicks_so_the_device_rejoins_cleanly(blocklist):
    """The regression: without a deauth the device keeps a dead lease and
    stays dark after being unblocked."""
    services.block_device(MAC, "Roku")
    blocklist["kicked"].clear()

    ok, _ = services.set_device_blocked(MAC, False)
    assert ok
    assert MAC not in rules_mod.blocked_mac_set(rules_mod.load_blocked_devices())
    assert blocklist["kicked"] == [MAC], "unblock must force a clean rejoin"


def test_unblock_reapplies_iptables(blocklist):
    """The DROP rule must actually be removed, not just the YAML flag."""
    services.block_device(MAC, "Roku")
    before = blocklist["iptables"]
    services.set_device_blocked(MAC, False)
    assert blocklist["iptables"] > before


def test_entry_survives_unblock_so_it_can_be_reblocked(blocklist):
    """A blocked device drops off the 'seen' list, so the entry must remain
    findable in order to be toggled back on."""
    services.block_device(MAC, "Roku")
    services.set_device_blocked(MAC, False)
    entries = rules_mod.load_blocked_devices()["devices"]
    assert [e["mac"] for e in entries] == [MAC]
    assert entries[0]["blocked"] is False


def test_reblocking_an_existing_entry_works(blocklist):
    services.block_device(MAC, "Roku")
    services.set_device_blocked(MAC, False)
    services.set_device_blocked(MAC, True)
    assert MAC in rules_mod.blocked_mac_set(rules_mod.load_blocked_devices())


def test_block_unblock_cycle_is_idempotent(blocklist):
    """Repeated toggling must not duplicate entries or drift."""
    for _ in range(5):
        services.block_device(MAC, "Roku")
        services.set_device_blocked(MAC, False)
    entries = rules_mod.load_blocked_devices()["devices"]
    assert len(entries) == 1
    assert entries[0]["blocked"] is False


def test_failed_iptables_does_not_report_success(blocklist, monkeypatch):
    """A block that could not be enforced must not claim it was."""
    monkeypatch.setattr(services, "apply_iptables", lambda: (False, "iptables boom"))
    ok, msg = services.set_device_blocked(MAC, True)
    assert ok is False
    assert "boom" in msg


def test_failed_iptables_skips_the_kick(blocklist, monkeypatch):
    """Don't disrupt a device for a change that did not take effect."""
    monkeypatch.setattr(services, "apply_iptables", lambda: (False, "nope"))
    services.set_device_blocked(MAC, True)
    assert blocklist["kicked"] == []
