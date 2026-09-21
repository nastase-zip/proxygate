"""
MAC address validation.

Regression cover for a real incident: a blocked-devices entry with
mac: '123' made `iptables -A ... --mac-source 123` fail, and because that
call was a _must(), it aborted the ENTIRE iptables setup. The hotspot never
came up and the UI showed "Retry" with an iptables error — one junk row took
down the whole gateway.

Defended at three layers, all covered here:
  1. the API refuses to store a malformed MAC
  2. blocked_mac_set() filters any that are already in the file
  3. apply_iptables() uses _r (best effort) for the per-MAC rule
"""
import json

import pytest

from backend import rules as rules_mod
from backend import web as web_mod


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_mod, "DEVICES_PATH", str(tmp_path / "devices.yaml"))
    monkeypatch.setattr(rules_mod, "BLOCKED_DEVICES_PATH", str(tmp_path / "blocked.yaml"))
    monkeypatch.setattr(rules_mod, "reload_devices",
                        lambda data=None: (rules_mod.save_devices(data), (True, "ok"))[1]
                        if data is not None else (True, "ok"))
    monkeypatch.setattr(rules_mod, "reload_blocked_devices",
                        lambda data=None: (rules_mod.save_blocked_devices(data), (True, "ok"))[1]
                        if data is not None else (True, "ok"))
    web_mod.app.config.update(TESTING=True)
    return web_mod.app.test_client()


def body(resp):
    return json.loads(resp.data)


# ── the validator ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("mac", [
    "aa:bb:cc:dd:ee:ff",
    "AA:BB:CC:DD:EE:FF",
    "aa-bb-cc-dd-ee-ff",
    "00:00:00:00:00:00",
    "  aa:bb:cc:dd:ee:ff  ",
])
def test_valid_macs_accepted(mac):
    assert rules_mod.is_valid_mac(mac) is True


@pytest.mark.parametrize("mac", [
    "123",                  # the value from the incident
    "{'a': 1}",             # the other one
    "hello",
    "aa:bb:cc",             # too short
    "aa:bb:cc:dd:ee:ff:00",  # too long
    "gg:bb:cc:dd:ee:ff",    # not hex
    "",
    None,
    123,
    {"a": 1},
])
def test_invalid_macs_rejected(mac):
    assert rules_mod.is_valid_mac(mac) is False


# ── layer 1: the API ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("endpoint", ["/api/devices/blocked", "/api/devices/decrypt"])
def test_api_rejects_the_incident_value(client, endpoint):
    r = client.post(endpoint, json={"mac": 123, "label": ""})
    assert r.status_code == 400
    assert "not a valid MAC" in body(r)["msg"]


@pytest.mark.parametrize("endpoint", ["/api/devices/blocked", "/api/devices/decrypt"])
def test_api_rejects_structured_types(client, endpoint):
    r = client.post(endpoint, json={"mac": {"a": 1}, "label": [2]})
    assert r.status_code == 400


def test_api_accepts_a_real_mac(client):
    r = client.post("/api/devices/blocked", json={"mac": "AA-BB-CC-DD-EE-FF"})
    assert r.status_code == 200


def test_rejected_mac_is_not_persisted(client):
    client.post("/api/devices/blocked", json={"mac": "123"})
    assert body(client.get("/api/devices/blocked"))["data"]["devices"] == []


# ── layer 2: filtering before iptables ────────────────────────────────────────

def test_blocked_mac_set_skips_malformed_entries():
    """
    A hand-edited file can contain anything. Every value this returns becomes
    an iptables argument, so junk must be dropped here rather than passed on.
    """
    data = {"devices": [
        {"mac": "123", "blocked": True},
        {"mac": "{'a': 1}", "blocked": True},
        {"mac": "aa:bb:cc:dd:ee:ff", "blocked": True},
    ]}
    assert rules_mod.blocked_mac_set(data) == {"aa:bb:cc:dd:ee:ff"}


def test_blocked_mac_set_still_excludes_toggled_off_entries():
    data = {"devices": [
        {"mac": "aa:bb:cc:dd:ee:ff", "blocked": True},
        {"mac": "11:22:33:44:55:66", "blocked": False},
    ]}
    assert rules_mod.blocked_mac_set(data) == {"aa:bb:cc:dd:ee:ff"}


def test_blocked_mac_set_normalises_dashes_and_case():
    data = {"devices": [{"mac": "AA-BB-CC-DD-EE-FF", "blocked": True}]}
    assert rules_mod.blocked_mac_set(data) == {"aa:bb:cc:dd:ee:ff"}
