"""
/api/settings validation.

Regression cover for a real incident: posting {"ap_ssid": {"a":1},
"hotspot_gw": [1]} wrote the literal strings "{'a': 1}" and "[1]" into
config.yaml. The hotspot then refused to start, because nmcli rejects
"[1]" as an ipv4.address — long after the bad value was accepted, with the
AP already half torn down.

Every test here writes to a TEMP config. The incident happened because a
probe was run against the live one.
"""
import json

import pytest

from backend import services
from backend import web as web_mod


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(services, "CONFIG_PATH", str(tmp_path / "config.yaml"))
    web_mod.app.config.update(TESTING=True)
    return web_mod.app.test_client()


def body(resp):
    return json.loads(resp.data)


# ── type rejection ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("payload,field", [
    ({"ap_ssid": {"a": 1}, "hotspot_gw": "192.168.100.1"}, "ap_ssid"),
    ({"ap_ssid": "X", "hotspot_gw": [1]}, "hotspot_gw"),
    ({"ap_ssid": ["a"], "hotspot_gw": "192.168.100.1"}, "ap_ssid"),
])
def test_non_string_fields_are_rejected_not_coerced(client, payload, field):
    """
    str()-ing these stops the 500 but stores nonsense. A 400 is correct:
    "[1]" is not a gateway IP, and pretending it is defers the failure to
    nmcli where it's far harder to diagnose.
    """
    r = client.post("/api/settings", json=payload)
    assert r.status_code == 400
    assert field in body(r)["msg"]


def test_the_exact_payload_from_the_incident_is_rejected(client):
    r = client.post("/api/settings", json={"ap_ssid": {"a": 1}, "hotspot_gw": [1]})
    assert r.status_code == 400


def test_bad_payload_does_not_modify_the_config(client):
    before = services.load_config()
    client.post("/api/settings", json={"ap_ssid": {"a": 1}, "hotspot_gw": [1]})
    assert services.load_config() == before, "a rejected request must write nothing"


def test_numbers_are_still_accepted_as_text(client):
    """A client sending a port or SSID unquoted is reasonable; only
    structured types (dict/list) are refused."""
    r = client.post("/api/settings", json={"ap_ssid": 12345,
                                           "hotspot_gw": "192.168.100.1"})
    assert r.status_code == 200
    assert services.load_config()["ap_ssid"] == "12345"


# ── gateway IP format ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("gw", ["not-an-ip", "[1]", "999.1.1.1", "192.168.1", "1.2.3.4.5"])
def test_invalid_gateway_ip_is_rejected(client, gw):
    r = client.post("/api/settings", json={"ap_ssid": "X", "hotspot_gw": gw})
    assert r.status_code == 400
    assert "valid IP" in body(r)["msg"]


def test_ipv6_gateway_is_rejected(client):
    """The hotspot's DHCP range is IPv4; an IPv6 gateway would break the
    derived subnet silently."""
    r = client.post("/api/settings", json={"ap_ssid": "X", "hotspot_gw": "fe80::1"})
    assert r.status_code == 400
    assert "IPv4" in body(r)["msg"]


def test_empty_fields_are_rejected(client):
    assert client.post("/api/settings",
                       json={"ap_ssid": "", "hotspot_gw": "192.168.100.1"}).status_code == 400
    assert client.post("/api/settings",
                       json={"ap_ssid": "X", "hotspot_gw": ""}).status_code == 400


# ── the happy path still works ────────────────────────────────────────────────

def test_valid_settings_save_and_derive_the_subnet(client):
    r = client.post("/api/settings", json={"ap_ssid": "ProxyGate",
                                           "hotspot_gw": "10.9.0.1"})
    assert r.status_code == 200
    cfg = services.load_config()
    assert cfg["hotspot_gw"] == "10.9.0.1"
    assert cfg["hotspot_subnet"] == "10.9.0.0/24"


def test_subnet_derivation_handles_a_non_dot_zero_gateway(client):
    """The old string-surgery version produced garbage for anything unusual;
    ip_network() masks it correctly."""
    client.post("/api/settings", json={"ap_ssid": "X", "hotspot_gw": "172.16.5.254"})
    assert services.load_config()["hotspot_subnet"] == "172.16.5.0/24"
