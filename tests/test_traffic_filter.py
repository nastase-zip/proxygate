"""
Own-traffic / non-hotspot filtering (mitm_logger._is_own_traffic).

Regression cover for two bugs found in this area: the gateway's own requests
appearing in the traffic table, and a LAN machine using the mitm port as a
plain proxy (mitmproxy binds 0.0.0.0, so the iptables REDIRECT's interface
scoping doesn't keep it out).
"""
import ipaddress

import pytest

from backend import mitm_logger as ml


@pytest.fixture
def filt(monkeypatch):
    """Pin the filter's config so tests don't depend on the live config.yaml."""
    cfg = ({"127.0.0.1", "::1", "192.168.100.1"},
           ipaddress.ip_network("192.168.100.0/24"))
    monkeypatch.setattr(ml, "_filter_config", lambda: cfg)
    return ml._is_own_traffic


@pytest.mark.parametrize("ip", [
    "192.168.100.140",
    "192.168.100.234",
    "192.168.100.2",
    "192.168.100.254",
])
def test_hotspot_clients_are_kept(filt, ip):
    assert filt(ip) is False


@pytest.mark.parametrize("ip", [
    "127.0.0.1",        # loopback
    "::1",              # loopback v6
    "127.0.0.53",       # systemd-resolved, still loopback
    "192.168.100.1",    # the gateway itself
])
def test_own_traffic_is_dropped(filt, ip):
    assert filt(ip) is True


@pytest.mark.parametrize("ip", [
    "192.168.0.196",    # LAN machine hitting the mitm port directly
    "192.168.0.115",    # this box's own LAN address
    "172.18.0.2",       # docker bridge peer
    "10.0.0.5",
    "8.8.8.8",
])
def test_non_hotspot_sources_are_dropped(filt, ip):
    assert filt(ip) is True


@pytest.mark.parametrize("ip", ["?", None, "", "   "])
def test_unknown_source_is_kept(filt, ip):
    """
    An indeterminate source must never be dropped: losing a real client's
    traffic is worse than logging one extra row.
    """
    assert filt(ip) is False


def test_garbage_source_is_kept(filt):
    assert filt("not-an-ip") is False


def test_subnet_boundaries(filt):
    """The /24 must not leak into adjacent ranges."""
    assert filt("192.168.101.5") is True
    assert filt("192.168.99.5") is True
    assert filt("192.168.100.255") is False


def test_falls_back_to_loopback_only_without_config(monkeypatch):
    """
    An unreadable config must not start dropping real clients by guessing a
    subnet — only loopback/own IPs are filtered in that case.
    """
    monkeypatch.setattr(ml, "_filter_config", lambda: ({"127.0.0.1", "::1"}, None))
    assert ml._is_own_traffic("127.0.0.1") is True
    assert ml._is_own_traffic("192.168.100.140") is False
    assert ml._is_own_traffic("192.168.0.196") is False


def test_filter_config_reads_yaml(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("hotspot_gw: 10.9.0.1\nhotspot_subnet: 10.9.0.0/24\n")
    monkeypatch.setattr(ml, "CONFIG_PATH", str(cfg))
    monkeypatch.setattr(ml, "_filter_cache", None)

    ips, subnet = ml._filter_config()
    assert "10.9.0.1" in ips
    assert subnet == ipaddress.ip_network("10.9.0.0/24")


def test_filter_config_survives_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "CONFIG_PATH", str(tmp_path / "nope.yaml"))
    monkeypatch.setattr(ml, "_filter_cache", None)

    ips, subnet = ml._filter_config()
    assert "127.0.0.1" in ips
    assert subnet is None
