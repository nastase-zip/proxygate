"""
Hotspot device discovery (services.list_hotspot_devices and friends).

Regression cover for three real bugs found here:
  1. `ip neigh show dev X` omits the "dev X" field its unscoped form prints,
     so a parser keyed on a fixed field count matched nothing.
  2. HOTSPOT_IF stayed at the "ap0" placeholder when the AP was already up,
     making every interface-scoped command fail silently.
  3. NM's shared-mode dnsmasq writes per-interface lease files, not
     /var/lib/misc/dnsmasq.leases — so hostnames were never found.
"""
import types

import pytest

from backend import services


# ── _neighbor_table parsing ───────────────────────────────────────────────────

SCOPED_OUTPUT = "192.168.100.140 lladdr d2:b6:62:ff:9a:12 REACHABLE\n"
UNSCOPED_OUTPUT = "192.168.100.140 dev wlp3s0 lladdr d2:b6:62:ff:9a:12 REACHABLE\n"


def _fake_run(stdout: str):
    def run(cmd, **kw):
        return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
    return run


@pytest.mark.parametrize("output", [SCOPED_OUTPUT, UNSCOPED_OUTPUT])
def test_neighbor_table_parses_both_output_shapes(monkeypatch, output):
    """
    The scoped form (what the code actually runs) has 4 fields, the unscoped
    form 6. Both must parse — this is the bug that silently emptied the list.
    """
    monkeypatch.setattr(services, "HOTSPOT_IF", "wlp3s0")
    monkeypatch.setattr(services.subprocess, "run", _fake_run(output))
    assert services._neighbor_table() == {"192.168.100.140": "d2:b6:62:ff:9a:12"}


@pytest.mark.parametrize("state", ["FAILED", "INCOMPLETE"])
def test_stale_neighbor_entries_are_skipped(monkeypatch, state):
    """The kernel keeps rows for departed devices; they aren't connected."""
    monkeypatch.setattr(services, "HOTSPOT_IF", "wlp3s0")
    monkeypatch.setattr(services.subprocess, "run",
                        _fake_run(f"192.168.100.9 lladdr aa:bb:cc:dd:ee:ff {state}\n"))
    assert services._neighbor_table() == {}


def test_neighbor_entry_without_lladdr_is_skipped(monkeypatch):
    monkeypatch.setattr(services, "HOTSPOT_IF", "wlp3s0")
    monkeypatch.setattr(services.subprocess, "run",
                        _fake_run("192.168.100.9 INCOMPLETE\n"))
    assert services._neighbor_table() == {}


def test_neighbor_table_survives_command_failure(monkeypatch):
    def boom(cmd, **kw):
        raise OSError("no such device")
    monkeypatch.setattr(services.subprocess, "run", boom)
    assert services._neighbor_table() == {}


# ── current_hotspot_if ────────────────────────────────────────────────────────

def test_stale_placeholder_interface_is_reresolved(monkeypatch):
    """HOTSPOT_IF left at 'ap0' must be re-resolved, not used as-is."""
    monkeypatch.setattr(services, "HOTSPOT_IF", "ap0")
    monkeypatch.setattr(services, "_get_ap_if", lambda: "wlp3s0")
    assert services.current_hotspot_if() == "wlp3s0"


def test_resolved_interface_is_kept(monkeypatch):
    """A real name is trusted without re-querying NetworkManager."""
    monkeypatch.setattr(services, "HOTSPOT_IF", "wlp3s0")
    monkeypatch.setattr(services, "_get_ap_if",
                        lambda: pytest.fail("should not re-resolve"))
    assert services.current_hotspot_if() == "wlp3s0"


def test_unresolvable_interface_keeps_placeholder(monkeypatch):
    monkeypatch.setattr(services, "HOTSPOT_IF", "ap0")
    monkeypatch.setattr(services, "_get_ap_if", lambda: "ap0")
    assert services.current_hotspot_if() == "ap0"


# ── lease file discovery + parsing ────────────────────────────────────────────

def test_nm_per_interface_lease_path_is_preferred(monkeypatch):
    monkeypatch.setattr(services, "current_hotspot_if", lambda: "wlp3s0")
    paths = services._lease_file_candidates()
    assert paths[0] == "/var/lib/NetworkManager/dnsmasq-wlp3s0.leases"
    assert "/var/lib/misc/dnsmasq.leases" in paths


def test_read_leases_parses_hostnames(tmp_path, monkeypatch):
    lease = tmp_path / "dnsmasq-wlp3s0.leases"
    lease.write_text(
        "1758450000 d2:b6:62:ff:9a:12 192.168.100.140 iPhone 01:d2:b6:62:ff:9a:12\n"
        "1758450001 aa:bb:cc:dd:ee:ff 192.168.100.55 * *\n"
    )
    monkeypatch.setattr(services, "_lease_file_candidates", lambda: [str(lease)])

    rows = services._read_leases()
    assert ("d2:b6:62:ff:9a:12", "192.168.100.140", "iPhone") in rows
    # dnsmasq writes "*" when the client sent no hostname.
    assert ("aa:bb:cc:dd:ee:ff", "192.168.100.55", None) in rows


def test_read_leases_returns_empty_when_no_file(monkeypatch, tmp_path):
    monkeypatch.setattr(services, "_lease_file_candidates",
                        lambda: [str(tmp_path / "missing.leases")])
    assert services._read_leases() == []


# ── MAC vendor lookup ─────────────────────────────────────────────────────────

def test_randomized_mac_has_no_vendor(monkeypatch):
    """
    Locally-administered MACs (0x02 bit set) are randomized — the bytes are
    random, so any OUI 'match' would be meaningless rather than missing.
    """
    monkeypatch.setattr(services, "_load_oui",
                        lambda: {"d2:b6:62": "Should Never Match"})
    assert services._mac_vendor("d2:b6:62:ff:9a:12") is None


def test_global_mac_resolves_vendor(monkeypatch):
    monkeypatch.setattr(services, "_load_oui", lambda: {"10:e9:92": "INGRAM MICRO"})
    # The IEEE file shouts names in caps; all-caps entries are title-cased.
    assert services._mac_vendor("10:e9:92:11:22:33") == "Ingram Micro"


def test_mixed_case_vendor_is_left_alone(monkeypatch):
    monkeypatch.setattr(services, "_load_oui", lambda: {"28:6f:b9": "Nokia Shanghai Bell"})
    assert services._mac_vendor("28:6f:b9:aa:bb:cc") == "Nokia Shanghai Bell"


@pytest.mark.parametrize("mac", ["garbage", "", "zz:yy:xx:11:22:33", "10:e9"])
def test_malformed_mac_returns_none(monkeypatch, mac):
    monkeypatch.setattr(services, "_load_oui", lambda: {})
    assert services._mac_vendor(mac) is None


# ── list_hotspot_devices integration ──────────────────────────────────────────

@pytest.fixture
def stub_sources(monkeypatch):
    """Drive list_hotspot_devices from fake leases + neighbours."""
    def apply(leases, neighbours, subnet="192.168.100.0/24"):
        monkeypatch.setattr(services, "load_config",
                            lambda: {"hotspot_subnet": subnet})
        monkeypatch.setattr(services, "_read_leases", lambda: leases)
        monkeypatch.setattr(services, "_neighbor_table", lambda: neighbours)
        monkeypatch.setattr(services, "_mac_vendor", lambda mac: None)
    return apply


def test_lease_hostname_wins_over_neighbour(stub_sources):
    stub_sources(
        leases=[("d2:b6:62:ff:9a:12", "192.168.100.140", "iPhone")],
        neighbours={"192.168.100.140": "d2:b6:62:ff:9a:12"},
    )
    devs = services.list_hotspot_devices()
    assert len(devs) == 1
    assert devs[0]["hostname"] == "iPhone"
    assert devs[0]["display_name"] == "iPhone"


def test_neighbour_only_device_still_listed(stub_sources):
    """A device dnsmasq hasn't leased (static IP) must still appear."""
    stub_sources(leases=[], neighbours={"192.168.100.77": "aa:bb:cc:dd:ee:ff"})
    devs = services.list_hotspot_devices()
    assert len(devs) == 1
    assert devs[0]["ip"] == "192.168.100.77"
    # No hostname and no vendor: fall back to the IP so the row is selectable.
    assert devs[0]["display_name"] == "192.168.100.77"


def test_off_subnet_devices_are_excluded(stub_sources):
    """Docker bridges and LAN peers must not look like hotspot clients."""
    stub_sources(
        leases=[("11:22:33:44:55:66", "192.168.0.5", "lan-box")],
        neighbours={"172.18.0.2": "aa:aa:aa:aa:aa:aa",
                    "192.168.100.140": "d2:b6:62:ff:9a:12"},
    )
    devs = services.list_hotspot_devices()
    assert [d["ip"] for d in devs] == ["192.168.100.140"]


def test_devices_are_sorted_and_deduped(stub_sources):
    stub_sources(
        leases=[("aa:bb:cc:dd:ee:01", "192.168.100.50", "b"),
                ("aa:bb:cc:dd:ee:02", "192.168.100.20", "a")],
        # Same MAC as a lease — must not produce a duplicate row.
        neighbours={"192.168.100.50": "aa:bb:cc:dd:ee:01"},
    )
    devs = services.list_hotspot_devices()
    assert len(devs) == 2
    assert [d["ip"] for d in devs] == ["192.168.100.20", "192.168.100.50"]


def test_vendor_used_when_no_hostname(monkeypatch, stub_sources):
    stub_sources(leases=[], neighbours={"192.168.100.9": "10:e9:92:11:22:33"})
    monkeypatch.setattr(services, "_mac_vendor", lambda mac: "Ingram Micro")
    devs = services.list_hotspot_devices()
    assert devs[0]["display_name"] == "Ingram Micro"


def test_bad_subnet_config_does_not_crash(stub_sources):
    """A malformed subnet must degrade to 'show everything', not raise."""
    stub_sources(leases=[], neighbours={"192.168.100.9": "aa:bb:cc:dd:ee:ff"},
                 subnet="not-a-subnet")
    assert len(services.list_hotspot_devices()) == 1
