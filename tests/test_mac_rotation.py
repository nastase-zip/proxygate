"""
MAC rotation — the root cause behind "the CA has to be reinstalled every few
minutes" and "ghost devices".

Phones randomize their WiFi MAC per network AND rotate it periodically (iOS
"Private Wi-Fi Address", Android "randomized MAC"). Every device identity in
ProxyGate was keyed purely on MAC, so a rotation:

  * detached the decrypt flag from the phone it was set for — decryption
    silently stopped applying, which presents as the CA no longer working,
  * left the OLD address still associated on the radio while the NEW one
    carried the traffic, so the device list showed entries that looked like
    ghosts alongside a "new" unnamed device,
  * left the new MAC with no DHCP hostname and no OUI vendor (randomized
    bytes have no vendor by design), so it rendered as a bare IP + MAC.

Observed live: d2:b6:62:ff:9a:12 (.140) carried 610 connections while
02:da:96:dc:a5:de was the address still listed as associated — the same
physical phone under two addresses.
"""
import pytest

from backend import rules as rules_mod
from backend import services


# ── Randomized-MAC detection ──────────────────────────────────────────────────

@pytest.mark.parametrize("mac", [
    "02:da:96:dc:a5:de",   # observed live (iPhone)
    "d2:b6:62:ff:9a:12",   # observed live (same phone, rotated)
    "AA:BB:CC:DD:EE:FF",   # 0xAA -> 0x02 bit set, uppercase
    "06:00:00:00:00:01",
])
def test_locally_administered_macs_are_randomized(mac):
    assert rules_mod.is_randomized_mac(mac) is True


@pytest.mark.parametrize("mac", [
    "20:ef:bd:65:a3:30",   # observed live (Roku, real OUI)
    "10:e9:92:11:22:33",
    "00:1b:17:00:23:40",
])
def test_burned_in_macs_are_not_randomized(mac):
    assert rules_mod.is_randomized_mac(mac) is False


@pytest.mark.parametrize("mac", ["", "garbage", "zz:yy:xx", None, 12345])
def test_malformed_macs_are_not_randomized(mac):
    """Must not raise — this feeds a decrypt decision."""
    assert rules_mod.is_randomized_mac(mac) is False


# ── Rebinding a rotated MAC ───────────────────────────────────────────────────

def _entry(mac, hostname=None, decrypt=True):
    d = {"id": "x", "mac": mac, "label": "", "decrypt": decrypt}
    if hostname:
        d["hostname"] = hostname
    return d


def test_rotation_rebinds_entry_to_current_mac():
    """The core fix: flag follows the phone across a rotation."""
    data = {"devices": [_entry("02:da:96:dc:a5:de", "iPhone")]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "d2:b6:62:ff:9a:12"
    assert rebinds == [("iphone", "02:da:96:dc:a5:de", "d2:b6:62:ff:9a:12")]


def test_no_rebind_while_original_mac_still_present():
    """Nothing rotated — the entry must be left completely alone."""
    data = {"devices": [_entry("02:da:96:dc:a5:de", "iPhone")]}
    current = [
        {"mac": "02:da:96:dc:a5:de", "hostname": "iPhone"},
        {"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"},
    ]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "02:da:96:dc:a5:de"
    assert rebinds == []


def test_ambiguous_hostname_never_rebinds():
    """Two phones both called 'iPhone' must never be merged into one."""
    data = {"devices": [_entry("02:da:96:dc:a5:de", "iPhone")]}
    current = [
        {"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"},
        {"mac": "ee:11:22:33:44:55", "hostname": "iPhone"},
    ]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "02:da:96:dc:a5:de"
    assert rebinds == []


def test_burned_in_mac_never_rebinds():
    """A real OUI address does not rotate; a hostname collision must not move
    the flag onto a different physical device."""
    data = {"devices": [_entry("20:ef:bd:65:a3:30", "Roku")]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "Roku"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "20:ef:bd:65:a3:30"
    assert rebinds == []


def test_never_rebinds_onto_a_mac_already_in_the_list():
    """Rebinding onto an existing entry's MAC would create a duplicate."""
    data = {"devices": [
        _entry("02:da:96:dc:a5:de", "iPhone"),
        _entry("d2:b6:62:ff:9a:12", "iPhone"),
    ]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert rebinds == []
    assert [d["mac"] for d in data["devices"]] == [
        "02:da:96:dc:a5:de", "d2:b6:62:ff:9a:12"]


def test_entry_without_hostname_cannot_rebind():
    """No anchor recorded — must degrade quietly, not guess."""
    data = {"devices": [_entry("02:da:96:dc:a5:de")]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert rebinds == []


def test_hostname_match_is_case_insensitive():
    data = {"devices": [_entry("02:da:96:dc:a5:de", "IPhone")]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "iphone"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "d2:b6:62:ff:9a:12"


def test_rebind_tolerates_junk_device_rows():
    """list_hotspot_devices output is not trusted blindly."""
    data = {"devices": [_entry("02:da:96:dc:a5:de", "iPhone")]}
    current = [{}, {"mac": ""}, {"hostname": "iPhone"},
               {"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "d2:b6:62:ff:9a:12"


def test_empty_inputs_are_safe():
    data, rebinds = rules_mod.rebind_rotated_macs({"devices": []}, [])
    assert rebinds == []
    data, rebinds = rules_mod.rebind_rotated_macs({}, [])
    assert rebinds == []


# ── remember_hostname ─────────────────────────────────────────────────────────

def test_remember_hostname_records_anchor():
    data = {"devices": [_entry("02:da:96:dc:a5:de")]}
    data = rules_mod.remember_hostname(data, "02:da:96:dc:a5:de", "iPhone")
    assert data["devices"][0]["hostname"] == "iPhone"


def test_remember_hostname_ignores_blank_and_unknown():
    data = {"devices": [_entry("02:da:96:dc:a5:de", "iPhone")]}
    data = rules_mod.remember_hostname(data, "02:da:96:dc:a5:de", "   ")
    assert data["devices"][0]["hostname"] == "iPhone"
    data = rules_mod.remember_hostname(data, "ff:ff:ff:ff:ff:ff", "Other")
    assert len(data["devices"]) == 1


# ── decrypt_hostname_set ──────────────────────────────────────────────────────

def test_hostname_set_only_covers_randomized_macs():
    """A burned-in MAC needs no hostname fallback; including it would widen
    the decrypt set for no benefit."""
    data = {"devices": [
        _entry("02:da:96:dc:a5:de", "iPhone"),
        _entry("20:ef:bd:65:a3:30", "Roku"),
    ]}
    assert rules_mod.decrypt_hostname_set(data) == {"iphone"}


def test_hostname_set_excludes_disabled_entries():
    data = {"devices": [_entry("02:da:96:dc:a5:de", "iPhone", decrypt=False)]}
    assert rules_mod.decrypt_hostname_set(data) == set()


# ── Composite identity scoring ────────────────────────────────────────────────
#
# No single signal is trusted alone. These pin the weighting so a future edit
# cannot quietly make a weak signal sufficient.

def test_client_id_beats_a_conflicting_hostname():
    """An independent client-id is conclusive; a matching hostname on a
    DIFFERENT device must not outrank it."""
    data = {"devices": [{"id": "x", "mac": "02:da:96:dc:a5:de", "decrypt": True,
                         "hostname": "iPhone", "client_id": "ff:de:ad:be:ef"}]}
    current = [
        {"mac": "d2:b6:62:ff:9a:12", "hostname": "Other", "client_id": "ff:de:ad:be:ef"},
        {"mac": "ee:11:22:33:44:55", "hostname": "iPhone"},
    ]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "d2:b6:62:ff:9a:12"


def test_disagreeing_client_ids_block_the_match():
    """Two independent ids that differ is positive evidence of DIFFERENT
    devices — a matching hostname must not override it."""
    data = {"devices": [{"id": "x", "mac": "02:da:96:dc:a5:de", "decrypt": True,
                         "hostname": "iPhone", "client_id": "aa:aa:aa"}]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone", "client_id": "bb:bb:bb"}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert rebinds == []
    assert data["devices"][0]["mac"] == "02:da:96:dc:a5:de"


def test_circumstantial_signals_alone_are_insufficient():
    """same-IP + mac-prefix + vendor (50) must NOT move a decrypt flag."""
    data = {"devices": [{"id": "x", "mac": "02:da:96:dc:a5:de", "decrypt": True,
                         "ip": "192.168.100.140", "vendor": "Apple, Inc."}]}
    current = [{"mac": "02:da:96:11:22:33", "ip": "192.168.100.140",
                "vendor": "Apple, Inc."}]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert rebinds == []


def test_corroborated_match_wins_over_bare_hostname_tie():
    """Two devices share the hostname, but one also matches on IP — the
    margin check must resolve in favour of the corroborated one."""
    data = {"devices": [{"id": "x", "mac": "02:da:96:dc:a5:de", "decrypt": True,
                         "hostname": "iPhone", "ip": "192.168.100.140"}]}
    current = [
        {"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone", "ip": "192.168.100.140"},
        {"mac": "ee:11:22:33:44:55", "hostname": "iPhone"},
    ]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert data["devices"][0]["mac"] == "d2:b6:62:ff:9a:12"


def test_two_identical_hostnames_stay_ambiguous():
    """Nothing distinguishes them — must refuse rather than coin-flip."""
    data = {"devices": [{"id": "x", "mac": "02:da:96:dc:a5:de", "decrypt": True,
                         "hostname": "iPhone"}]}
    current = [
        {"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone"},
        {"mac": "ee:11:22:33:44:55", "hostname": "iPhone"},
    ]
    data, rebinds = rules_mod.rebind_rotated_macs(data, current)
    assert rebinds == []


def test_rebind_refreshes_all_anchors():
    """After following a rotation the entry must carry the CURRENT signals,
    so the next rotation has more to match on than the one just consumed."""
    data = {"devices": [{"id": "x", "mac": "02:da:96:dc:a5:de", "decrypt": True,
                         "hostname": "iPhone"}]}
    current = [{"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone",
                "client_id": "ff:00:11", "ip": "192.168.100.140",
                "vendor": "Apple, Inc."}]
    data, _ = rules_mod.rebind_rotated_macs(data, current)
    e = data["devices"][0]
    assert e["mac"] == "d2:b6:62:ff:9a:12"
    assert e["client_id"] == "ff:00:11"
    assert e["ip"] == "192.168.100.140"


def test_scoring_helper_reports_reasons():
    """Reasons are logged, so a rebind is explainable rather than magic."""
    score, reasons = rules_mod._identity_score(
        {"mac": "02:da:96:dc:a5:de", "hostname": "iPhone", "ip": "192.168.100.140"},
        {"mac": "d2:b6:62:ff:9a:12", "hostname": "iPhone", "ip": "192.168.100.140"},
    )
    assert "hostname" in reasons and "same-ip" in reasons
    assert score >= rules_mod._REBIND_THRESHOLD
