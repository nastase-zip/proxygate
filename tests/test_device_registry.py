"""
The device registry: one merged view, explicit provenance.

Replaces seven overlapping functions whose disagreements caused every device
bug we hit. Each case below is a real failure that reached the user.
"""
import pytest

from backend import devices as dev


class FakeSources(dev.Sources):
    """Drive the registry from fixed data — never touches the radio."""

    def __init__(self, leases=(), stations=None, neighbours=None):
        super().__init__(hotspot_if="wlp2s0")
        self._leases = list(leases)
        self._stations = stations
        self._neighbours = dict(neighbours or {})

    def leases(self):
        return list(self._leases)

    def stations(self):
        # stations=None models "the radio could not be read", which must be
        # distinguishable from "nobody is connected".
        if self._stations is None:
            return set(), False
        return set(self._stations), True

    def neighbours(self):
        return dict(self._neighbours)


def registry(**kw):
    return dev.Registry(FakeSources(**kw), subnet="192.168.100.0/24")


IPHONE = ("02:da:96:dc:a5:de", "192.168.100.101", "iPhone", None)
ROKU = ("20:ef:bd:65:a3:30", "192.168.100.124", "RokuRonoc", None)
ROTATED = ("d2:b6:62:ff:9a:12", "192.168.100.140", "iPhone", None)


# ── Merging ───────────────────────────────────────────────────────────────────

def test_lease_supplies_ip_and_hostname():
    d = registry(leases=[IPHONE]).snapshot()
    assert len(d) == 1
    assert (d[0].ip, d[0].hostname, d[0].display_name) == \
        ("192.168.100.101", "iPhone", "iPhone")


def test_arp_device_still_gets_its_lease_hostname():
    """The 'new device shows only IP and MAC' bug: ARP saw it first and
    inserted hostname=None, and setdefault then refused the lease's name."""
    r = registry(leases=[ROTATED], neighbours={"192.168.100.140": ROTATED[0]})
    d = r.snapshot()[0]
    assert d.hostname == "iPhone"
    assert d.sources == {"lease", "neighbour"}


def test_device_on_radio_only_is_listed():
    """Just joined, no DHCP yet — must be visible, not invisible."""
    d = registry(stations=[ROTATED[0]]).snapshot()
    assert [x.mac for x in d] == [ROTATED[0]]
    assert d[0].associated is True


def test_device_absent_from_radio_is_still_listed():
    """Union, not intersection. After a rotation the radio still lists the OLD
    MAC while the NEW one carries traffic — intersecting would hide the device
    that is actually working."""
    r = registry(leases=[ROTATED], stations=[IPHONE[0]])
    macs = {d.mac for d in r.snapshot()}
    assert macs == {ROTATED[0], IPHONE[0]}


def test_associated_flag_reflects_the_radio():
    r = registry(leases=[ROTATED], stations=[IPHONE[0]])
    by_mac = {d.mac: d for d in r.snapshot()}
    assert by_mac[IPHONE[0]].associated is True
    assert by_mac[ROTATED[0]].associated is False


def test_associated_is_none_when_radio_unreadable():
    """'Cannot tell' must not be reported as 'not connected'."""
    d = registry(leases=[IPHONE], stations=None).snapshot()[0]
    assert d.associated is None


def test_no_duplicate_rows_for_one_mac():
    r = registry(leases=[IPHONE], stations=[IPHONE[0]],
                 neighbours={"192.168.100.101": IPHONE[0]})
    assert len(r.snapshot()) == 1


def test_provenance_is_recorded():
    """Which source said what — so a wrong value can be traced."""
    r = registry(leases=[IPHONE], stations=[IPHONE[0]])
    assert r.snapshot()[0].sources == {"lease", "radio"}


# ── Ghost devices ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("state", ["STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE"])
def test_stale_neighbours_are_not_devices(state, monkeypatch):
    """ARP keeps a valid-looking row long after a device leaves. Treating
    those as present is what produced 'ghost devices'."""
    src = FakeSources()
    monkeypatch.setattr(src, "_run",
                        lambda *c: (0, f"192.168.100.140 lladdr {ROTATED[0]} {state}\n"))
    monkeypatch.setattr(src, "_iface_ok", lambda: True)
    assert dev.Sources.neighbours(src) == {}


@pytest.mark.parametrize("state", ["REACHABLE", "PERMANENT"])
def test_live_neighbours_count(state, monkeypatch):
    src = FakeSources()
    monkeypatch.setattr(src, "_run",
                        lambda *c: (0, f"192.168.100.140 lladdr {ROTATED[0]} {state}\n"))
    monkeypatch.setattr(src, "_iface_ok", lambda: True)
    assert dev.Sources.neighbours(src) == {"192.168.100.140": ROTATED[0]}


def test_unresolved_interface_yields_nothing(monkeypatch):
    """'ap0' means unresolved. An unscoped fallback would dump docker and LAN
    neighbours into the hotspot list."""
    src = dev.Sources(hotspot_if="ap0")
    def boom(*a, **kw):
        raise AssertionError("queried an unresolved interface")
    monkeypatch.setattr(src, "_run", boom)
    assert src.neighbours() == {}
    assert src.stations() == (set(), False)


def test_off_subnet_devices_are_excluded():
    """A docker bridge peer or the host's LAN gateway is not a client."""
    r = registry(leases=[("aa:bb:cc:dd:ee:01", "10.10.112.45", "laptop", None)],
                 neighbours={"172.20.0.2": "9e:42:3d:dc:b1:51"})
    assert r.snapshot() == []


# ── Hostname survival ─────────────────────────────────────────────────────────

def test_hostname_survives_lease_expiry():
    """A lease file holds only CURRENT leases; the device is still the same
    device and must not degrade to a bare IP mid-session."""
    src = FakeSources(leases=[IPHONE], stations=[IPHONE[0]])
    r = dev.Registry(src, subnet="192.168.100.0/24")
    assert r.snapshot()[0].hostname == "iPhone"
    src._leases = []                      # lease rolls, device still associated
    d = r.snapshot()[0]
    assert d.hostname == "iPhone"
    assert d.display_name == "iPhone"


def test_memo_never_invents_a_hostname():
    src = FakeSources(leases=[IPHONE])
    r = dev.Registry(src, subnet="192.168.100.0/24")
    r.snapshot()
    src._leases = [("aa:bb:cc:dd:ee:01", "192.168.100.50", None, None)]
    assert r.snapshot()[0].hostname is None


# ── Fast lookup for a just-joined device ──────────────────────────────────────

def test_by_ip_finds_a_device_not_yet_in_any_cache():
    """First connection after joining or waking must be identified, or it
    falls through unrecognised."""
    r = registry(leases=[IPHONE])
    d = r.by_ip("192.168.100.101")
    assert d.mac == IPHONE[0] and d.hostname == "iPhone"


def test_by_ip_does_not_touch_neighbours_on_the_fast_path():
    """Reading the neighbour table spawns `ip neigh`. On mitmproxy's event
    loop that stalls EVERY connection, not just this one — the cause of the
    proxy lagging and intermittently appearing dead. An IP with no DHCP lease
    is reported unknown rather than waited for."""
    r = registry(neighbours={"192.168.100.140": ROTATED[0]})
    assert r.by_ip("192.168.100.140") is None


def test_by_ip_consults_neighbours_when_explicitly_allowed():
    """Off the event loop, the full lookup is still available."""
    r = registry(neighbours={"192.168.100.140": ROTATED[0]})
    d = r.by_ip("192.168.100.140", allow_slow=True)
    assert d is not None and d.mac == ROTATED[0]


def test_by_ip_unknown_is_none():
    assert registry(leases=[IPHONE]).by_ip("192.168.100.250") is None


# ── Counting ──────────────────────────────────────────────────────────────────

def test_connected_count_uses_the_radio():
    """Leases and ARP persist after a device leaves and would over-count."""
    r = registry(leases=[IPHONE, ROKU, ROTATED], stations=[IPHONE[0]])
    assert r.connected_count() == 1


def test_connected_count_is_zero_when_radio_unreadable():
    assert registry(leases=[IPHONE], stations=None).connected_count() == 0


# ── Sorting ───────────────────────────────────────────────────────────────────

def test_devices_sort_numerically_by_ip():
    r = registry(leases=[
        ("aa:bb:cc:dd:ee:01", "192.168.100.101", None, None),
        ("aa:bb:cc:dd:ee:02", "192.168.100.99", None, None),
        ("aa:bb:cc:dd:ee:03", "192.168.100.9", None, None),
    ])
    assert [d.ip for d in r.snapshot()] == \
        ["192.168.100.9", "192.168.100.99", "192.168.100.101"]


def test_device_without_ip_sorts_last():
    r = registry(leases=[("aa:bb:cc:dd:ee:01", "192.168.100.50", None, None)],
                 stations=["aa:bb:cc:dd:ee:01", ROTATED[0]])
    assert r.snapshot()[-1].ip is None


# ── Identity helpers ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("mac", ["02:da:96:dc:a5:de", "d2:b6:62:ff:9a:12", "AA:BB:CC:DD:EE:FF"])
def test_randomized_macs_detected(mac):
    assert dev.is_randomized(mac) is True


@pytest.mark.parametrize("mac", ["20:ef:bd:65:a3:30", "00:1b:17:00:23:40"])
def test_burned_in_macs_detected(mac):
    assert dev.is_randomized(mac) is False


@pytest.mark.parametrize("mac", ["", "garbage", None, 123])
def test_malformed_macs_are_not_randomized(mac):
    assert dev.is_randomized(mac) is False


@pytest.mark.parametrize("mac,cid", [
    ("d2:b6:62:ff:9a:12", "01:d2:b6:62:ff:9a:12"),
    ("02:da:96:dc:a5:de", "01:02:da:96:dc:a5:de"),
])
def test_mac_derived_client_ids_rejected(mac, cid):
    """Every device on this hotspot sends '01:'+MAC — it rotates with the MAC,
    so it is not an independent identity."""
    assert dev.clean_client_id(cid, mac) is None


def test_independent_client_id_is_kept():
    assert dev.clean_client_id("00:01:00:01:2b:9c:ff:aa", "d2:b6:62:ff:9a:12") \
        == "00:01:00:01:2b:9c:ff:aa"


@pytest.mark.parametrize("cid", ["*", "", "   "])
def test_absent_client_id_is_none(cid):
    assert dev.clean_client_id(cid, "d2:b6:62:ff:9a:12") is None


def test_client_id_survives_lease_expiry():
    src = FakeSources(leases=[("d2:b6:62:ff:9a:12", "192.168.100.140",
                              "iPhone", "00:01:aa:bb")])
    r = dev.Registry(src, subnet="192.168.100.0/24")
    assert r.snapshot()[0].client_id == "00:01:aa:bb"
    src._leases = []
    src._stations = ["d2:b6:62:ff:9a:12"]
    assert r.snapshot()[0].client_id == "00:01:aa:bb"


# ── Robustness ────────────────────────────────────────────────────────────────

def test_malformed_lease_lines_are_skipped(tmp_path):
    path = tmp_path / "leases"
    path.write_text("garbage\n\n1790 02:da:96:dc:a5:de 192.168.100.101 iPhone *\n")
    src = dev.Sources(hotspot_if="wlp2s0", lease_paths=(str(path),))
    rows = src.leases()
    assert len(rows) == 1 and rows[0][0] == "02:da:96:dc:a5:de"


def test_missing_lease_file_is_safe():
    src = dev.Sources(hotspot_if="wlp2s0", lease_paths=("/nonexistent",))
    assert src.leases() == []


def test_bad_subnet_degrades_to_showing_everything():
    r = dev.Registry(FakeSources(leases=[IPHONE]), subnet="not-a-subnet")
    assert len(r.snapshot()) == 1


# ── Vendor ────────────────────────────────────────────────────────────────────

def test_vendor_is_used_when_there_is_no_hostname():
    """A bare MAC is unreadable in a list; the OUI vendor is not."""
    r = dev.Registry(FakeSources(leases=[("20:ef:bd:65:a3:30", "192.168.100.124", None, None)]),
                     subnet="192.168.100.0/24",
                     vendor_lookup=lambda mac: "Roku, Inc")
    d = r.snapshot()[0]
    assert d.vendor == "Roku, Inc"
    assert d.display_name == "Roku, Inc"


def test_hostname_outranks_vendor():
    r = dev.Registry(FakeSources(leases=[ROKU]), subnet="192.168.100.0/24",
                     vendor_lookup=lambda mac: "Roku, Inc")
    assert r.snapshot()[0].display_name == "RokuRonoc"


def test_display_name_falls_back_to_ip_then_mac():
    r = dev.Registry(FakeSources(leases=[("aa:bb:cc:dd:ee:01", "192.168.100.50", None, None)]),
                     subnet="192.168.100.0/24")
    assert r.snapshot()[0].display_name == "192.168.100.50"
    r2 = dev.Registry(FakeSources(stations=["aa:bb:cc:dd:ee:02"]),
                      subnet="192.168.100.0/24")
    assert r2.snapshot()[0].display_name == "aa:bb:cc:dd:ee:02"


# ── Event-loop safety ─────────────────────────────────────────────────────────
#
# by_ip() runs inside mitmproxy's synchronous tls_clienthello hook, driven
# straight from its asyncio loop. Anything slow there stalls EVERY connection
# the proxy is handling — which presented as the proxy lagging, pausing, and
# intermittently seeming dead.

class CountingSources(FakeSources):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.lease_reads = 0
        self.neighbour_reads = 0

    def leases(self):
        self.lease_reads += 1
        return super().leases()

    def neighbours(self):
        self.neighbour_reads += 1
        return super().neighbours()


class FakeClock:
    def __init__(self):
        self.t = 1000.0
    def __call__(self):
        return self.t
    def advance(self, dt):
        self.t += dt


def test_by_ip_never_spawns_a_subprocess():
    """Reading the neighbour table means running `ip neigh`. That must never
    happen on the event-loop path."""
    src = CountingSources(leases=[IPHONE], neighbours={"192.168.100.140": ROTATED[0]})
    r = dev.Registry(src, subnet="192.168.100.0/24")
    r.by_ip("192.168.100.250")          # a miss — the tempting case
    assert src.neighbour_reads == 0


def test_repeated_lookups_do_not_re_read_the_lease_file():
    """A busy device would otherwise re-read the file on every connection."""
    clock = FakeClock()
    src = CountingSources(leases=[IPHONE])
    r = dev.Registry(src, subnet="192.168.100.0/24", clock=clock)
    for _ in range(50):
        assert r.by_ip("192.168.100.101").mac == IPHONE[0]
    assert src.lease_reads == 1


def test_unknown_ip_is_cached_too():
    """The worst case is an unknown IP generating heavy traffic."""
    clock = FakeClock()
    src = CountingSources(leases=[IPHONE])
    r = dev.Registry(src, subnet="192.168.100.0/24", clock=clock)
    for _ in range(50):
        assert r.by_ip("192.168.100.250") is None
    assert src.lease_reads == 1


def test_cache_expires_so_a_new_device_is_seen():
    """Caching must not make a just-joined device invisible."""
    clock = FakeClock()
    src = CountingSources(leases=[])
    r = dev.Registry(src, subnet="192.168.100.0/24", clock=clock)
    assert r.by_ip("192.168.100.101") is None
    src._leases = [IPHONE]
    clock.advance(5.0)
    assert r.by_ip("192.168.100.101").mac == IPHONE[0]


def test_snapshot_does_not_hold_the_lock_during_io():
    """snapshot() runs subprocesses; holding the lock across them would block
    by_ip() on the event loop for as long as `iw` takes to return."""
    import threading

    held = []

    class SlowSources(FakeSources):
        def stations(self):
            # If the lock were held here, this acquire would deadlock the test.
            held.append(r._lock.acquire(blocking=False))
            if held[-1]:
                r._lock.release()
            return set(), False

    r = dev.Registry(SlowSources(leases=[IPHONE]), subnet="192.168.100.0/24")
    r.snapshot()
    assert held and all(held), "lock was held across source I/O"


def test_invalidate_forces_a_fresh_read():
    clock = FakeClock()
    src = CountingSources(leases=[IPHONE])
    r = dev.Registry(src, subnet="192.168.100.0/24", clock=clock)
    r.by_ip("192.168.100.101")
    r.invalidate()
    r.by_ip("192.168.100.101")
    assert src.lease_reads == 2


def test_lookup_cache_is_bounded():
    """A busy hotspot must not grow the cache without limit."""
    r = registry(leases=[IPHONE])
    for i in range(700):
        r.by_ip(f"192.168.100.{i % 254}")
    assert len(r._lookup_cache) <= 513
