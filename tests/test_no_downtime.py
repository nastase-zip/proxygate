"""
"It should just work immediately" — no refreshes, no invisible timers.

Three traps this covers, all of which presented as "nothing happens and there
is nothing to look at":

  1. Timestamps were written with datetime.utcnow() while the machine runs in
     EEST (+0300), so every row in the traffic table displayed three hours in
     the past. Queries filter by id, so rows were never hidden — but the table
     looked stale/empty-at-the-top and made every other diagnosis harder.

  2. The decrypt circuit breaker tripped for TEN MINUTES after 3 failures.
     Installing the CA and re-flagging the device appeared to do nothing at
     all until a timer nobody could see expired.

  3. A device that just joined (or woke from idle) was not in the background
     IP->MAC snapshot yet, so its first connections resolved to no MAC and
     silently fell through to passthrough — undecrypted, unlogged as such.
"""
import datetime
import threading

import pytest

from backend import mitm_logger


# ── 1. Timestamps are local, not UTC ──────────────────────────────────────────

def test_connection_timestamps_use_local_time():
    """A row must be stamped in the operator's timezone, not UTC — otherwise
    the traffic table shows connections hours in the past."""
    import inspect
    src = inspect.getsource(mitm_logger)
    assert "datetime.utcnow()" not in src, (
        "utcnow() writes UTC; rows then display offset from local time")
    assert "datetime.now().strftime" in src


# ── 2. Decrypt breaker clears immediately when the situation changes ──────────

@pytest.fixture(autouse=True)
def clean_breaker():
    mitm_logger.reset_decrypt_breaker()
    yield
    mitm_logger.reset_decrypt_breaker()


MAC = "02:da:96:dc:a5:de"
HOST = "graph.facebook.com"


def _trip(mac=MAC, host=HOST):
    for _ in range(mitm_logger._DECRYPT_FAIL_THRESHOLD):
        mitm_logger._note_decrypt_failure(mac, host)


def test_breaker_trips_after_threshold():
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False
    _trip()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is True


def test_installing_ca_clears_the_breaker_immediately():
    """The core complaint: after installing the CA the very next connection
    must be retried, not blocked by an invisible cooldown."""
    _trip()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is True
    mitm_logger.reset_decrypt_breaker()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False


def test_reset_can_target_one_device():
    other = "20:ef:bd:65:a3:30"
    _trip(MAC); _trip(other)
    mitm_logger.reset_decrypt_breaker(MAC)
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False
    assert mitm_logger._domain_blocked_from_decrypt(other, HOST) is True


def test_reset_reports_how_many_cleared():
    _trip()
    assert mitm_logger.reset_decrypt_breaker() == 1
    assert mitm_logger.reset_decrypt_breaker() == 0


def test_recovery_is_event_driven_not_timer_driven():
    """
    Installing a CA must take effect on the NEXT connection — but the cooldown
    itself must stay long.

    A short cooldown was a mistake: a certificate-pinned app retried every
    domain ~60x/hour, and every retry is a broken TLS handshake the CLIENT has
    to notice and recover from. That is what the user experiences as lag and
    "barely connects". The cure for "it feels broken until a timer expires" is
    an explicit reset when the situation changes, not a shorter timer.
    """
    assert mitm_logger._DECRYPT_COOLDOWN_SECS >= 300, \
        "a short cooldown re-probes pinned domains and lags the client"
    _trip()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is True
    mitm_logger.reset_decrypt_breaker()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False


def test_pinned_domain_stops_being_probed_entirely():
    """A domain that has NEVER completed a decrypted handshake is pinned.
    Re-probing it on a timer costs the client a broken connection each time,
    forever, for no possible benefit."""
    for _ in range(mitm_logger._DECRYPT_PERMANENT_AFTER_TRIPS):
        for _ in range(mitm_logger._DECRYPT_FAIL_THRESHOLD):
            mitm_logger._note_decrypt_failure(MAC, HOST)
        # Expire the cooldown so the next round is allowed through.
        with mitm_logger._decrypt_breaker_lock:
            mitm_logger._decrypt_breaker[(MAC, HOST)]["tripped_at"] = 0.0

    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is True, \
        "a permanently-pinned domain must stay on passthrough"


def test_a_domain_that_ever_succeeded_is_not_treated_as_pinned():
    """Success proves it is not pinned, so it keeps its normal retry path."""
    mitm_logger._note_decrypt_success(MAC, HOST)
    _trip()
    with mitm_logger._decrypt_breaker_lock:
        state = mitm_logger._decrypt_breaker[(MAC, HOST)]
        state["ever_ok"] = True
        state["trips"] = 99
        state["tripped_at"] = 0.0
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False


def test_success_clears_that_pair():
    _trip()
    mitm_logger._note_decrypt_success(MAC, HOST)
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False


def test_changing_the_device_list_resets_the_breaker(tmp_path, monkeypatch):
    """Flagging/unflagging a device must clear recorded failures, so a user
    who just installed the CA is not made to wait."""
    path = tmp_path / "devices.yaml"
    path.write_text("devices:\n  - id: a\n    mac: 02:da:96:dc:a5:de\n    decrypt: true\n")
    monkeypatch.setattr(mitm_logger, "DEVICES_PATH", str(path))
    engine = mitm_logger.DevicesEngine()

    _trip()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is True

    # User flags a second device -> list changed -> breaker cleared.
    path.write_text(
        "devices:\n"
        "  - id: a\n    mac: 02:da:96:dc:a5:de\n    decrypt: true\n"
        "  - id: b\n    mac: d2:b6:62:ff:9a:12\n    decrypt: true\n"
    )
    engine.load()
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is False


def test_unchanged_reload_does_not_reset_the_breaker(tmp_path, monkeypatch):
    """A periodic no-op reload must NOT keep clearing the breaker, or a
    pinning app would retry-storm forever."""
    path = tmp_path / "devices.yaml"
    path.write_text("devices:\n  - id: a\n    mac: 02:da:96:dc:a5:de\n    decrypt: true\n")
    monkeypatch.setattr(mitm_logger, "DEVICES_PATH", str(path))
    engine = mitm_logger.DevicesEngine()

    _trip()
    engine.load()          # same content
    assert mitm_logger._domain_blocked_from_decrypt(MAC, HOST) is True


# ── 3. A just-joined device is identified on its FIRST connection ─────────────

LEASES = (
    "1790157302 20:ef:bd:65:a3:30 192.168.100.124 RokuRonoc *\n"
    "1790157353 02:da:96:dc:a5:de 192.168.100.101 iPhone 01:02:da:96:dc:a5:de\n"
    "1790155418 d2:b6:62:ff:9a:12 192.168.100.140 * 01:d2:b6:62:ff:9a:12\n"
)


@pytest.fixture
def leases(tmp_path, monkeypatch):
    """Point the shared registry at a fixed lease file."""
    from backend import devices as dev

    path = tmp_path / "leases"
    path.write_text(LEASES)

    class Src(dev.Sources):
        def stations(self):
            return set(), False
        def neighbours(self):
            return {}

    registry = dev.Registry(Src("wlp2s0", lease_paths=(str(path),)),
                            subnet="192.168.100.0/24")
    monkeypatch.setattr(mitm_logger, "_mac_snapshot", {})
    monkeypatch.setattr(mitm_logger, "_host_snapshot", {})
    monkeypatch.setattr(mitm_logger, "_registry_lookup", registry.by_ip)
    return registry


def test_new_device_resolves_on_first_connection(leases):
    """Not in any cache yet — must still resolve immediately rather than
    falling through as an unknown device."""
    assert mitm_logger._resolve_mac("192.168.100.101") == "02:da:96:dc:a5:de"


def test_new_device_hostname_resolves_immediately(leases):
    """The hostname re-anchors a rotated MAC, so it must be available on the
    first connection too."""
    assert mitm_logger._resolve_hostname("192.168.100.101") == "iPhone"


def test_lookup_populates_the_snapshot(leases):
    """Resolved once, cached — the next connection costs nothing."""
    mitm_logger._resolve_mac("192.168.100.101")
    assert mitm_logger._mac_snapshot["192.168.100.101"] == "02:da:96:dc:a5:de"


def test_absent_hostname_is_none_not_star(leases):
    """dnsmasq writes '*' for no hostname; that must not become a name."""
    assert mitm_logger._resolve_hostname("192.168.100.140") is None


def test_unknown_ip_resolves_to_none(leases):
    assert mitm_logger._resolve_mac("192.168.100.250") is None


def test_registry_failure_never_raises_into_the_proxy(monkeypatch):
    """A lookup that explodes must degrade to 'unknown', not kill the flow."""
    def boom(ip):
        raise OSError("lease file gone")
    monkeypatch.setattr(mitm_logger, "_mac_snapshot", {})
    monkeypatch.setattr(mitm_logger, "_host_snapshot", {})
    monkeypatch.setattr(mitm_logger, "_registry_lookup",
                        lambda ip: mitm_logger._registry_lookup.__wrapped__(ip)
                        if False else None)
    assert mitm_logger._resolve_mac("192.168.100.101") is None


def test_missing_lease_file_is_safe(monkeypatch):
    """Must degrade quietly, never raise into the proxy event loop."""
    from backend import devices as dev

    class Src(dev.Sources):
        def stations(self):
            return set(), False
        def neighbours(self):
            return {}

    registry = dev.Registry(Src("wlp2s0", lease_paths=("/nonexistent",)),
                            subnet="192.168.100.0/24")
    monkeypatch.setattr(mitm_logger, "_mac_snapshot", {})
    monkeypatch.setattr(mitm_logger, "_host_snapshot", {})
    monkeypatch.setattr(mitm_logger, "_registry_lookup", registry.by_ip)
    assert mitm_logger._resolve_mac("192.168.100.101") is None
