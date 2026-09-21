"""
Decrypt gating (mitm_logger): which flows actually get TLS-terminated.

Decryption is opt-in per device, keyed by MAC. Anything that stops the MAC
from resolving silently disables decryption for that device with no error
anywhere, so the failure modes here matter more than the happy path.
"""
import threading

import pytest

from backend import mitm_logger as ml


@pytest.fixture(autouse=True)
def clean_state():
    with ml._mac_snapshot_lock:
        ml._mac_snapshot.clear()
    with ml._unresolved_lock:
        ml._unresolved_macs.clear()
    ml._mac_refresh_now.clear()
    ml._decrypt_breaker.clear()
    yield


def test_known_ip_resolves_to_its_mac():
    with ml._mac_snapshot_lock:
        ml._mac_snapshot["192.168.100.5"] = "aa:bb:cc:dd:ee:ff"
    assert ml._resolve_mac("192.168.100.5") == "aa:bb:cc:dd:ee:ff"


def test_unknown_ip_triggers_an_immediate_refresh():
    """
    A device that just joined isn't in the snapshot yet, so its first
    connections can't be evaluated for decryption. Without this nudge the
    blind window lasts a full refresh interval, which is exactly when the
    interesting traffic (app launch, login) happens.
    """
    assert ml._resolve_mac("192.168.100.99") is None
    assert ml._mac_refresh_now.is_set()


def test_unresolved_ip_is_logged_once_not_per_connection():
    for _ in range(50):
        ml._resolve_mac("192.168.100.77")
    assert ml._unresolved_macs == {"192.168.100.77"}


# ── circuit breaker ───────────────────────────────────────────────────────────

def test_breaker_opens_only_after_the_threshold():
    mac, host = "aa:bb:cc:dd:ee:ff", "pinned.example.com"
    for i in range(ml._DECRYPT_FAIL_THRESHOLD - 1):
        ml._note_decrypt_failure(mac, host)
        assert ml._domain_blocked_from_decrypt(mac, host) is False, f"tripped early at {i+1}"
    ml._note_decrypt_failure(mac, host)
    assert ml._domain_blocked_from_decrypt(mac, host) is True


def test_breaker_is_per_device_not_global():
    """
    One device failing a pinned domain says nothing about another device
    that has the CA properly trusted — a shared blocklist would silently
    kill decryption everywhere on the first failure anywhere.
    """
    host = "pinned.example.com"
    for _ in range(ml._DECRYPT_FAIL_THRESHOLD):
        ml._note_decrypt_failure("aa:aa:aa:aa:aa:aa", host)
    assert ml._domain_blocked_from_decrypt("aa:aa:aa:aa:aa:aa", host) is True
    assert ml._domain_blocked_from_decrypt("bb:bb:bb:bb:bb:bb", host) is False


def test_breaker_is_per_domain_not_per_device_wide():
    mac = "aa:bb:cc:dd:ee:ff"
    for _ in range(ml._DECRYPT_FAIL_THRESHOLD):
        ml._note_decrypt_failure(mac, "pinned.example.com")
    assert ml._domain_blocked_from_decrypt(mac, "pinned.example.com") is True
    assert ml._domain_blocked_from_decrypt(mac, "other.example.com") is False


def test_success_clears_the_breaker():
    mac, host = "aa:bb:cc:dd:ee:ff", "flaky.example.com"
    for _ in range(ml._DECRYPT_FAIL_THRESHOLD):
        ml._note_decrypt_failure(mac, host)
    assert ml._domain_blocked_from_decrypt(mac, host) is True
    ml._note_decrypt_success(mac, host)
    assert ml._domain_blocked_from_decrypt(mac, host) is False


def test_breaker_self_heals_after_the_cooldown(monkeypatch):
    """
    A tripped domain must get another chance later: a CA may have been
    installed, or an app updated to stop pinning. Staying blocked until
    restart would quietly lose coverage forever.
    """
    mac, host = "aa:bb:cc:dd:ee:ff", "pinned.example.com"
    for _ in range(ml._DECRYPT_FAIL_THRESHOLD):
        ml._note_decrypt_failure(mac, host)
    assert ml._domain_blocked_from_decrypt(mac, host) is True

    key = ml._breaker_key(mac, host)
    ml._decrypt_breaker[key]["tripped_at"] -= (ml._DECRYPT_COOLDOWN_SECS + 1)
    assert ml._domain_blocked_from_decrypt(mac, host) is False, "should allow a retry"


def test_mac_key_is_normalised():
    """Dashes vs colons and case must not create two separate breaker entries."""
    assert ml._breaker_key("AA-BB-CC-DD-EE-FF", "h") == ml._breaker_key("aa:bb:cc:dd:ee:ff", "h")
