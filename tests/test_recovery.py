"""
Automatic recovery — no manual WiFi toggling, no CA reinstalls.

Two things a user should never have to do by hand:

  1. Toggle a device's WiFi after the gateway restarts. Bringing the gateway
     up recreates the AP and reprograms NAT underneath any already-associated
     device, which keeps a lease, ARP entry and sockets that all reference the
     PREVIOUS state. It stays associated and silent until someone power-cycles
     its WiFi. One deauth makes it reassociate and re-DHCP automatically.

  2. Reinstall the CA. Without an explicit confdir, mitmproxy resolves
     ~/.mitmproxy from $HOME at launch; whenever that differs (sudo with or
     without -H, a systemd unit, a different invoking user) it finds no CA and
     GENERATES A NEW ONE, invalidating every certificate already trusted on a
     device.
"""
import os
import types

import pytest

from backend import services


# ── Client resync after the gateway comes up ─────────────────────────────────

@pytest.fixture
def kicks(monkeypatch):
    seen = []
    monkeypatch.setattr(services, "kick_device", lambda mac: seen.append(mac))
    return seen


def test_associated_clients_are_kicked_so_they_re_dhcp(kicks, monkeypatch):
    monkeypatch.setattr(services, "_associated_stations",
                        lambda: {"02:da:96:dc:a5:de", "20:ef:bd:65:a3:30"})
    monkeypatch.setattr(services, "_blocked_mac_set", lambda: set())
    assert services._resync_associated_clients() == 2
    assert set(kicks) == {"02:da:96:dc:a5:de", "20:ef:bd:65:a3:30"}


def test_blocked_devices_are_not_kicked(kicks, monkeypatch):
    """They are meant to stay off; kicking them is pointless noise."""
    monkeypatch.setattr(services, "_associated_stations",
                        lambda: {"02:da:96:dc:a5:de", "20:ef:bd:65:a3:30"})
    monkeypatch.setattr(services, "_blocked_mac_set", lambda: {"20:ef:bd:65:a3:30"})
    assert services._resync_associated_clients() == 1
    assert kicks == ["02:da:96:dc:a5:de"]


def test_resync_with_no_clients_is_a_noop(kicks, monkeypatch):
    monkeypatch.setattr(services, "_associated_stations", lambda: set())
    monkeypatch.setattr(services, "_blocked_mac_set", lambda: set())
    assert services._resync_associated_clients() == 0


def test_resync_survives_a_failing_blocklist(kicks, monkeypatch):
    """A broken blocklist must not stop clients being recovered."""
    def boom():
        raise OSError("unreadable")
    monkeypatch.setattr(services, "_blocked_mac_set", boom)
    monkeypatch.setattr(services, "_associated_stations", lambda: {"02:da:96:dc:a5:de"})
    assert services._resync_associated_clients() == 1


# ── CA stability ──────────────────────────────────────────────────────────────

def test_ca_directory_is_absolute_and_not_home_dependent():
    """$HOME-relative means a new CA whenever HOME changes — the exact cause
    of 'the CA stopped working, install it again'."""
    assert os.path.isabs(services.MITM_CONF_DIR)
    assert ".mitmproxy" not in os.path.basename(services.MITM_CONF_DIR) or \
        services.MITM_CONF_DIR.startswith(services.PROJECT_ROOT)


def test_mitmdump_is_launched_with_a_pinned_confdir():
    """Regression guard: dropping `--set confdir` silently re-introduces the
    rotating-CA bug, where mitmproxy mints a fresh CA whenever $HOME differs
    and every device's installed certificate stops working.

    Asserted against the source of the launch command rather than by running
    it, so the guard holds without needing a live mitmdump or the manager's
    internal locking.
    """
    import inspect
    src = inspect.getsource(services.MitmproxyManager._launch)
    assert "confdir=" in src, \
        "mitmdump launched without a pinned confdir — CA will rotate with $HOME"
    assert "MITM_CONF_DIR" in src
    # And the migration must run before launch, or pinning would itself
    # invalidate an already-installed certificate.
    assert "_migrate_existing_ca" in src


def test_existing_ca_is_migrated_not_regenerated(tmp_path, monkeypatch):
    """Pinning confdir must not itself invalidate an installed certificate."""
    old_home = tmp_path / "root"
    old_ca_dir = old_home / ".mitmproxy"
    old_ca_dir.mkdir(parents=True)
    (old_ca_dir / "mitmproxy-ca.pem").write_text("OLD-CA-KEY")
    (old_ca_dir / "mitmproxy-ca-cert.pem").write_text("OLD-CA-CERT")

    dest = tmp_path / "pinned"
    dest.mkdir()
    monkeypatch.setattr(services, "MITM_CONF_DIR", str(dest))
    monkeypatch.setattr(services.os.path, "expanduser",
                        lambda p: str(old_home) if "root" in p else str(old_home))

    services._migrate_existing_ca()
    assert (dest / "mitmproxy-ca.pem").read_text() == "OLD-CA-KEY"
    assert (dest / "mitmproxy-ca-cert.pem").read_text() == "OLD-CA-CERT"


def test_migration_never_overwrites_an_existing_ca(tmp_path, monkeypatch):
    """Once pinned, the CA in place wins — re-copying an older one would
    invalidate certificates installed since."""
    old_home = tmp_path / "root"
    (old_home / ".mitmproxy").mkdir(parents=True)
    (old_home / ".mitmproxy" / "mitmproxy-ca.pem").write_text("OLD")

    dest = tmp_path / "pinned"
    dest.mkdir()
    (dest / "mitmproxy-ca.pem").write_text("CURRENT")

    monkeypatch.setattr(services, "MITM_CONF_DIR", str(dest))
    monkeypatch.setattr(services.os.path, "expanduser", lambda p: str(old_home))

    services._migrate_existing_ca()
    assert (dest / "mitmproxy-ca.pem").read_text() == "CURRENT"


def test_migration_is_safe_when_nothing_to_migrate(tmp_path, monkeypatch):
    dest = tmp_path / "pinned"
    dest.mkdir()
    monkeypatch.setattr(services, "MITM_CONF_DIR", str(dest))
    monkeypatch.setattr(services.os.path, "expanduser", lambda p: str(tmp_path / "nowhere"))
    services._migrate_existing_ca()  # must not raise


# ── File ownership ────────────────────────────────────────────────────────────
#
# ProxyGate needs root for iptables, the hotspot and NetworkManager — but
# everything it writes lives inside the user's own checkout. Anything left
# root-owned locks them out of their own project directory and forces a manual
# chown. rules.py already restored ownership for the YAML config; the CA
# directory and the log directory were missed and ended up root:root beside
# user-owned files.

def test_restore_owner_hands_files_back_to_the_invoking_user(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(services.os, "chown",
                        lambda p, u, g: calls.update(path=p, uid=u, gid=g))
    f = tmp_path / "thing"
    f.write_text("x")
    services._restore_owner(str(f))
    assert calls == {"path": str(f), "uid": 1000, "gid": 1000}


def test_restore_owner_is_a_noop_without_sudo(tmp_path, monkeypatch):
    """Run directly as root there is no invoking user to restore to."""
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    called = []
    monkeypatch.setattr(services.os, "chown", lambda *a: called.append(a))
    f = tmp_path / "thing"
    f.write_text("x")
    services._restore_owner(str(f))
    assert called == []


def test_restore_owner_never_raises(tmp_path, monkeypatch):
    """Ownership is a convenience; failing it must not break a write."""
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    def boom(*a):
        raise OSError("read-only fs")
    monkeypatch.setattr(services.os, "chown", boom)
    monkeypatch.setattr(services.os, "chmod", boom)
    services._restore_owner(str(tmp_path / "missing"))   # must not raise


def test_directories_get_traversable_mode(tmp_path, monkeypatch):
    """0644 on a directory would make it unenterable — dirs need the x bit."""
    modes = {}
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(services.os, "chown", lambda *a: None)
    monkeypatch.setattr(services.os, "chmod", lambda p, m: modes.update(mode=m))
    services._restore_owner(str(tmp_path), is_dir=True)
    assert modes["mode"] & 0o111, "directory must stay traversable"


def test_ca_private_key_is_not_world_readable(tmp_path, monkeypatch):
    """The cert is meant to be handed out; the KEY must not be. Loosening
    permissions on the whole directory would expose it."""
    import inspect
    src = inspect.getsource(services.MitmproxyManager._launch)
    # Only the public cert files are explicitly relaxed.
    assert "mitmproxy-ca-cert.pem" in src
    assert "mitmproxy-ca.pem" not in src.split("_restore_owner(cert)")[0].split(
        "for name in")[-1], "the private key must not be in the relaxed list"
