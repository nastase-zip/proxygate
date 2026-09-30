"""
The decrypt gate across a MAC rotation (mitm_logger.DevicesEngine).

This is the layer that decides, per connection, whether to terminate TLS. If
it stops recognizing a phone after the phone rotates its randomized MAC, the
device silently falls back to passthrough — which is what "the CA needs
reinstalling every few minutes" actually was.

The hostname fallback is deliberately narrow: it applies ONLY to randomized
MACs, so a device with a real burned-in address is never decrypted merely
because it shares a DHCP hostname with a flagged phone.
"""
import textwrap

import pytest

from backend import mitm_logger


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """A DevicesEngine reading a temp devices.yaml."""
    def build(yaml_text):
        path = tmp_path / "devices.yaml"
        path.write_text(textwrap.dedent(yaml_text))
        monkeypatch.setattr(mitm_logger, "DEVICES_PATH", str(path))
        return mitm_logger.DevicesEngine()
    return build


FLAGGED_RANDOM = """
    devices:
      - id: a
        mac: 02:da:96:dc:a5:de
        hostname: iPhone
        label: iPhone
        decrypt: true
"""

FLAGGED_BURNED_IN = """
    devices:
      - id: b
        mac: 20:ef:bd:65:a3:30
        hostname: Roku
        label: Roku
        decrypt: true
"""


def test_exact_mac_still_decrypts(engine):
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt("02:da:96:dc:a5:de") is True


def test_rotated_mac_decrypts_via_hostname(engine):
    """The regression: same phone, new address, same DHCP hostname."""
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt("d2:b6:62:ff:9a:12", "iPhone") is True


def test_rotated_mac_without_hostname_does_not_decrypt(engine):
    """No anchor to match on — must not decrypt a device we cannot identify,
    since decrypting an untrusting device breaks its connections outright."""
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt("d2:b6:62:ff:9a:12", None) is False


def test_unknown_device_sharing_hostname_is_not_decrypted_if_burned_in(engine):
    """A real OUI device must never inherit a flag via hostname."""
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt("20:ef:bd:65:a3:30", "iPhone") is False


def test_burned_in_flag_does_not_leak_to_other_devices(engine):
    """A flagged burned-in device contributes no hostname fallback at all."""
    e = engine(FLAGGED_BURNED_IN)
    assert e.should_decrypt("20:ef:bd:65:a3:30") is True
    assert e.should_decrypt("d2:b6:62:ff:9a:12", "Roku") is False


def test_unflagged_device_never_decrypts(engine):
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt("ee:11:22:33:44:55", "Android") is False


def test_hostname_match_is_case_insensitive(engine):
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt("d2:b6:62:ff:9a:12", "IPHONE") is True


def test_no_mac_never_decrypts(engine):
    """Unidentified source must stay passthrough even with a known hostname."""
    e = engine(FLAGGED_RANDOM)
    assert e.should_decrypt(None, "iPhone") is False
    assert e.should_decrypt("", "iPhone") is False


def test_decrypt_false_is_honoured(engine):
    e = engine("""
        devices:
          - id: a
            mac: 02:da:96:dc:a5:de
            hostname: iPhone
            decrypt: false
    """)
    assert e.should_decrypt("02:da:96:dc:a5:de") is False
    assert e.should_decrypt("d2:b6:62:ff:9a:12", "iPhone") is False


def test_missing_file_is_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(mitm_logger, "DEVICES_PATH", str(tmp_path / "nope.yaml"))
    e = mitm_logger.DevicesEngine()
    assert e.should_decrypt("02:da:96:dc:a5:de") is False


def test_malformed_yaml_fails_closed(tmp_path, monkeypatch):
    """A broken file must not decrypt everything — fail closed, not open."""
    path = tmp_path / "devices.yaml"
    path.write_text("devices: [[[ unclosed")
    monkeypatch.setattr(mitm_logger, "DEVICES_PATH", str(path))
    e = mitm_logger.DevicesEngine()
    assert e.should_decrypt("02:da:96:dc:a5:de") is False
    assert e.should_decrypt("d2:b6:62:ff:9a:12", "iPhone") is False
