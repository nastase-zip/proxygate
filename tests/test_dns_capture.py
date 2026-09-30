"""
Real-time DNS capture.

Hostnames in the traffic table come from dnsmasq's query log. This was broken
in three independent ways at once, all silent:

  1. PATH MISMATCH. The tailer waited on <project>/var/log/proxygate/dnsmasq.log
     while the dnsmasq drop-in writes the ABSOLUTE /var/log/proxygate/dnsmasq.log.
     Two different files. The tailer blocked forever on a path that never
     appeared, so DNS was NEVER captured, while 59 MB of queries piled up in
     the real file.

  2. REGEX MISSED CACHED ANSWERS. dnsmasq answers with "reply <name> is <ip>"
     OR "cached <name> is <ip>". Only "reply" was matched — and on a busy
     hotspot, where the same hostnames repeat constantly, cached answers are
     the majority. The domains a device visits MOST were the ones shown as
     bare IPs.

  3. NO ROTATION. Nothing truncated the log; it grew without bound.
"""
import os

import pytest

from backend import mitm_logger as ml
from backend import services


# ── Regex ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("line,host,ip", [
    ("Sep 22 14:24:01 dnsmasq[1]: reply api.tiktokv.com is 1.2.3.4",
     "api.tiktokv.com", "1.2.3.4"),
    ("Sep 22 14:24:01 dnsmasq[1]: cached example.com is 93.184.216.34",
     "example.com", "93.184.216.34"),
    ("Sep 22 14:24:01 dnsmasq[1]: reply graph.facebook.com is 31.13.72.36",
     "graph.facebook.com", "31.13.72.36"),
])
def test_both_reply_and_cached_are_captured(line, host, ip):
    m = ml._DNS_REPLY_RE.search(line)
    assert m, "answer not recognised — hostname would be missing from the table"
    assert (m.group(1), m.group(2)) == (host, ip)


def test_cached_answers_are_not_ignored():
    """The specific regression: cached hits are the majority of answers."""
    assert ml._DNS_REPLY_RE.search("cached foo.example is 10.0.0.1") is not None


@pytest.mark.parametrize("line", [
    "Sep 22 14:24:01 dnsmasq[1]: query[A] foo.com from 192.168.100.101",
    "Sep 22 14:24:01 dnsmasq[1]: forwarded foo.com to 8.8.8.8",
    "Sep 22 14:24:01 dnsmasq[1]: reply foo.com is <CNAME>",
])
def test_non_answer_lines_are_ignored(line):
    assert ml._DNS_REPLY_RE.search(line) is None


def test_ipv6_answers_do_not_produce_bogus_rows():
    """Only A records carry an IPv4 the connection table can key on."""
    assert ml._DNS_REPLY_RE.search("reply foo.com is 2606:4700::1111") is None


# ── Log discovery ─────────────────────────────────────────────────────────────

def test_log_path_is_read_from_the_dnsmasq_dropin(tmp_path, monkeypatch):
    """The tailer must follow whatever log-facility dnsmasq was configured
    with, not a hardcoded guess that silently disagrees with it."""
    conf_dir = tmp_path / "dnsmasq-shared.d"
    conf_dir.mkdir()
    (conf_dir / "proxygate-logging.conf").write_text(
        "log-queries\nlog-facility=/var/log/proxygate/dnsmasq.log\n")
    monkeypatch.setattr(ml.os, "listdir", lambda p: ["proxygate-logging.conf"])

    real_open = open

    def fake_open(path, *a, **kw):
        if str(path).endswith("proxygate-logging.conf"):
            return real_open(conf_dir / "proxygate-logging.conf", *a, **kw)
        raise FileNotFoundError(path)

    monkeypatch.setattr("builtins.open", fake_open)
    assert "/var/log/proxygate/dnsmasq.log" in ml._dnsmasq_log_candidates()


def test_candidates_include_the_absolute_fallback():
    """Even with no drop-in readable, the real location must be tried — this
    is the path the tailer previously never looked at."""
    assert "/var/log/proxygate/dnsmasq.log" in ml._dnsmasq_log_candidates()


def test_resolve_picks_the_first_readable_log(tmp_path, monkeypatch):
    good = tmp_path / "real.log"
    good.write_text("reply a.com is 1.2.3.4\n")
    monkeypatch.setattr(ml, "_dnsmasq_log_candidates",
                        lambda: ["/nonexistent/one", str(good)])
    assert ml._resolve_dnsmasq_log() == str(good)


def test_resolve_returns_none_when_nothing_readable(monkeypatch):
    """Must report rather than block forever, which is what it used to do."""
    monkeypatch.setattr(ml, "_dnsmasq_log_candidates", lambda: ["/nonexistent"])
    assert ml._resolve_dnsmasq_log() is None


# ── Configuration is owned by the app ─────────────────────────────────────────

def test_ensure_dns_logging_writes_the_dropin(tmp_path, monkeypatch):
    """A fresh install previously had NO dns capture until someone placed this
    file by hand."""
    conf_dir = tmp_path / "dnsmasq-shared.d"
    log_path = tmp_path / "log" / "dnsmasq.log"
    monkeypatch.setattr(services, "DNSMASQ_DROPIN_DIR", str(conf_dir))
    monkeypatch.setattr(services, "DNSMASQ_LOG_PATH", str(log_path))

    ok, _msg = services.ensure_dns_logging()
    assert ok
    written = (conf_dir / "proxygate-logging.conf").read_text()
    assert "log-queries" in written
    assert f"log-facility={log_path}" in written


def test_ensure_dns_logging_is_idempotent(tmp_path, monkeypatch):
    conf_dir = tmp_path / "dnsmasq-shared.d"
    monkeypatch.setattr(services, "DNSMASQ_DROPIN_DIR", str(conf_dir))
    monkeypatch.setattr(services, "DNSMASQ_LOG_PATH", str(tmp_path / "d.log"))
    services.ensure_dns_logging()
    ok, msg = services.ensure_dns_logging()
    assert ok and "already" in msg


def test_ensure_dns_logging_never_raises(monkeypatch):
    """Must not take the gateway down if /etc is not writable."""
    monkeypatch.setattr(services, "DNSMASQ_DROPIN_DIR", "/proc/cannot/write/here")
    ok, msg = services.ensure_dns_logging()
    assert ok is False and msg


# ── Rotation ──────────────────────────────────────────────────────────────────

def test_log_is_rotated_once_it_exceeds_the_cap(tmp_path, monkeypatch):
    """Unmanaged, this reached 59 MB and kept growing — dnsmasq logs every
    query AND every cache hit."""
    log_path = tmp_path / "dnsmasq.log"
    log_path.write_bytes(b"x" * 2048)
    monkeypatch.setattr(services, "DNSMASQ_LOG_PATH", str(log_path))
    monkeypatch.setattr(services, "DNSMASQ_LOG_MAX_BYTES", 1024)

    assert services.rotate_dns_log() is True
    assert log_path.stat().st_size == 0


def test_small_log_is_left_alone(tmp_path, monkeypatch):
    log_path = tmp_path / "dnsmasq.log"
    log_path.write_bytes(b"x" * 10)
    monkeypatch.setattr(services, "DNSMASQ_LOG_PATH", str(log_path))
    monkeypatch.setattr(services, "DNSMASQ_LOG_MAX_BYTES", 1024)
    assert services.rotate_dns_log() is False
    assert log_path.stat().st_size == 10


def test_rotation_truncates_rather_than_replacing(tmp_path, monkeypatch):
    """dnsmasq holds the fd open. Renaming would leave it writing to a deleted
    inode and the log would appear to stop forever."""
    log_path = tmp_path / "dnsmasq.log"
    log_path.write_bytes(b"x" * 2048)
    inode_before = log_path.stat().st_ino
    monkeypatch.setattr(services, "DNSMASQ_LOG_PATH", str(log_path))
    monkeypatch.setattr(services, "DNSMASQ_LOG_MAX_BYTES", 1024)
    services.rotate_dns_log()
    assert log_path.stat().st_ino == inode_before


def test_rotation_of_missing_file_is_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(services, "DNSMASQ_LOG_PATH", str(tmp_path / "nope.log"))
    assert services.rotate_dns_log() is False
