"""
AP band/channel selection must be DETERMINISTIC across restarts.

The real failure this covers: the hotspot silently moved bands between runs.
The AP shares one radio with the IPv6 client link, so it inherits whatever
channel that link associates on. With no band configured, the BSS was chosen
purely by signal strength — and because the same SSID's 2.4 GHz and 5 GHz
radios trade places as RSSI fluctuates by a few dBm, consecutive restarts of
an UNCHANGED config landed on:

    12:11  BSS d4:dc:09:71:27:07  band=a   channel=44   (worked)
    12:21  BSS d4:dc:09:71:27:07  band=a   channel=44   (worked)
    12:45  BSS d4:dc:09:71:2e:d8  band=bg  channel=1    (broken)

Clients that were happy on an empty 5 GHz channel suddenly found a congested
2.4 GHz one. Nothing in the config changed; only the RSSI ordering did.
"""
import types

import pytest

from backend import services


def _scan(*bsses):
    """Build `iw scan dump` output. Each bss is (bssid, freq, ssid, signal)."""
    out = []
    for bssid, freq, ssid, signal in bsses:
        out.append(f"BSS {bssid}(on wlan-ipv6)")
        out.append(f"\tfreq: {freq}")
        out.append(f"\tsignal: {signal} dBm")
        out.append(f"\tSSID: {ssid}")
    return "\n".join(out) + "\n"


@pytest.fixture
def scan(monkeypatch):
    def apply(output):
        def run(cmd, **kw):
            if "scan" in cmd and "dump" in cmd:
                return types.SimpleNamespace(returncode=0, stdout=output, stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(services.subprocess, "run", run)
    return apply


# The two real BSSs observed on this network.
BSS_5G = "d4:dc:09:71:27:07"
BSS_24 = "d4:dc:09:71:2e:d8"
SSID = "POLYMOONIPv6"


def test_prefers_5ghz_when_24ghz_is_stronger(scan):
    """The exact regression: 2.4 GHz has the better RSSI, but picking it moves
    the hotspot off 5 GHz. Must still choose 5 GHz."""
    scan(_scan(
        (BSS_24, 2412.0, SSID, -54.0),   # stronger
        (BSS_5G, 5220.0, SSID, -66.0),   # weaker, but 5 GHz
    ))
    bssid, band = services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID)
    assert (bssid, band) == (BSS_5G, "a")


def test_choice_is_stable_regardless_of_rssi_ordering(scan):
    """Flipping which band is momentarily louder must NOT change the result —
    that instability is what moved the AP between restarts."""
    results = set()
    for sig_24, sig_5 in [(-54.0, -66.0), (-66.0, -54.0), (-60.0, -60.0)]:
        scan(_scan((BSS_24, 2412.0, SSID, sig_24), (BSS_5G, 5220.0, SSID, sig_5)))
        results.add(services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID))
    assert results == {(BSS_5G, "a")}, "band choice must not depend on RSSI noise"


def test_falls_back_to_24ghz_when_no_5ghz_in_range(scan):
    """2.4 GHz is still correct when it is the only option — the link must
    come up rather than refusing."""
    scan(_scan((BSS_24, 2412.0, SSID, -54.0)))
    bssid, band = services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID)
    assert (bssid, band) == (BSS_24, "bg")


def test_explicit_band_preference_still_wins(scan):
    """A configured band must override the 5 GHz default."""
    scan(_scan((BSS_24, 2412.0, SSID, -70.0), (BSS_5G, 5220.0, SSID, -50.0)))
    bssid, band = services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID, prefer_band="bg")
    assert (bssid, band) == (BSS_24, "bg")


def test_dfs_channels_are_never_chosen(scan):
    """The AP cannot start on a DFS channel on this hardware, so a DFS BSS
    must be skipped even though it is 5 GHz and strongest."""
    # 5260 MHz = channel 52, DFS.
    scan(_scan(
        ("aa:aa:aa:aa:aa:aa", 5260.0, SSID, -40.0),
        (BSS_24, 2412.0, SSID, -70.0),
    ))
    bssid, band = services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID)
    assert (bssid, band) == (BSS_24, "bg")


def test_strongest_5ghz_wins_among_several(scan):
    scan(_scan(
        (BSS_5G, 5220.0, SSID, -66.0),
        ("bb:bb:bb:bb:bb:bb", 5180.0, SSID, -48.0),
    ))
    bssid, band = services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID)
    assert (bssid, band) == ("bb:bb:bb:bb:bb:bb", "a")


def test_other_ssids_are_ignored(scan):
    scan(_scan(
        ("cc:cc:cc:cc:cc:cc", 5220.0, "SomeNeighbour", -30.0),
        (BSS_24, 2412.0, SSID, -70.0),
    ))
    bssid, band = services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID)
    assert (bssid, band) == (BSS_24, "bg")


def test_no_matching_ssid_returns_nothing(scan):
    scan(_scan(("cc:cc:cc:cc:cc:cc", 5220.0, "SomeNeighbour", -30.0)))
    assert services._non_dfs_bssid_for_ssid("wlan-ipv6", SSID) == (None, None)
