"""
HTTP API contract tests (backend/web.py).

Everything the UI does goes through these routes, so they're tested against a
real Flask test client with the config files redirected into tmp_path and the
privileged side effects (iptables, signalling mitmdump) stubbed out.
"""
import json

import pytest

from backend import rules as rules_mod
from backend import services
from backend import web as web_mod


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_mod, "RULES_PATH", str(tmp_path / "rules.yaml"))
    monkeypatch.setattr(rules_mod, "DEVICES_PATH", str(tmp_path / "devices.yaml"))
    monkeypatch.setattr(rules_mod, "BLOCKED_DEVICES_PATH",
                        str(tmp_path / "blocked_devices.yaml"))

    # The real reload_* functions save the file AND then do privileged work
    # (iptables, signalling mitmdump). The stubs keep the save — otherwise
    # nothing persists and the tests wouldn't exercise the round-trip — and
    # drop only the privileged part.
    def stub(saver):
        def reload(data=None):
            if data is not None:
                saver(data)
            return True, "ok"
        return reload

    monkeypatch.setattr(rules_mod, "reload_rules", stub(rules_mod.save_rules))
    monkeypatch.setattr(rules_mod, "reload_devices", stub(rules_mod.save_devices))
    monkeypatch.setattr(rules_mod, "reload_blocked_devices",
                        stub(rules_mod.save_blocked_devices))

    web_mod.app.config.update(TESTING=True)
    return web_mod.app.test_client()


def body(resp):
    return json.loads(resp.data)


# ── rules ─────────────────────────────────────────────────────────────────────

def test_get_rules_returns_defaults(client):
    r = client.get("/api/rules")
    assert r.status_code == 200
    data = body(r)["data"]
    assert [x["name"] for x in data["rules"]] == ["IP Info", "Google"]


def test_add_rule(client):
    r = client.post("/api/rules", json={"name": "T", "pattern": "*.t.com",
                                        "proxy": "XVPN"})
    assert r.status_code == 200
    assert [x["name"] for x in body(r)["data"]["rules"]][-1] == "T"


@pytest.mark.parametrize("payload", [
    {},
    {"name": "", "pattern": "*.t.com"},
    {"name": "T", "pattern": ""},
    {"name": "   ", "pattern": "   "},
])
def test_add_rule_rejects_missing_fields(client, payload):
    r = client.post("/api/rules", json=payload)
    assert r.status_code == 400
    assert body(r)["ok"] is False


def test_add_rule_accepts_a_regex_pattern(client):
    r = client.post("/api/rules", json={"name": "Rgx", "pattern": r"'^cdn\d+\.x\.com$'",
                                        "proxy": "XVPN"})
    assert r.status_code == 200


@pytest.mark.parametrize("pattern", ["'[unclosed'", "''", "'(unbalanced'"])
def test_add_rule_rejects_a_broken_regex(client, pattern):
    """
    Caught at save time: an invalid regex otherwise stores fine and then
    silently never matches, which is very hard to diagnose later.
    """
    r = client.post("/api/rules", json={"name": "Bad", "pattern": pattern,
                                        "proxy": "XVPN"})
    assert r.status_code == 400
    assert "regex" in body(r)["msg"].lower()


def test_update_rule_also_validates_the_regex(client):
    r = client.put("/api/rules/0", json={"name": "X", "pattern": "'[bad'",
                                         "proxy": "XVPN"})
    assert r.status_code == 400


def test_a_broken_regex_is_not_persisted(client):
    client.post("/api/rules", json={"name": "Bad", "pattern": "'[bad'",
                                    "proxy": "XVPN"})
    names = [x["name"] for x in body(client.get("/api/rules"))["data"]["rules"]]
    assert "Bad" not in names


def test_add_rule_handles_malformed_json(client):
    """force=True/silent=True means a bad body must 400, not 500."""
    r = client.post("/api/rules", data="not json",
                    content_type="application/json")
    assert r.status_code == 400


@pytest.mark.parametrize("index", [99, 1000])
def test_mutating_out_of_range_rule_does_not_error(client, index):
    """A stale index from the UI must be a no-op, never a 500."""
    for method, path in [
        ("put", f"/api/rules/{index}"),
        ("delete", f"/api/rules/{index}"),
        ("post", f"/api/rules/{index}/toggle"),
        ("post", f"/api/rules/{index}/duplicate"),
    ]:
        r = getattr(client, method)(path, json={"name": "X", "pattern": "*.x.com"})
        assert r.status_code < 500, f"{method} {path} -> {r.status_code}"


def test_delete_then_get_is_consistent(client):
    client.delete("/api/rules/0")
    names = [x["name"] for x in body(client.get("/api/rules"))["data"]["rules"]]
    assert names == ["Google"]


def test_toggle_rule_persists(client):
    before = body(client.get("/api/rules"))["data"]["rules"][0]["enabled"]
    client.post("/api/rules/0/toggle")
    after = body(client.get("/api/rules"))["data"]["rules"][0]["enabled"]
    assert after is not before


def test_set_default_target(client):
    r = client.post("/api/rules/default", json={"default": "CGVPN"})
    assert r.status_code == 200
    assert body(client.get("/api/rules"))["data"]["default"] == "CGVPN"


# ── proxies ───────────────────────────────────────────────────────────────────

def test_add_proxy(client):
    r = client.post("/api/proxies", json={"name": "NEW", "type": "http",
                                          "host": "127.0.0.1", "port": 9999})
    assert r.status_code == 200
    names = [p["name"] for p in body(client.get("/api/rules"))["data"]["proxies"]]
    assert "NEW" in names


def test_delete_unknown_proxy_is_not_a_crash(client):
    r = client.delete("/api/proxies/DOES_NOT_EXIST")
    assert r.status_code < 500


def test_proxy_name_with_url_unsafe_chars(client):
    """Names go straight into the URL path — must round-trip or fail cleanly."""
    client.post("/api/proxies", json={"name": "a b/c", "type": "http",
                                      "host": "127.0.0.1", "port": 9998})
    r = client.get("/api/rules")
    assert r.status_code == 200


# ── devices ───────────────────────────────────────────────────────────────────

def test_decrypt_list_starts_empty(client):
    r = client.get("/api/devices/decrypt")
    assert r.status_code == 200
    assert body(r)["data"]["devices"] == []


def test_add_decrypt_device(client):
    r = client.post("/api/devices/decrypt",
                    json={"mac": "AA:BB:CC:DD:EE:FF", "label": "Phone"})
    assert r.status_code == 200
    macs = [d["mac"] for d in body(client.get("/api/devices/decrypt"))["data"]["devices"]]
    assert "aa:bb:cc:dd:ee:ff" in macs, "MACs should be normalised to lowercase"


def test_add_decrypt_device_rejects_empty_mac(client):
    r = client.post("/api/devices/decrypt", json={"mac": "", "label": "x"})
    assert r.status_code == 400


def test_blocked_list_starts_empty(client):
    r = client.get("/api/devices/blocked")
    assert r.status_code == 200
    assert body(r)["data"]["devices"] == []


def test_seen_devices_endpoint(client, monkeypatch):
    monkeypatch.setattr(services, "list_hotspot_devices",
                        lambda: [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.100.5",
                                  "hostname": "phone", "vendor": None,
                                  "display_name": "phone"}])
    r = client.get("/api/devices/seen")
    assert r.status_code == 200
    assert body(r)["devices"][0]["display_name"] == "phone"


# ── misc routes ───────────────────────────────────────────────────────────────

# ── traffic window ────────────────────────────────────────────────────────────

def test_history_returns_recent_rows_on_a_fresh_process(client, monkeypatch):
    """
    Regression: SESSION_FLOOR_ID used to be db.get_max_id(), set at process
    start, so on a fresh `sudo proxygate` the floor WAS the newest row and
    the history window was always empty. The row limit is what bounds the
    payload now, so the floor must not also hide everything.
    """
    monkeypatch.setattr(web_mod.db, "get_history_page",
                        lambda floor, **kw: [{"id": 1, "floor_seen": floor}])
    r = client.get("/api/traffic/history?limit=50")
    assert r.status_code == 200
    rows = body(r)["rows"]
    assert rows, "a fresh process must still return recent history"
    assert rows[0]["floor_seen"] == 0, "no session floor should be applied"


def test_live_tail_without_since_does_not_replay_history(client, monkeypatch):
    """
    /api/traffic/live is a tail. With no `since` it must start from the
    newest row, never from 0 — otherwise a caller omitting the cursor pulls
    the whole table back.
    """
    seen = {}

    def fake_since(since, limit=200):
        seen["since"] = since
        return []

    monkeypatch.setattr(web_mod.db, "get_connections_since", fake_since)
    monkeypatch.setattr(web_mod.db, "get_max_id", lambda: 9999)
    client.get("/api/traffic/live")
    assert seen["since"] == 9999


def test_index_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"<html" in r.data.lower()


def test_unknown_route_404s(client):
    assert client.get("/api/nope").status_code == 404


def test_settings_get_shape(client, monkeypatch):
    monkeypatch.setattr(services, "load_config", lambda: {"ap_ssid": "ProxyGate"})
    monkeypatch.setattr(services, "list_network_interfaces", lambda: ["eth0"])
    r = client.get("/api/settings")
    assert r.status_code == 200
    assert "config" in body(r) and "interfaces" in body(r)


# ── concurrency ───────────────────────────────────────────────────────────────

def test_concurrent_rule_writes_are_not_lost(client):
    """
    Regression: every mutating handler does load -> mutate -> save, and the
    server runs 8 waitress threads, so two saves could interleave and the
    second would silently discard the first. Measured at 154/200 writes lost
    before rules_transaction() made the cycle atomic.
    """
    import threading

    client.get("/api/rules")
    before = len(body(client.get("/api/rules"))["data"]["rules"])

    def worker(n):
        for i in range(10):
            client.post("/api/rules", json={"name": f"r{n}_{i}",
                                            "pattern": f"*.h{n}-{i}.com",
                                            "proxy": "XVPN"})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rules = body(client.get("/api/rules"))["data"]["rules"]
    names = [r["name"] for r in rules]
    assert len(rules) - before == 40, "writes were lost under concurrency"
    assert len(names) == len(set(names))
    assert len({r["id"] for r in rules}) == len(rules)
