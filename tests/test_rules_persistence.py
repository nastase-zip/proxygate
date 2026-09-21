"""
rules.yaml load/save and CRUD.

This file is the app's source of truth for routing, rewritten on every UI
action while mitmproxy reads it concurrently — so atomicity, index-bounds
safety and default-merging all matter.
"""
import os

import pytest
import yaml

from backend import rules as rules_mod


@pytest.fixture
def rules_path(tmp_path, monkeypatch):
    p = tmp_path / "rules.yaml"
    monkeypatch.setattr(rules_mod, "RULES_PATH", str(p))
    return p


# ── load/save round-trip ──────────────────────────────────────────────────────

def test_missing_file_is_seeded_with_defaults(rules_path):
    data = rules_mod.load_rules()
    assert rules_path.exists(), "load_rules should write the defaults out"
    assert data["default"] == "DIRECT"
    assert {p["name"] for p in data["proxies"]} == {"XVPN", "CGVPN", "PIAVPN"}
    assert [r["name"] for r in data["rules"]] == ["IP Info", "Google"]


def test_shipped_defaults_are_internally_consistent(rules_path):
    """Every rule must point at a proxy that actually exists."""
    data = rules_mod.load_rules()
    names = {p["name"] for p in data["proxies"]} | {"DIRECT", "BLOCK"}
    for r in data["rules"]:
        assert r["proxy"] in names, f"{r['name']} targets unknown proxy {r['proxy']}"
    assert data["default"] in names


def test_default_proxies_use_distinct_ports(rules_path):
    ports = [p["port"] for p in rules_mod.load_rules()["proxies"]]
    assert len(ports) == len(set(ports)), "proxies must not share a port"


def test_round_trip_preserves_data(rules_path):
    data = rules_mod.load_rules()
    data = rules_mod.add_rule(data, "Test", "*.test.com", "XVPN")
    rules_mod.save_rules(data)

    reloaded = rules_mod.load_rules()
    assert [r["name"] for r in reloaded["rules"]] == ["IP Info", "Google", "Test"]


def test_corrupt_yaml_falls_back_to_defaults(rules_path):
    rules_path.write_text("{{{ not valid yaml")
    data = rules_mod.load_rules()
    assert data["default"] == "DIRECT"
    assert len(data["rules"]) == 2


def test_partial_file_is_merged_with_defaults(rules_path):
    """A file missing keys must not produce KeyErrors downstream."""
    rules_path.write_text("rules: []\n")
    data = rules_mod.load_rules()
    assert data["rules"] == []
    assert "proxies" in data and "default" in data


def test_save_is_atomic_leaving_no_temp_files(rules_path):
    data = rules_mod.load_rules()
    rules_mod.save_rules(data)
    leftovers = [f for f in os.listdir(rules_path.parent) if f != rules_path.name]
    assert leftovers == [], f"temp files left behind: {leftovers}"


def test_save_writes_parseable_yaml(rules_path):
    data = rules_mod.load_rules()
    rules_mod.save_rules(data)
    assert yaml.safe_load(rules_path.read_text())["default"] == "DIRECT"


# ── ids ───────────────────────────────────────────────────────────────────────

def test_ids_are_assigned_and_unique(rules_path):
    rules_path.write_text(yaml.dump({
        "rules": [{"name": "A", "pattern": "*.a.com", "proxy": "DIRECT", "enabled": True},
                  {"name": "B", "pattern": "*.b.com", "proxy": "DIRECT", "enabled": True}],
        "proxies": [], "default": "DIRECT",
    }))
    data = rules_mod.load_rules()
    ids = [r["id"] for r in data["rules"]]
    assert all(ids) and len(set(ids)) == 2


def test_added_rules_get_unique_ids(rules_path):
    data = rules_mod.load_rules()
    data = rules_mod.add_rule(data, "A", "*.a.com", "XVPN")
    data = rules_mod.add_rule(data, "B", "*.b.com", "XVPN")
    ids = [r["id"] for r in data["rules"]]
    assert len(set(ids)) == len(ids)


# ── CRUD bounds safety ────────────────────────────────────────────────────────

@pytest.mark.parametrize("index", [-1, 99, 1000])
def test_out_of_range_indices_are_noops(rules_path, index):
    """
    The UI sends list indices; a stale index after a concurrent edit must not
    raise or corrupt the file.
    """
    data = rules_mod.load_rules()
    before = [r["name"] for r in data["rules"]]

    rules_mod.delete_rule(data, index)
    rules_mod.update_rule(data, index, "X", "*.x.com", "XVPN", True)
    rules_mod.toggle_rule(data, index)
    rules_mod.duplicate_rule(data, index)

    assert [r["name"] for r in data["rules"]] == before


def test_delete_removes_the_right_rule(rules_path):
    data = rules_mod.load_rules()
    rules_mod.delete_rule(data, 0)
    assert [r["name"] for r in data["rules"]] == ["Google"]


def test_toggle_flips_enabled(rules_path):
    data = rules_mod.load_rules()
    before = data["rules"][0]["enabled"]
    rules_mod.toggle_rule(data, 0)
    assert data["rules"][0]["enabled"] is not before


def test_update_preserves_id(rules_path):
    data = rules_mod.load_rules()
    original_id = data["rules"][0]["id"]
    rules_mod.update_rule(data, 0, "Renamed", "*.new.com", "CGVPN", False)
    assert data["rules"][0]["id"] == original_id
    assert data["rules"][0]["name"] == "Renamed"


def test_duplicate_makes_unique_name_and_id(rules_path):
    data = rules_mod.load_rules()
    original_id = data["rules"][0]["id"]
    rules_mod.duplicate_rule(data, 0)
    names = [r["name"] for r in data["rules"]]
    assert names == ["IP Info", "IP Info_copy", "Google"]
    assert data["rules"][1]["id"] != original_id


def test_duplicate_twice_does_not_collide(rules_path):
    data = rules_mod.load_rules()
    rules_mod.duplicate_rule(data, 0)
    rules_mod.duplicate_rule(data, 0)
    names = [r["name"] for r in data["rules"]]
    assert len(names) == len(set(names)), f"duplicate names: {names}"


def test_insert_clamps_index(rules_path):
    """Drag-and-drop reordering sends arbitrary indices."""
    data = rules_mod.load_rules()
    rules_mod.insert_rule(data, 999, {"id": "x", "name": "End",
                                      "pattern": "*.e.com", "proxy": "DIRECT",
                                      "enabled": True})
    assert data["rules"][-1]["name"] == "End"

    rules_mod.insert_rule(data, -5, {"id": "y", "name": "Start",
                                     "pattern": "*.s.com", "proxy": "DIRECT",
                                     "enabled": True})
    assert data["rules"][0]["name"] == "Start"
