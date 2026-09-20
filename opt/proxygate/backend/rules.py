"""
backend/rules.py — Load, save, and hot-reload routing rules.

Routing model:
  - `default` is the catch-all fallback: "DIRECT", "BLOCK", or a proxy name.
  - `rules[]` are per-pattern overrides evaluated top-to-bottom.
  - Upstream proxy routing is done natively by mitmproxy via server_conn.via —
    no proxychains4, no wrapper process.
  - `devices.yaml` separately lists MAC addresses of devices that have the
    ProxyGate CA installed and opted in to TLS decryption (see decrypt_devices.py
    docstring in mitm_logger.py for why MAC, not IP, is the identity key).
"""

from __future__ import annotations

import os
import tempfile
import uuid
from typing import Optional

import yaml

RULES_PATH   = os.getenv("PROXYGATE_RULES",   "/etc/proxygate/rules.yaml")
CONFIG_PATH  = os.getenv("PROXYGATE_CONFIG",  "/etc/proxygate/config.yaml")
DEVICES_PATH = os.getenv("PROXYGATE_DEVICES", "/etc/proxygate/devices.yaml")
BLOCKED_DEVICES_PATH = os.getenv("PROXYGATE_BLOCKED_DEVICES", "/etc/proxygate/blocked_devices.yaml")

# ── Defaults ──────────────────────────────────────────────────────────────────

_DEFAULT_RULES: dict = {
    "proxies": [],
    "rules":   [],
    "default": "DIRECT",
}

# ── Routing helpers ───────────────────────────────────────────────────────────

def _effective_target(data: dict) -> str:
    """Return the catch-all target: "DIRECT", "BLOCK", or a proxy name."""
    default     = data.get("default", "DIRECT")
    proxy_names = {p["name"] for p in data.get("proxies", [])}
    if default in ("DIRECT", "BLOCK"):
        return default
    if default in proxy_names:
        return default
    return "DIRECT"

# ── Load / Save ───────────────────────────────────────────────────────────────

def _ensure_ids(data: dict) -> dict:
    """Backfill missing ids on existing rules and proxies."""
    dirty = False
    for r in data.get("rules", []):
        if not r.get("id"):
            r["id"] = str(uuid.uuid4())
            dirty = True
    for p in data.get("proxies", []):
        if not p.get("id"):
            p["id"] = str(uuid.uuid4())
            dirty = True
    if dirty:
        save_rules(data)
    return data


def load_rules() -> dict:
    if not os.path.exists(RULES_PATH):
        save_rules(_DEFAULT_RULES)
        return dict(_DEFAULT_RULES)
    try:
        with open(RULES_PATH) as f:
            data = yaml.safe_load(f) or {}
        data = {**_DEFAULT_RULES, **data}
        return _ensure_ids(data)
    except Exception:
        return dict(_DEFAULT_RULES)


def save_rules(data: dict) -> None:
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(RULES_PATH))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        os.replace(tmp_path, RULES_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise

# ── Proxy CRUD ────────────────────────────────────────────────────────────────

def add_proxy(data: dict, name: str, ptype: str, host: str, port: int,
              login: str = "", password: str = "") -> dict:
    entry: dict = {"id": str(uuid.uuid4()), "name": name, "type": ptype, "host": host, "port": port}
    if login:
        entry["login"] = login
    if password:
        entry["password"] = password
    data.setdefault("proxies", []).append(entry)
    return data


def insert_proxy(data: dict, index: int, proxy: dict) -> dict:
    proxies = data.setdefault("proxies", [])
    index = max(0, min(index, len(proxies)))
    proxies.insert(index, proxy)
    return data


def remove_proxy(data: dict, name: str) -> dict:
    data["proxies"] = [p for p in data.get("proxies", []) if p["name"] != name]
    for rule in data.get("rules", []):
        if rule.get("proxy") == name:
            rule["proxy"] = "DIRECT"
    if data.get("default") == name:
        data["default"] = "DIRECT"
    return data

# ── Rule CRUD ─────────────────────────────────────────────────────────────────

def add_rule(data: dict, name: str, pattern: str, proxy: str,
             enabled: bool = True) -> dict:
    data.setdefault("rules", []).append(
        {"id": str(uuid.uuid4()), "name": name, "pattern": pattern, "proxy": proxy, "enabled": enabled}
    )
    return data


def update_rule(data: dict, index: int, name: str, pattern: str,
                proxy: str, enabled: bool) -> dict:
    if 0 <= index < len(data.get("rules", [])):
        existing_id = data["rules"][index].get("id") or str(uuid.uuid4())
        data["rules"][index] = {
            "id": existing_id, "name": name, "pattern": pattern,
            "proxy": proxy, "enabled": enabled,
        }
    return data


def duplicate_rule(data: dict, index: int) -> dict:
    rules = data.get("rules", [])
    if 0 <= index < len(rules):
        original = dict(rules[index])
        base_name = original.get("name", "rule")
        existing = {r.get("name") for r in rules}
        new_name = f"{base_name}_copy"
        counter = 2
        while new_name in existing:
            new_name = f"{base_name}_copy{counter}"
            counter += 1
        original["name"] = new_name
        original["id"] = str(uuid.uuid4())
        rules.insert(index + 1, original)
    return data


def delete_rule(data: dict, index: int) -> dict:
    rules = data.get("rules", [])
    if 0 <= index < len(rules):
        rules.pop(index)
    return data


def insert_rule(data: dict, index: int, rule: dict) -> dict:
    rules = data.setdefault("rules", [])
    index = max(0, min(index, len(rules)))
    rules.insert(index, rule)
    return data


def toggle_rule(data: dict, index: int) -> dict:
    rules = data.get("rules", [])
    if 0 <= index < len(rules):
        rules[index]["enabled"] = not rules[index].get("enabled", True)
    return data


def move_rule_up(data: dict, index: int) -> dict:
    rules = data.get("rules", [])
    if index > 0:
        rules[index], rules[index - 1] = rules[index - 1], rules[index]
    return data


def move_rule_down(data: dict, index: int) -> dict:
    rules = data.get("rules", [])
    if index < len(rules) - 1:
        rules[index], rules[index + 1] = rules[index + 1], rules[index]
    return data


def move_rule_to(data: dict, src: int, dest: int) -> dict:
    rules = data.get("rules", [])
    if 0 <= src < len(rules) and 0 <= dest < len(rules) and src != dest:
        rule = rules.pop(src)
        rules.insert(dest, rule)
    return data

# ── Full reload flow ──────────────────────────────────────────────────────────

RELOAD_SIGNAL = os.getenv("PROXYGATE_RELOAD_SIGNAL", "/tmp/proxygate-reload")


def _signal_mitm_reload() -> None:
    """Touch the reload-signal file so mitmdump's RulesWatcher picks up changes instantly."""
    try:
        with open(RELOAD_SIGNAL, "a"):
            os.utime(RELOAD_SIGNAL, None)
    except Exception:
        pass



# ── Decrypt devices (TLS-MITM opt-in, by MAC) ─────────────────────────────────
#
# A device is only ever decrypted if its MAC is listed here — everything else
# stays raw-TLS passthrough exactly as before (see mitm_logger.py's
# tls_clienthello). MAC, not IP, so the flag survives a DHCP lease renewal
# instead of silently detaching from the phone it was set for.

_DEFAULT_DEVICES: dict = {"devices": []}


def load_devices() -> dict:
    if not os.path.exists(DEVICES_PATH):
        save_devices(_DEFAULT_DEVICES)
        return dict(_DEFAULT_DEVICES)
    try:
        with open(DEVICES_PATH) as f:
            data = yaml.safe_load(f) or {}
        return {**_DEFAULT_DEVICES, **data}
    except Exception:
        return dict(_DEFAULT_DEVICES)


def save_devices(data: dict) -> None:
    os.makedirs(os.path.dirname(DEVICES_PATH), exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(DEVICES_PATH))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        os.replace(tmp_path, DEVICES_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def _norm_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def add_decrypt_device(data: dict, mac: str, label: str = "") -> dict:
    mac = _norm_mac(mac)
    devices = data.setdefault("devices", [])
    if any(_norm_mac(d.get("mac", "")) == mac for d in devices):
        return data
    devices.append({"id": str(uuid.uuid4()), "mac": mac, "label": label, "decrypt": True})
    return data


def remove_decrypt_device(data: dict, mac: str) -> dict:
    mac = _norm_mac(mac)
    data["devices"] = [d for d in data.get("devices", []) if _norm_mac(d.get("mac", "")) != mac]
    return data


def set_decrypt_device(data: dict, mac: str, decrypt: bool) -> dict:
    mac = _norm_mac(mac)
    for d in data.get("devices", []):
        if _norm_mac(d.get("mac", "")) == mac:
            d["decrypt"] = decrypt
    return data


def decrypt_mac_set(data: dict) -> set[str]:
    """MAC addresses currently flagged for TLS decryption."""
    return {_norm_mac(d["mac"]) for d in data.get("devices", []) if d.get("decrypt") and d.get("mac")}


# ── Blocked devices (kicked from the hotspot, by MAC) ─────────────────────────
#
# A completely separate concept from decrypt opt-in above — this is a
# network-level ban list. A device whose MAC is here AND has `blocked: true`
# gets an immediate `iw station del` (instant WiFi deauth) when blocked, AND
# every future connection attempt is dropped in iptables (PROXYGATE_BLOCKDEV,
# applied by apply_iptables() in services.py) so it can't just reassociate a
# moment later — "kick + block from reconnecting", not a one-off disconnect.
# Deliberately its own file (not devices.yaml) since blocking a device from
# the network and flagging it for TLS decryption are unrelated actions on
# unrelated device sets.
#
# Entries persist here even once toggled off (`blocked: false`) rather than
# being deleted — same idea as devices.yaml's decrypt flag: the device stays
# in the list (with its last-known label) so it can be found and re-toggled
# later, since it also stops appearing in /api/devices/seen the moment it's
# actually kicked off the hotspot. An explicit delete (remove_blocked_device)
# is the only thing that actually removes an entry.

_DEFAULT_BLOCKED_DEVICES: dict = {"devices": []}


def load_blocked_devices() -> dict:
    if not os.path.exists(BLOCKED_DEVICES_PATH):
        save_blocked_devices(_DEFAULT_BLOCKED_DEVICES)
        return dict(_DEFAULT_BLOCKED_DEVICES)
    try:
        with open(BLOCKED_DEVICES_PATH) as f:
            data = yaml.safe_load(f) or {}
        return {**_DEFAULT_BLOCKED_DEVICES, **data}
    except Exception:
        return dict(_DEFAULT_BLOCKED_DEVICES)


def save_blocked_devices(data: dict) -> None:
    os.makedirs(os.path.dirname(BLOCKED_DEVICES_PATH), exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(BLOCKED_DEVICES_PATH))
    try:
        with os.fdopen(tmp_fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
        os.replace(tmp_path, BLOCKED_DEVICES_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def add_blocked_device(data: dict, mac: str, label: str = "") -> dict:
    """Add (or re-block, if the entry already exists from a prior toggle-off)
    `mac` to the list with blocked=True."""
    mac = _norm_mac(mac)
    devices = data.setdefault("devices", [])
    for d in devices:
        if _norm_mac(d.get("mac", "")) == mac:
            d["blocked"] = True
            if label:
                d["label"] = label
            return data
    devices.append({"id": str(uuid.uuid4()), "mac": mac, "label": label, "blocked": True})
    return data


def set_blocked_device(data: dict, mac: str, blocked: bool) -> dict:
    """Toggle an existing entry's enforcement on/off without removing it —
    this is the on/off switch the UI's per-device toggle calls."""
    mac = _norm_mac(mac)
    for d in data.get("devices", []):
        if _norm_mac(d.get("mac", "")) == mac:
            d["blocked"] = blocked
    return data


def remove_blocked_device(data: dict, mac: str) -> dict:
    """Fully delete the entry — unlike set_blocked_device(..., False), this
    also removes it from the list, not just disables enforcement."""
    mac = _norm_mac(mac)
    data["devices"] = [d for d in data.get("devices", []) if _norm_mac(d.get("mac", "")) != mac]
    return data


def blocked_mac_set(data: dict) -> set[str]:
    """MAC addresses currently ENFORCED as blocked (blocked=True) — a
    toggled-off entry stays in the list but is excluded here, since
    apply_iptables() only bans what this returns."""
    return {_norm_mac(d["mac"]) for d in data.get("devices", []) if d.get("mac") and d.get("blocked")}


def reload_rules(data: Optional[dict] = None) -> tuple[bool, str]:
    """
    1. Save rules.yaml.
    2. Signal mitmdump's RulesWatcher via a touch file (picks up in ~250ms).
    3. Reapply iptables (mode may have changed: BLOCK ↔ proxy ↔ DIRECT).
    """
    try:
        if data is not None:
            save_rules(data)

        _signal_mitm_reload()

        try:
            from backend.services import get_gateway_state, apply_iptables, GatewayState
            state, _ = get_gateway_state()
            if state == GatewayState.CONNECTED:
                apply_iptables()
        except Exception:
            pass

        return True, "Rules applied"

    except Exception as e:
        return False, str(e)


def reload_devices(data: Optional[dict] = None) -> tuple[bool, str]:
    """Save devices.yaml (if given) and signal mitmdump to hot-reload it — no
    iptables change needed, decrypt policy is enforced entirely inside mitmproxy."""
    try:
        if data is not None:
            save_devices(data)
        _signal_mitm_reload()
        return True, "Devices updated"
    except Exception as e:
        return False, str(e)


def reload_blocked_devices(data: Optional[dict] = None) -> tuple[bool, str]:
    """
    Save blocked_devices.yaml (if given) and reapply iptables — unlike the
    decrypt device list, blocking is enforced by an actual iptables DROP
    rule per MAC (PROXYGATE_BLOCKDEV, services.py), so a real rule change is
    needed here, not just a hot-reload signal to mitmdump.
    """
    try:
        if data is not None:
            save_blocked_devices(data)
        from backend.services import get_gateway_state, apply_iptables, GatewayState
        state, _ = get_gateway_state()
        if state == GatewayState.CONNECTED:
            ok, msg = apply_iptables()
            if not ok:
                return False, msg
        return True, "Blocked devices updated"
    except Exception as e:
        return False, str(e)
