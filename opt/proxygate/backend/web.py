"""
backend/web.py — Flask web server exposing ProxyGate's control surface over HTTP.

Replaces the DearPyGui desktop UI. Every action the old UI performed by calling
straight into backend.services / backend.rules now happens the same way, just
triggered from an HTTP request instead of a button callback. No proxy/gateway
logic changed — this is purely a new transport for the same operations.

Runs on 0.0.0.0 so any device on the LAN reachable via the host's Ethernet
interface can open the UI in a browser and control the gateway.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, request, send_from_directory, Response

from backend import db
from backend import rules as rules_mod
from backend import services
from backend.services import GatewayState

log = logging.getLogger("proxygate.web")

_HERE = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(_HERE)
STATIC_DIR = os.path.join(_APP_ROOT, "webui", "static")
TEMPLATE_DIR = os.path.join(_APP_ROOT, "webui", "templates")

app = Flask(
    __name__,
    static_folder=STATIC_DIR,
    static_url_path="/static",
    template_folder=TEMPLATE_DIR,
)
# Disable browser caching of static assets — this UI has no build step or
# cache-busting filenames, so a cached JS/CSS file otherwise makes edits
# invisible until the user hard-refreshes.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def _no_cache_static(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

# Rows with id <= this were logged before this web server process started.
# History paging/search is scoped to id > SESSION_FLOOR_ID so a fresh
# `sudo proxygate` doesn't dump years of accumulated traffic into the browser.
# Set once at import time (i.e. at process start), not per-request.
SESSION_FLOOR_ID: int = db.get_max_id()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ok(payload: dict | None = None, msg: str = "") -> Response:
    body = {"ok": True, "msg": msg}
    if payload:
        body.update(payload)
    return jsonify(body)


def _err(msg: str, status: int = 400) -> tuple[Response, int]:
    return jsonify({"ok": False, "msg": msg}), status


def _log_request() -> None:
    log.info("%s %s", request.method, request.path)


# ── Static frontend ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(TEMPLATE_DIR, "index.html")


# ── Gateway state / connect / disconnect ────────────────────────────────────────

@app.route("/api/gateway/state")
def gateway_state():
    state, msg = services.get_gateway_state()
    return _ok({"state": state.value, "detail": msg})


@app.route("/api/gateway/connect", methods=["POST"])
def gateway_connect():
    _log_request()
    state, _ = services.get_gateway_state()
    if state not in (GatewayState.IDLE, GatewayState.ERROR):
        return _err(f"Cannot connect from state '{state.value}'", 409)
    services.connect_gateway()
    return _ok(msg="Connecting…")


@app.route("/api/gateway/disconnect", methods=["POST"])
def gateway_disconnect():
    _log_request()
    state, _ = services.get_gateway_state()
    if state != GatewayState.CONNECTED:
        return _err(f"Cannot disconnect from state '{state.value}'", 409)
    services.disconnect_gateway()
    return _ok(msg="Disconnecting…")


# ── Services / hotspot status ────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    state, msg = services.get_gateway_state()
    ap_if = services.resolve_ap_wifi_if()
    cfg = services.load_config()
    wan_cfg = (cfg.get("wan_if") or "").strip()
    wan_if = wan_cfg if wan_cfg and wan_cfg != ap_if else services.detect_wan_if()
    return _ok({
        "gateway_state": state.value,
        "gateway_detail": msg,
        "services": services.check_all_services(),
        "hotspot_ip": services.get_hotspot_ip(),
        "connected_devices": services.get_connected_devices(),
        "ap_interface": ap_if or None,
        "wan_interface": wan_if or None,
        "interface_conflict": bool(ap_if) and ap_if == wan_if,
    })


@app.route("/api/services/restart_mitm", methods=["POST"])
def restart_mitm():
    _log_request()
    ok, msg = services.mitm.restart()
    return _ok(msg=msg) if ok else _err(msg, 500)


@app.route("/api/services/reapply_rules", methods=["POST"])
def reapply_rules():
    _log_request()
    ok, msg = services.apply_iptables()
    if ok:
        ok2, msg2 = rules_mod.reload_rules()
        msg = "Rules applied." if ok2 else f"iptables OK; rules: {msg2}"
    return _ok(msg=msg) if ok else _err(msg, 500)


# ── Latency ──────────────────────────────────────────────────────────────────────

# Dedicated small pool so latency checks for N proxies run concurrently
# instead of serially. Checking them one at a time (up to `timeout` seconds
# each) meant a single dead/unreachable proxy could block this endpoint —
# and the single-threaded-per-request dev server — for many seconds, which
# is what caused intermittent NetworkErrors/timeouts on other requests
# arriving from other devices while a slow latency check was in flight.
_LATENCY_TIMEOUT = 1.5
_latency_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="latency-check")


@app.route("/api/proxies/latency")
def proxies_latency():
    data = rules_mod.load_rules()
    proxies = data.get("proxies", [])
    futures = {
        p["name"]: _latency_pool.submit(
            services.check_proxy_latency, p["host"], int(p["port"]), _LATENCY_TIMEOUT
        )
        for p in proxies
    }
    result = {name: fut.result() for name, fut in futures.items()}
    return _ok({"latency": result})


# ── Settings ───────────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
def get_settings():
    cfg = services.load_config()
    ifaces = services.list_network_interfaces()
    return _ok({"config": cfg, "interfaces": ifaces})


@app.route("/api/settings", methods=["POST"])
def save_settings():
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    wan = (body.get("wan_if") or "").strip()
    ssid = (body.get("ap_ssid") or "").strip()
    password = body.get("ap_password") or ""
    gw = (body.get("hotspot_gw") or "").strip()
    wifi_if = (body.get("ap_wifi_if") or "*").strip() or "*"
    band = body.get("ap_band") or ""

    if not ssid:
        return _err("SSID cannot be empty.")
    if not gw:
        return _err("Gateway IP cannot be empty.")

    cfg = services.load_config()
    cfg["wan_if"] = wan
    cfg["ap_ssid"] = ssid
    cfg["ap_password"] = password
    cfg["hotspot_gw"] = gw
    cfg["hotspot_subnet"] = gw.rsplit(".", 1)[0] + ".0/24"
    cfg["ap_wifi_if"] = wifi_if
    cfg["ap_band"] = band
    services.save_config(cfg)
    return _ok(msg="Settings saved. Reconnect to apply.")


@app.route("/api/settings/detect_wan", methods=["POST"])
def detect_wan():
    _log_request()
    iface = services.detect_wan_if()
    if iface:
        return _ok({"iface": iface}, msg=f"Detected: {iface}")
    return _err("Could not detect WAN interface.", 404)


# ── Rules CRUD ─────────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def get_rules():
    return _ok({"data": rules_mod.load_rules()})


@app.route("/api/rules", methods=["POST"])
def add_rule():
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    pattern = (body.get("pattern") or "").strip()
    proxy = body.get("proxy") or "DIRECT"
    enabled = bool(body.get("enabled", True))
    if not name or not pattern:
        return _err("Name and pattern are required.")
    data = rules_mod.load_rules()
    data = rules_mod.add_rule(data, name, pattern, proxy, enabled)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/<int:index>", methods=["PUT"])
def update_rule(index: int):
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    pattern = (body.get("pattern") or "").strip()
    proxy = body.get("proxy") or "DIRECT"
    enabled = bool(body.get("enabled", True))
    if not name or not pattern:
        return _err("Name and pattern are required.")
    data = rules_mod.load_rules()
    data = rules_mod.update_rule(data, index, name, pattern, proxy, enabled)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/<int:index>", methods=["DELETE"])
def delete_rule(index: int):
    _log_request()
    data = rules_mod.load_rules()
    data = rules_mod.delete_rule(data, index)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/restore", methods=["POST"])
def restore_rule():
    """Re-insert a previously-deleted rule at a specific index — powers Ctrl+Z undo."""
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    index = body.get("index")
    rule = body.get("rule")
    if index is None or not isinstance(rule, dict):
        return _err("index and rule are required.")
    data = rules_mod.load_rules()
    data = rules_mod.insert_rule(data, int(index), rule)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, "Rule restored") if ok else _err(msg, 500)


@app.route("/api/rules/<int:index>/duplicate", methods=["POST"])
def duplicate_rule(index: int):
    _log_request()
    data = rules_mod.load_rules()
    rules_list = data.get("rules", [])
    if not (0 <= index < len(rules_list)):
        return _err("Rule not found.", 404)
    data = rules_mod.duplicate_rule(data, index)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data, "new_index": index + 1}, "Rule duplicated") if ok else _err(msg, 500)


@app.route("/api/rules/<int:index>/toggle", methods=["POST"])
def toggle_rule(index: int):
    _log_request()
    data = rules_mod.load_rules()
    data = rules_mod.toggle_rule(data, index)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/<int:index>/move", methods=["POST"])
def move_rule(index: int):
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    direction = body.get("direction")
    data = rules_mod.load_rules()
    rules_list = data.get("rules", [])
    if direction == "up":
        if index <= 0:
            return _err("Already at top.", 409)
        data = rules_mod.move_rule_up(data, index)
    elif direction == "down":
        if index >= len(rules_list) - 1:
            return _err("Already at bottom.", 409)
        data = rules_mod.move_rule_down(data, index)
    else:
        return _err("direction must be 'up' or 'down'.")
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/<int:index>/move_to", methods=["POST"])
def move_rule_to(index: int):
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    dest = body.get("index")
    if dest is None:
        return _err("index is required.")
    data = rules_mod.load_rules()
    rules_list = data.get("rules", [])
    if not (0 <= index < len(rules_list)) or not (0 <= dest < len(rules_list)):
        return _err("Index out of range.", 409)
    data = rules_mod.move_rule_to(data, index, dest)
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/reorder", methods=["POST"])
def reorder_rules():
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    order = body.get("order")  # list of rule names in new order
    if not isinstance(order, list):
        return _err("order must be a list of rule names.")
    data = rules_mod.load_rules()
    rules_by_name = {r["name"]: r for r in data.get("rules", [])}
    reordered = [rules_by_name[n] for n in order if n in rules_by_name]
    # Append any rules not mentioned (shouldn't happen, but safe fallback)
    mentioned = set(order)
    for r in data.get("rules", []):
        if r["name"] not in mentioned:
            reordered.append(r)
    data["rules"] = reordered
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/default", methods=["POST"])
def set_default_rule():
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    target = body.get("default", "DIRECT")
    data = rules_mod.load_rules()
    data["default"] = target
    ok, msg = rules_mod.reload_rules(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/rules/apply", methods=["POST"])
def apply_rules_now():
    _log_request()
    data = rules_mod.load_rules()
    ok, msg = rules_mod.reload_rules(data)
    return _ok(msg=msg) if ok else _err(msg, 500)


# ── Proxy CRUD ─────────────────────────────────────────────────────────────────

@app.route("/api/proxies", methods=["POST"])
def add_proxy():
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    ptype = body.get("type") or "http"
    host = (body.get("host") or "").strip()
    port_raw = body.get("port")
    login = (body.get("login") or "").strip()
    password = body.get("password") or ""

    if not name or not host or port_raw in (None, ""):
        return _err("Name, host and port are required.")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return _err("Port must be a number.")

    data = rules_mod.load_rules()
    data = rules_mod.add_proxy(data, name, ptype, host, port, login, password)
    rules_mod.save_rules(data)
    ok, msg = rules_mod.reload_rules()
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/proxies/<name>", methods=["PUT"])
def edit_proxy(name: str):
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    new_name = (body.get("name") or "").strip()
    ptype = body.get("type") or "http"
    host = (body.get("host") or "").strip()
    port_raw = body.get("port")
    login = (body.get("login") or "").strip()
    password = body.get("password") or ""

    if not new_name or not host or port_raw in (None, ""):
        return _err("Name, host and port are required.")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return _err("Port must be a number.")

    data = rules_mod.load_rules()
    proxies = data.get("proxies", [])
    found = False
    for i, p in enumerate(proxies):
        if p["name"] == name:
            entry: dict = {"name": new_name, "type": ptype, "host": host, "port": port}
            if login:
                entry["login"] = login
            if password:
                entry["password"] = password
            proxies[i] = entry
            found = True
            break
    if not found:
        return _err(f"Proxy '{name}' not found.", 404)

    if new_name != name:
        for rule in data.get("rules", []):
            if rule.get("proxy") == name:
                rule["proxy"] = new_name
        if data.get("default") == name:
            data["default"] = new_name

    rules_mod.save_rules(data)
    ok, msg = rules_mod.reload_rules()
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/proxies/<name>", methods=["DELETE"])
def remove_proxy(name: str):
    _log_request()
    data = rules_mod.load_rules()
    data = rules_mod.remove_proxy(data, name)
    rules_mod.save_rules(data)
    ok, msg = rules_mod.reload_rules()
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/proxies/restore", methods=["POST"])
def restore_proxy():
    """Re-insert a previously-deleted proxy at a specific index — powers Ctrl+Z undo."""
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    index = body.get("index")
    proxy = body.get("proxy")
    if index is None or not isinstance(proxy, dict):
        return _err("index and proxy are required.")
    data = rules_mod.load_rules()
    data = rules_mod.insert_proxy(data, int(index), proxy)
    rules_mod.save_rules(data)
    ok, msg = rules_mod.reload_rules()
    return _ok({"data": data}, "Proxy restored") if ok else _err(msg, 500)


@app.route("/api/proxies/<name>/duplicate", methods=["POST"])
def duplicate_proxy(name: str):
    _log_request()
    data = rules_mod.load_rules()
    proxies = data.get("proxies", [])
    original = next((p for p in proxies if p["name"] == name), None)
    if not original:
        return _err(f"Proxy '{name}' not found.", 404)

    base_name = original["name"] + "_copy"
    new_name = base_name
    existing = {p["name"] for p in proxies}
    counter = 2
    while new_name in existing:
        new_name = f"{base_name}_{counter}"
        counter += 1
    new_proxy = dict(original)
    new_proxy["name"] = new_name
    proxies.append(new_proxy)
    rules_mod.save_rules(data)
    ok, msg = rules_mod.reload_rules()
    return _ok({"data": data, "new_name": new_name}, f"Duplicated as '{new_name}'") if ok else _err(msg, 500)


# ── Decrypt devices (TLS-MITM opt-in, by MAC) ─────────────────────────────────
#
# Lets a device with the ProxyGate CA installed get real TLS interception
# (decryption -> real HTTPS status codes) while every other device on the
# same hotspot, at the same time, keeps the original raw-TLS passthrough —
# see mitm_logger.py's DevicesEngine docstring for the full mechanism.

@app.route("/api/devices/seen")
def devices_seen():
    """Devices currently visible on the hotspot subnet (from dnsmasq leases +
    ARP), for the picker UI — separate from the decrypt allowlist itself."""
    return _ok({"devices": services.list_hotspot_devices()})


@app.route("/api/devices/decrypt", methods=["GET"])
def get_decrypt_devices():
    return _ok({"data": rules_mod.load_devices()})


@app.route("/api/devices/decrypt", methods=["POST"])
def add_decrypt_device():
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    mac = (body.get("mac") or "").strip()
    label = (body.get("label") or "").strip()
    if not mac:
        return _err("MAC address is required.")
    data = rules_mod.load_devices()
    data = rules_mod.add_decrypt_device(data, mac, label)
    ok, msg = rules_mod.reload_devices(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/devices/decrypt/<mac>", methods=["PUT"])
def set_decrypt_device(mac: str):
    _log_request()
    body = request.get_json(force=True, silent=True) or {}
    decrypt = bool(body.get("decrypt", True))
    data = rules_mod.load_devices()
    data = rules_mod.set_decrypt_device(data, mac, decrypt)
    ok, msg = rules_mod.reload_devices(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


@app.route("/api/devices/decrypt/<mac>", methods=["DELETE"])
def remove_decrypt_device(mac: str):
    _log_request()
    data = rules_mod.load_devices()
    data = rules_mod.remove_decrypt_device(data, mac)
    ok, msg = rules_mod.reload_devices(data)
    return _ok({"data": data}, msg) if ok else _err(msg, 500)


# mitmdump runs as root (see main.py's geteuid check), so its CA lives under
# root's home — mitmproxy writes it here unconditionally on first launch.
MITM_CA_CERT_PATH = os.path.expanduser("~root/.mitmproxy/mitmproxy-ca-cert.pem")


@app.route("/api/devices/ca-cert")
def ca_cert():
    """
    Serve mitmproxy's CA certificate for a device to install and trust —
    required only for devices flagged for decryption above. Devices that
    aren't flagged never need this; their traffic stays raw-TLS passthrough.
    """
    if not os.path.isfile(MITM_CA_CERT_PATH):
        return _err(
            "CA certificate not found yet — start the gateway at least once "
            "so mitmproxy generates it.", 404,
        )
    return send_from_directory(
        os.path.dirname(MITM_CA_CERT_PATH),
        os.path.basename(MITM_CA_CERT_PATH),
        as_attachment=True,
        download_name="proxygate-ca.pem",
        mimetype="application/x-x509-ca-cert",
    )


# ── Traffic feed ───────────────────────────────────────────────────────────────
#
# Two distinct query shapes, both scoped to SESSION_FLOOR_ID so a fresh
# `sudo proxygate` starts with an empty table instead of the full history:
#
#   /api/traffic/session  — metadata: floor id + current max id + live stats.
#                            Called once on page load.
#   /api/traffic/live      — forward tail, id > since. Polled every 500ms for
#                            new rows as they arrive.
#   /api/traffic/history    — backward chunk, id < before_id (or newest chunk
#                            if omitted), newest first. Called once on load
#                            and again each time the user scrolls near the
#                            top of the table asking for more/older rows.
#                            Filtering (`q`) happens here, in SQL, not in JS.

_HISTORY_CHUNK = 50
_HISTORY_CHUNK_MAX = 200


@app.route("/api/traffic/session")
def traffic_session():
    stats = db.get_session_stats(SESSION_FLOOR_ID)
    return _ok({
        "session_floor_id": SESSION_FLOOR_ID,
        "max_id": db.get_max_id(),
        "stats": stats,
    })


@app.route("/api/traffic/live")
def traffic_live():
    """Forward tail: rows with id > since (never below the session floor), oldest first."""
    since = request.args.get("since", default=SESSION_FLOOR_ID, type=int)
    since = max(since, SESSION_FLOOR_ID)
    limit = request.args.get("limit", default=200, type=int)
    rows = db.get_connections_since(since, limit=limit)
    stats = db.get_session_stats(SESSION_FLOOR_ID)
    return _ok({"rows": rows, "stats": stats})


@app.route("/api/traffic/history")
def traffic_history():
    """
    Backward chunk for scroll-up pagination and server-side search.
    before_id omitted -> newest chunk. Otherwise -> next older chunk, exclusive.
    Rows are returned newest-first (caller prepends them above the current top row).
    """
    before_id = request.args.get("before_id", type=int)
    limit = request.args.get("limit", default=_HISTORY_CHUNK, type=int)
    limit = max(1, min(limit, _HISTORY_CHUNK_MAX))
    filter_text = request.args.get("q", default="", type=str).strip()

    rows = db.get_history_page(SESSION_FLOOR_ID, before_id=before_id, limit=limit, filter_text=filter_text)
    return _ok({"rows": rows, "has_more": len(rows) == limit})


# ── Client-side debug log sink ───────────────────────────────────────────────────
# The frontend mirrors its console logs here so migration issues can be
# inspected from the server logs too (e.g. via `journalctl` or the log file),
# not just the browser devtools console.

@app.route("/api/clientlog", methods=["POST"])
def client_log():
    body = request.get_json(force=True, silent=True) or {}
    level = str(body.get("level", "info")).upper()
    message = body.get("message", "")
    context = body.get("context")
    line = f"[browser:{level}] {message}"
    if context:
        line += f" | {context}"
    if level == "ERROR":
        log.error(line)
    elif level == "WARN":
        log.warning(line)
    else:
        log.info(line)
    return _ok()


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return _err("Not found", 404)
    return send_from_directory(TEMPLATE_DIR, "index.html")


@app.errorhandler(Exception)
def handle_exception(e):
    log.exception("Unhandled exception in %s %s", request.method, request.path)
    return _err(f"Internal error: {e}", 500)


def run(host: str = "0.0.0.0", port: int = 8765) -> None:
    """
    Serve with waitress instead of Flask's built-in dev server. The dev
    server explicitly warns it's not for continuous multi-client use, and in
    practice a single slow request (e.g. checking a dead proxy's latency)
    could starve other devices' requests. Waitress runs a real thread pool
    for request handling; background daemon threads this app spawns
    (gateway connect/disconnect, iptables watchdog, mitm watchdog) are
    independent of that pool and unaffected either way.
    """
    from waitress import serve
    log.info("ProxyGate web UI listening on http://%s:%s (waitress)", host, port)
    serve(app, host=host, port=port, threads=8, _quiet=False)
