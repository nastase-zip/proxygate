/**
 * status.js — Gateway toggle, service status dots, hotspot info.
 * Mirrors ui/status_panel.py's polling loop (was a background thread pushing
 * into DearPyGui; here it's a setInterval polling GET /api/status).
 */

(function () {
  "use strict";

  const TAG = "status";
  const POLL_MS = 5000;

  const STATE_BTN_CLASS = {
    idle: "gw-idle",
    connecting: "gw-connecting",
    connected: "gw-connected",
    disconnecting: "gw-disconnecting",
    error: "gw-error",
  };
  const STATE_BTN_LABEL = {
    idle: "Connect",
    connecting: "Connecting…",
    connected: "Disconnect",
    disconnecting: "Stopping…",
    error: "Retry",
  };
  const STATE_DOT_CLASS = {
    idle: "dim",
    connecting: "warn",
    connected: "ok",
    disconnecting: "warn",
    error: "error",
  };

  let lastState = null;

  function setStatusLine(msg, isError) {
    const el = document.getElementById("sp-status-line");
    el.textContent = msg || "";
    el.className = "status-line" + (isError ? " error" : msg ? " ok" : "");
  }

  function applyGatewayUi(state, detail) {
    const btn = document.getElementById("gw-toggle-btn");
    btn.textContent = STATE_BTN_LABEL[state] || state;
    btn.className = STATE_BTN_CLASS[state] || "";
    btn.disabled = state === "connecting" || state === "disconnecting";

    const dot = document.getElementById("gw-state-dot");
    if (dot) dot.className = "dot " + (STATE_DOT_CLASS[state] || "dim");

    const text = document.getElementById("gw-state-text");
    if (text) { text.textContent = detail || state; text.className = state === "error" ? "" : state === "connected" ? "" : "dim-label"; }

    if (state === "idle") setStatusLine("", false);
  }

  async function onToggle() {
    try {
      const stateRes = await PG.api.get("/api/gateway/state");
      const state = stateRes.state;
      if (state === "idle" || state === "error") {
        applyGatewayUi("connecting", "Starting…");
        PG.log.info(TAG, "Connect requested");
        await PG.api.post("/api/gateway/connect");
      } else if (state === "connected") {
        applyGatewayUi("disconnecting", "Stopping…");
        PG.log.info(TAG, "Disconnect requested");
        await PG.api.post("/api/gateway/disconnect");
      } else {
        PG.log.warn(TAG, "Toggle ignored during transition state", { state });
      }
    } catch (e) {
      PG.log.error(TAG, "Gateway toggle failed", { error: e.message });
      setStatusLine(e.message, true);
    }
  }

  function renderServices(services) {
    const list = document.getElementById("services-list");
    list.innerHTML = "";
    const labels = { hostapd: "WiFi AP", dnsmasq: "dnsmasq", mitmproxy: "mitmproxy" };
    for (const svc of ["hostapd", "dnsmasq", "mitmproxy"]) {
      const status = services[svc] || "unknown";
      const row = document.createElement("div");
      row.className = "svc-row";
      const dot = document.createElement("span");
      dot.className = "dot " + (status === "running" ? "ok" : status === "stopped" ? "error" : "warn");
      const name = document.createElement("span");
      name.className = "svc-name";
      name.textContent = labels[svc] || svc;
      const stat = document.createElement("span");
      stat.className = "svc-status";
      stat.textContent = status;
      row.appendChild(dot);
      row.appendChild(name);
      row.appendChild(stat);
      list.appendChild(row);
    }
  }

  let lastConflict = null;

  function renderInterfaceConflict(res) {
    document.getElementById("ap-interface").textContent = res.ap_interface || "—";
    document.getElementById("wan-interface").textContent = res.wan_interface || "—";

    const banner = document.getElementById("interface-conflict-banner");
    if (res.interface_conflict !== lastConflict) {
      PG.log.warn(TAG, "Interface conflict state changed", {
        conflict: res.interface_conflict, ap_interface: res.ap_interface, wan_interface: res.wan_interface,
      });
      lastConflict = res.interface_conflict;
    }
    if (res.interface_conflict) {
      banner.textContent =
        `⚠ WAN and hotspot are both resolving to '${res.ap_interface}'. Connect will refuse to start. ` +
        `Plug in Ethernet (or set the WAN interface explicitly in Settings) so the hotspot has a ` +
        `separate interface to route traffic through.`;
      banner.classList.remove("hidden");
    } else {
      banner.classList.add("hidden");
    }
  }

  async function poll() {
    try {
      const res = await PG.api.get("/api/status");
      if (res.gateway_state !== lastState) {
        PG.log.info(TAG, "Gateway state changed", { from: lastState, to: res.gateway_state, detail: res.gateway_detail });
        lastState = res.gateway_state;
      }
      applyGatewayUi(res.gateway_state, res.gateway_detail);
      renderServices(res.services);
      renderInterfaceConflict(res);
      document.getElementById("hotspot-ip").textContent = res.hotspot_ip || "—";
      document.getElementById("hotspot-devices").textContent = String(res.connected_devices || 0);
    } catch (e) {
      PG.log.error(TAG, "Status poll failed", { error: e.message });
    }
  }

  async function restartMitm() {
    setStatusLine("Restarting mitmproxy…", false);
    try {
      const res = await PG.api.post("/api/services/restart_mitm");
      PG.log.info(TAG, "mitmproxy restarted");
      setStatusLine(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Restart mitmproxy failed", { error: e.message });
      setStatusLine(e.message, true);
    }
  }

  function initStatusDropdown() {
    const btn = document.getElementById("status-dropdown-btn");
    const drop = document.getElementById("status-dropdown");
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      drop.classList.toggle("hidden");
    });
    document.addEventListener("click", () => drop.classList.add("hidden"));
    drop.addEventListener("click", (e) => e.stopPropagation());
  }

  function init() {
    document.getElementById("gw-toggle-btn").addEventListener("click", onToggle);
    document.getElementById("restart-mitm-btn").addEventListener("click", restartMitm);
    initStatusDropdown();

    poll();
    setInterval(poll, POLL_MS);
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.status = { setStatusLine, poll };
})();
