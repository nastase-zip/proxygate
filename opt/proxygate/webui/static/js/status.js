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

  // Short labels used for the plain-text top-bar warning line ("AP down,
  // Mediastreamer down") — deliberately shorter than the dropdown's labels
  // (e.g. "AP" not "WiFi AP") to keep that line compact.
  const SERVICE_WARN_LABELS = { hostapd: "AP", dnsmasq: "DNS", mitmproxy: "mitmproxy", mediastreamer: "Mediastreamer" };

  function renderServices(services) {
    const list = document.getElementById("services-list");
    list.innerHTML = "";
    const labels = { hostapd: "WiFi AP", dnsmasq: "dnsmasq", mitmproxy: "mitmproxy", mediastreamer: "Mediastreamer DNS" };
    const downLabels = [];
    for (const svc of ["hostapd", "dnsmasq", "mitmproxy", "mediastreamer"]) {
      const status = services[svc] || "unknown";
      const row = document.createElement("div");
      row.className = "svc-row";
      // "stopped" means "off" (not an error) for the optional mediastreamer
      // toggle, same dim treatment as the gateway's own idle dot — only its
      // degraded ("unknown" = enabled but neither resolver reachable) state
      // is a real warning. The other three services' "stopped" always means
      // an actual outage of something that's supposed to be running.
      const dotClass = svc === "mediastreamer"
        ? (status === "running" ? "ok" : status === "unknown" ? "warn" : "dim")
        : (status === "running" ? "ok" : status === "stopped" ? "error" : "warn");
      const dot = document.createElement("span");
      dot.className = "dot " + dotClass;
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
      const isDown = svc === "mediastreamer" ? status === "unknown" : status === "stopped";
      if (isDown) downLabels.push(SERVICE_WARN_LABELS[svc] || svc);
    }
    renderServiceWarning(downLabels);
  }

  function renderServiceWarning(downLabels) {
    const el = document.getElementById("service-warning-line");
    if (!el) return;
    if (downLabels.length === 0) {
      el.classList.add("hidden");
      el.textContent = "";
    } else {
      el.textContent = downLabels.map((l) => `${l} down`).join(", ");
      el.classList.remove("hidden");
    }
  }

  // ── Hotspot device list (status dropdown) ───────────────────────────────
  //
  // Separate from the left-panel "Devices" tab (devices.js) — that one is
  // the decrypt opt-in allowlist. This is "who's currently on my hotspot,
  // kick them off" — a network-level ban, not a TLS setting.
  //
  // Merges TWO sources so a blocked device stays visible even after it's
  // no longer on the network (which blocking it causes): /api/devices/seen
  // (currently associated, from dnsmasq/ARP) and /api/devices/blocked (the
  // persisted ban list — entries survive being toggled off, see
  // rules.py's blocked_devices.yaml docstring). A device that's both seen
  // AND blocked shouldn't normally happen (blocking kicks it off), but if
  // it does, the blocked entry's label/mac wins for identity since that's
  // the durable record.
  //
  // Toggle icon (wifi / wifi-slash) flips PUT .../blocked {blocked: bool} —
  // same on/off-icon-button convention as devices.js's lock/unlock toggle,
  // not a separate switch widget, for visual consistency with the rest of
  // the app. Trash icon is a DIFFERENT, separate action: it fully deletes
  // the blocked-devices.yaml entry (services.delete_blocked_device),
  // distinct from toggling it off — only shown for entries that HAVE a
  // blocked-devices.yaml record (a plain "seen, never blocked" device has
  // nothing to delete, only something to block for the first time).

  async function renderDeviceList() {
    const list = document.getElementById("hotspot-device-list");
    try {
      const [seenRes, blockedRes] = await Promise.all([
        PG.api.get("/api/devices/seen"),
        PG.api.get("/api/devices/blocked"),
      ]);
      const seen = seenRes.devices || [];
      const blockedEntries = (blockedRes.data && blockedRes.data.devices) || [];

      const byMac = new Map();
      for (const dev of seen) {
        byMac.set(dev.mac, { mac: dev.mac, ip: dev.ip, hostname: dev.hostname, blockedEntry: null });
      }
      for (const entry of blockedEntries) {
        const existing = byMac.get(entry.mac);
        if (existing) {
          existing.blockedEntry = entry;
        } else {
          byMac.set(entry.mac, { mac: entry.mac, ip: null, hostname: entry.label || null, blockedEntry: entry });
        }
      }
      const devices = Array.from(byMac.values());

      document.getElementById("hotspot-devices").textContent = String(seen.length);
      list.innerHTML = "";
      if (!devices.length) {
        const empty = document.createElement("div");
        empty.className = "device-mini-empty";
        empty.textContent = "No devices connected.";
        list.appendChild(empty);
        return;
      }
      for (const dev of devices) {
        const isBlocked = !!(dev.blockedEntry && dev.blockedEntry.blocked);
        const row = document.createElement("div");
        row.className = "device-mini-row" + (isBlocked ? " device-mini-blocked" : "");

        const info = document.createElement("div");
        info.className = "device-mini-info";
        const name = document.createElement("span");
        name.className = "device-mini-name";
        name.textContent = dev.hostname || dev.ip || dev.mac;
        const sub = document.createElement("span");
        sub.className = "device-mini-sub";
        const subParts = [];
        if (dev.ip) subParts.push(dev.ip);
        subParts.push(dev.mac);
        if (isBlocked && !dev.ip) subParts.push("offline (blocked)");
        sub.textContent = subParts.join(" — ");
        info.appendChild(name);
        info.appendChild(sub);

        const actions = document.createElement("div");
        actions.className = "device-mini-actions";

        const toggleBtn = document.createElement("button");
        toggleBtn.className = "device-mini-kick";
        toggleBtn.innerHTML = isBlocked
          ? '<i class="fa-solid fa-wifi-slash"></i>'
          : '<i class="fa-solid fa-wifi"></i>';
        toggleBtn.title = isBlocked
          ? "Blocked — click to allow this device to reconnect"
          : "Click to kick and block this device from the hotspot";
        toggleBtn.addEventListener("click", () => toggleDeviceBlocked(dev, isBlocked));
        actions.appendChild(toggleBtn);

        if (dev.blockedEntry) {
          const delBtn = document.createElement("button");
          delBtn.className = "device-mini-kick";
          delBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
          delBtn.title = "Remove from the block list entirely";
          delBtn.addEventListener("click", () => deleteBlockedDevice(dev));
          actions.appendChild(delBtn);
        }

        row.appendChild(info);
        row.appendChild(actions);
        list.appendChild(row);
      }
    } catch (e) {
      PG.log.error(TAG, "Failed to load hotspot device list", { error: e.message });
    }
  }

  async function toggleDeviceBlocked(dev, currentlyBlocked) {
    const label = dev.hostname || dev.ip || dev.mac;
    try {
      if (currentlyBlocked) {
        await PG.api.put(`/api/devices/blocked/${encodeURIComponent(dev.mac)}`, { blocked: false });
        PG.log.info(TAG, "Device un-blocked", { mac: dev.mac, label });
        setStatusLine(`${label} can reconnect to the hotspot again.`, false);
      } else {
        if (!confirm(`Kick "${label}" off the hotspot and block it from reconnecting?`)) return;
        await PG.api.post("/api/devices/blocked", { mac: dev.mac, label: dev.hostname || "" });
        PG.log.info(TAG, "Device kicked and blocked", { mac: dev.mac, label });
        setStatusLine(`Kicked ${label} — blocked from reconnecting.`, false);
      }
      renderDeviceList();
    } catch (e) {
      PG.log.error(TAG, "Toggle device block failed", { error: e.message, mac: dev.mac });
      setStatusLine(e.message, true);
    }
  }

  async function deleteBlockedDevice(dev) {
    const label = dev.hostname || dev.ip || dev.mac;
    if (!confirm(`Remove "${label}" from the block list entirely?`)) return;
    try {
      await PG.api.del(`/api/devices/blocked/${encodeURIComponent(dev.mac)}`);
      PG.log.info(TAG, "Blocked-device entry deleted", { mac: dev.mac, label });
      setStatusLine(`Removed ${label} from the block list.`, false);
      renderDeviceList();
    } catch (e) {
      PG.log.error(TAG, "Delete blocked device failed", { error: e.message, mac: dev.mac });
      setStatusLine(e.message, true);
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
      if (!mediastreamerBusy) refreshMediastreamerDns(res.gateway_state === "connected");
      renderServices(res.services);
      renderInterfaceConflict(res);
      document.getElementById("hotspot-ip").textContent = res.hotspot_ip || "—";
      // Device count comes from the same list the dropdown renders (not
      // res.connected_devices, an `iw station dump` count that can lag
      // slightly behind dnsmasq/ARP-based list_hotspot_devices()) so the
      // number always matches what's actually in the expandable list below it.
      renderDeviceList();
    } catch (e) {
      PG.log.error(TAG, "Status poll failed", { error: e.message });
    }
  }

  let mediastreamerBusy = false;

  function renderMediastreamerBtn(enabled, gatewayConnected) {
    const btn = document.getElementById("mediastreamer-dns-btn");
    if (!btn || mediastreamerBusy) return;
    btn.disabled = !gatewayConnected;
    btn.classList.toggle("active", !!enabled);
    btn.title = !gatewayConnected
      ? "Connect the gateway first to use Mediastreamer DNS."
      : enabled
        ? "Mediastreamer DNS is active (85.203.37.1 / .2). Click to disable."
        : "Routes hotspot DNS through 85.203.37.1 / .2, falling back to normal DNS if both are unreachable. Briefly disconnects all hotspot devices while applying.";
  }

  async function refreshMediastreamerDns(gatewayConnected) {
    try {
      const res = await PG.api.get("/api/settings/mediastreamer_dns");
      renderMediastreamerBtn(res.enabled, gatewayConnected);
    } catch (e) {
      PG.log.warn(TAG, "Failed to load Mediastreamer DNS status", { error: e.message });
    }
  }

  async function toggleMediastreamerDns() {
    const btn = document.getElementById("mediastreamer-dns-btn");
    if (btn.disabled || mediastreamerBusy) return;
    const enable = !btn.classList.contains("active");
    mediastreamerBusy = true;
    btn.disabled = true;
    setStatusLine(enable ? "Enabling Mediastreamer DNS…" : "Disabling Mediastreamer DNS…", false);
    try {
      const res = await PG.api.post("/api/settings/mediastreamer_dns", { enabled: enable });
      PG.log.info(TAG, "Mediastreamer DNS toggled", { enable, msg: res.msg });
      setStatusLine(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Mediastreamer DNS toggle failed", { error: e.message });
      setStatusLine(e.message, true);
    } finally {
      mediastreamerBusy = false;
      // Re-sync from the server rather than trusting the requested state —
      // an enable can fail and auto-roll back server-side, or the gateway
      // itself may have gone down while this was in flight.
      try {
        const stateRes = await PG.api.get("/api/gateway/state");
        await refreshMediastreamerDns(stateRes.state === "connected");
      } catch (e) { /* next poll() will resync anyway */ }
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
    document.getElementById("mediastreamer-dns-btn").addEventListener("click", toggleMediastreamerDns);
    initStatusDropdown();

    poll();
    setInterval(poll, POLL_MS);
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.status = { setStatusLine, poll };
})();
