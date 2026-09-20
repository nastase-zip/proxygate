/**
 * settings.js — Settings modal (WAN iface, hotspot SSID/password/gateway IP,
 * WiFi adapter, band). Mirrors ui/status_panel.py's _build_settings_modal.
 */

(function () {
  "use strict";

  const TAG = "settings";

  // Purely a display filter for the traffic table (whether to show
  // "QUIC (blocked)" rows) — not gateway/network config, so it's a
  // per-browser localStorage preference (same idea as dark mode in
  // main.js) rather than a round-trip to /api/settings. Defaults to shown.
  const SHOW_QUIC_KEY = "proxygate_show_quic";

  function getShowQuic() {
    try {
      const v = localStorage.getItem(SHOW_QUIC_KEY);
      return v === null ? true : v === "1";
    } catch (e) {
      return true;
    }
  }

  function setShowQuic(show) {
    try { localStorage.setItem(SHOW_QUIC_KEY, show ? "1" : "0"); } catch (e) { /* ignore */ }
  }

  function fillWanSelect(sel, interfaces, current) {
    sel.innerHTML = "";
    const items = ["(auto-detect)", ...interfaces];
    if (current && current !== "(auto-detect)" && !items.includes(current)) items.splice(1, 0, current);
    for (const item of items) {
      const opt = document.createElement("option");
      opt.value = item;
      opt.textContent = item;
      if (item === current) opt.selected = true;
      sel.appendChild(opt);
    }
  }

  async function open() {
    try {
      const res = await PG.api.get("/api/settings");
      const cfg = res.config;
      const currentWan = cfg.wan_if || "(auto-detect)";
      fillWanSelect(document.getElementById("sf-wan"), res.interfaces, currentWan);
      document.getElementById("sf-ssid").value = cfg.ap_ssid || "ProxyGate";
      document.getElementById("sf-pass").value = cfg.ap_password || "proxygate123";
      document.getElementById("sf-pass").type = "password";
      document.getElementById("sf-pass-toggle").textContent = "●";
      document.getElementById("sf-gw").value = cfg.hotspot_gw || "192.168.100.1";
      document.getElementById("sf-wifi-if").value = cfg.ap_wifi_if || "*";
      document.getElementById("sf-band").value = cfg.ap_band || "";
      document.getElementById("sf-show-quic").checked = getShowQuic();
      PG.log.info(TAG, "Settings modal opened", { cfg });
      PG.showModal("modal-settings");
    } catch (e) {
      PG.log.error(TAG, "Failed to load settings", { error: e.message });
      window.PG.status && window.PG.status.setStatusLine("Failed to load settings: " + e.message, true);
    }
  }

  async function detectWan() {
    try {
      const res = await PG.api.post("/api/settings/detect_wan");
      const sel = document.getElementById("sf-wan");
      const iface = res.iface;
      if (![...sel.options].some((o) => o.value === iface)) {
        const opt = document.createElement("option");
        opt.value = iface;
        opt.textContent = iface;
        sel.appendChild(opt);
      }
      sel.value = iface;
      PG.log.info(TAG, "WAN interface detected", { iface });
    } catch (e) {
      PG.log.warn(TAG, "WAN detect failed", { error: e.message });
    }
  }

  async function save() {
    const wanRaw = document.getElementById("sf-wan").value;
    const body = {
      wan_if: wanRaw === "(auto-detect)" ? "" : wanRaw,
      ap_ssid: document.getElementById("sf-ssid").value.trim(),
      ap_password: document.getElementById("sf-pass").value,
      hotspot_gw: document.getElementById("sf-gw").value.trim(),
      ap_wifi_if: document.getElementById("sf-wifi-if").value.trim() || "*",
      ap_band: document.getElementById("sf-band").value,
    };
    // show-quic is a local display preference, not gateway config — saved
    // straight to localStorage, no /api/settings round-trip involved.
    const showQuic = document.getElementById("sf-show-quic").checked;
    setShowQuic(showQuic);
    window.PG.traffic && window.PG.traffic.setShowQuic(showQuic);
    try {
      const res = await PG.api.post("/api/settings", body);
      PG.log.info(TAG, "Settings saved", { body: { ...body, ap_password: "***" }, showQuic });
      PG.hideModal("modal-settings");
      window.PG.status && window.PG.status.setStatusLine(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Save settings failed", { error: e.message });
      window.PG.status && window.PG.status.setStatusLine(e.message, true);
    }
  }

  function togglePassword(inputId, btnId) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    btn.textContent = hidden ? "○" : "●";
  }

  function init() {
    document.getElementById("settings-btn").addEventListener("click", open);
    document.getElementById("sf-detect").addEventListener("click", detectWan);
    document.getElementById("sf-save").addEventListener("click", save);
    document.getElementById("sf-cancel").addEventListener("click", () => PG.hideModal("modal-settings"));
    document.getElementById("sf-pass-toggle").addEventListener("click", () => togglePassword("sf-pass", "sf-pass-toggle"));
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.settings = { open };
})();
