/**
 * settings.js — Settings modal (hotspot SSID/password, WiFi band).
 *
 * WAN interface, gateway IP and WiFi adapter used to be editable here but
 * aren't any more: they're auto-detected at connect time. Their config keys
 * still exist server-side, so this modal deliberately leaves them alone
 * rather than posting blanks over them (see gatewayFields).
 */

(function () {
  "use strict";

  const TAG = "settings";

  // Purely a display filter for the traffic table (whether to show
  // "QUIC (blocked)" rows) — not gateway/network config, so it's a
  // per-browser localStorage preference (same idea as dark mode in
  // main.js) rather than a round-trip to /api/settings. Defaults to hidden —
  // traffic.js holds the same default for its initial render.
  const SHOW_QUIC_KEY = "proxygate_show_quic";

  function getShowQuic() {
    try {
      return localStorage.getItem(SHOW_QUIC_KEY) === "1";
    } catch (e) {
      return false;
    }
  }

  function setShowQuic(show) {
    try { localStorage.setItem(SHOW_QUIC_KEY, show ? "1" : "0"); } catch (e) { /* ignore */ }
  }

  // The gateway config the modal was opened with. Used to skip the
  // /api/settings POST — and its "reconnect to apply" prompt — when the user
  // only came in to flip a local display preference.
  let openedWith = null;

  // Values for the config keys this modal no longer exposes. /api/settings
  // writes every key it receives, so these are echoed back verbatim to keep
  // the stored config intact instead of overwriting it with blanks.
  let passthrough = { wan_if: "", hotspot_gw: "", ap_wifi_if: "*" };

  function gatewayFields() {
    return {
      wan_if: passthrough.wan_if,
      ap_ssid: document.getElementById("sf-ssid").value.trim(),
      ap_password: document.getElementById("sf-pass").value,
      hotspot_gw: passthrough.hotspot_gw,
      ap_wifi_if: passthrough.ap_wifi_if,
      ap_band: document.getElementById("sf-band").value,
    };
  }

  async function open() {
    try {
      const res = await PG.api.get("/api/settings");
      const cfg = res.config;
      passthrough = {
        wan_if: cfg.wan_if || "",
        hotspot_gw: cfg.hotspot_gw || "192.168.100.1",
        ap_wifi_if: cfg.ap_wifi_if || "*",
      };
      document.getElementById("sf-ssid").value = cfg.ap_ssid || "ProxyGate";
      document.getElementById("sf-pass").value = cfg.ap_password || "proxygate123";
      setPasswordVisible("sf-pass", "sf-pass-toggle", false);
      document.getElementById("sf-band").value = cfg.ap_band || "";
      document.getElementById("sf-show-quic").checked = getShowQuic();
      document.getElementById("sf-full-lines").checked =
        !!(window.PG.getFullHeightLines && window.PG.getFullHeightLines());
      // Snapshot of the gateway fields as loaded, so save() can tell whether
      // any of them actually changed.
      openedWith = gatewayFields();
      PG.log.info(TAG, "Settings modal opened", { cfg });
      PG.showModal("modal-settings");
    } catch (e) {
      PG.log.error(TAG, "Failed to load settings", { error: e.message });
      window.PG.status && window.PG.status.setStatusLine("Failed to load settings: " + e.message, true);
    }
  }

  async function save() {
    const body = gatewayFields();
    // The display preferences (show-quic, full-height dividers) are NOT
    // handled here — they're applied and persisted to localStorage on change,
    // see init(). This function only deals with gateway config.
    //
    // If none of that config was touched, don't POST at all: the request
    // prompts to reconnect the gateway, which is misleading when the user
    // only opened this modal to toggle a display preference and then hit
    // Save to close it.
    if (openedWith && Object.keys(body).every((k) => body[k] === openedWith[k])) {
      PG.log.info(TAG, "Settings closed with no gateway changes — skipping save");
      PG.hideModal("modal-settings");
      return;
    }
    try {
      const res = await PG.api.post("/api/settings", body);
      PG.log.info(TAG, "Settings saved", { body: { ...body, ap_password: "***" } });
      PG.hideModal("modal-settings");
      window.PG.status && window.PG.status.setStatusLine(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Save settings failed", { error: e.message });
      window.PG.status && window.PG.status.setStatusLine(e.message, true);
    }
  }

  function togglePassword(inputId, btnId) {
    setPasswordVisible(inputId, btnId,
                       document.getElementById(inputId).type === "password");
  }

  /* Drives both the input type and the eye icon, so the button can never
     end up showing the wrong state after a modal reopen. */
  function setPasswordVisible(inputId, btnId, visible) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    input.type = visible ? "text" : "password";
    btn.classList.toggle("on", visible);
    btn.title = visible ? "Hide password" : "Show password";
    btn.setAttribute("aria-label", btn.title);
    const icon = btn.querySelector("i");
    if (icon) icon.className = visible ? "fa-regular fa-eye-slash"
                                       : "fa-regular fa-eye";
  }

  function init() {
    document.getElementById("settings-btn").addEventListener("click", open);
    document.getElementById("sf-save").addEventListener("click", save);

    // Display preferences apply the moment they're toggled and are stored in
    // localStorage. They deliberately do NOT go through Save: that button
    // POSTs the gateway config and prompts to reconnect, which has nothing
    // to do with how the traffic table happens to be drawn.
    document.getElementById("sf-show-quic").addEventListener("change", (e) => {
      setShowQuic(e.target.checked);
      window.PG.traffic && window.PG.traffic.setShowQuic(e.target.checked);
    });
    document.getElementById("sf-full-lines").addEventListener("change", (e) => {
      window.PG.setFullHeightLines && window.PG.setFullHeightLines(e.target.checked);
    });
    document.getElementById("sf-cancel").addEventListener("click", () => PG.hideModal("modal-settings"));
    document.getElementById("sf-pass-toggle").addEventListener("click", () => togglePassword("sf-pass", "sf-pass-toggle"));
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.settings = { open };
})();
