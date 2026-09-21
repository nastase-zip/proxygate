/**
 * devices.js — Decrypt-devices panel.
 *
 * Lists devices flagged (by MAC) to get real TLS decryption instead of raw
 * passthrough. A device only shows up decrypted if it also has the CA
 * (downloadable from this panel) installed and trusted — flagging it here
 * without installing the CA just breaks TLS for that device.
 */

(function () {
  "use strict";

  const TAG = "devices";
  let data = { devices: [] };
  let seen = [];

  let statusFadeTimer = null;

  function setStatus(msg, isError) {
    const el = document.getElementById("rules-status");
    if (!el) return;
    clearTimeout(statusFadeTimer);
    el.textContent = msg || "";
    el.className = "topbar-status" + (isError ? " error" : msg ? " ok" : " hidden");
    if (msg && !isError) {
      statusFadeTimer = setTimeout(() => {
        el.classList.add("fading");
        setTimeout(() => { el.classList.add("hidden"); el.classList.remove("fading"); }, 400);
      }, 3000);
    }
  }

  function render() {
    const list = document.getElementById("device-list");
    list.innerHTML = "";
    const devices = data.devices || [];

    if (!devices.length) {
      return;
    }

    for (const dev of devices) {
      const row = document.createElement("div");
      row.className = "device-row";
      row.dataset.mac = dev.mac;

      const body = document.createElement("div");
      body.className = "proxy-body";

      const titleLine = document.createElement("div");
      titleLine.className = "proxy-title-line";
      const nameSpan = document.createElement("span");
      nameSpan.className = "proxy-name-text";
      nameSpan.textContent = dev.label || dev.mac;
      titleLine.appendChild(nameSpan);
      body.appendChild(titleLine);

      const detail = document.createElement("div");
      detail.className = "proxy-detail";
      detail.textContent = dev.label ? dev.mac : "";
      body.appendChild(detail);
      row.appendChild(body);

      const sideCol = document.createElement("div");
      sideCol.className = "proxy-side-col";

      const actions = document.createElement("div");
      actions.className = "proxy-actions";

      const toggleBtn = document.createElement("button");
      toggleBtn.className = "rule-action-btn";
      toggleBtn.innerHTML = dev.decrypt
        ? '<i class="fa-solid fa-unlock"></i>'
        : '<i class="fa-solid fa-lock"></i>';
      toggleBtn.title = dev.decrypt ? "Decrypting — click to pause" : "Passthrough — click to decrypt";
      toggleBtn.addEventListener("click", () => setDecrypt(dev.mac, !dev.decrypt));

      const delBtn = document.createElement("button");
      delBtn.className = "rule-action-btn";
      delBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
      delBtn.title = "Remove";
      delBtn.addEventListener("click", () => removeDevice(dev.mac));

      actions.appendChild(toggleBtn);
      actions.appendChild(delBtn);
      sideCol.appendChild(actions);
      row.appendChild(sideCol);

      list.appendChild(row);
    }
  }

  async function refresh() {
    try {
      const [devRes, seenRes] = await Promise.all([
        PG.api.get("/api/devices/decrypt"),
        PG.api.get("/api/devices/seen"),
      ]);
      data = devRes.data;
      seen = seenRes.devices || [];
      PG.log.info(TAG, "Devices loaded", { flagged: (data.devices || []).length, seen: seen.length });
      render();
    } catch (e) {
      PG.log.error(TAG, "Failed to load devices", { error: e.message });
      setStatus("Failed to load devices: " + e.message, true);
    }
  }

  async function setDecrypt(mac, decrypt) {
    try {
      const res = await PG.api.put(`/api/devices/decrypt/${encodeURIComponent(mac)}`, { decrypt });
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Toggle device failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  async function removeDevice(mac) {
    try {
      const res = await PG.api.del(`/api/devices/decrypt/${encodeURIComponent(mac)}`);
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Remove device failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  function openAddModal() {
    const sel = document.getElementById("adf-seen");
    sel.innerHTML = "";
    const blank = document.createElement("option");
    blank.value = "";
    blank.textContent = seen.length ? "— choose a device seen on the hotspot —" : "(no devices seen yet)";
    sel.appendChild(blank);
    for (const d of seen) {
      const opt = document.createElement("option");
      opt.value = d.mac;
      // Lead with whatever identifies the device best — its DHCP hostname,
      // else its MAC vendor — so the list is scannable instead of a column
      // of near-identical IPs. display_name falls back to the IP itself.
      const name = d.display_name || d.hostname || d.ip;
      const detail = name === d.ip ? d.mac : `${d.ip} · ${d.mac}`;
      opt.textContent = `${name} · ${detail}`;
      sel.appendChild(opt);
    }
    sel.onchange = () => {
      if (!sel.value) return;
      document.getElementById("adf-mac").value = sel.value;
      // Pre-fill the label with the device's name so it's one less thing
      // to type; still editable before saving.
      const picked = seen.find((d) => d.mac === sel.value);
      const labelEl = document.getElementById("adf-label");
      if (picked && !labelEl.value) {
        const n = picked.hostname || picked.vendor || "";
        if (n) labelEl.value = n;
      }
    };
    document.getElementById("adf-mac").value = "";
    document.getElementById("adf-label").value = "";
    PG.showModal("modal-add-device");
  }

  async function saveAdd() {
    const mac = document.getElementById("adf-mac").value.trim();
    const label = document.getElementById("adf-label").value.trim();
    if (!mac) {
      setStatus("MAC address is required.", true);
      return;
    }
    try {
      const res = await PG.api.post("/api/devices/decrypt", { mac, label });
      PG.log.info(TAG, "Device added", { mac, label });
      PG.hideModal("modal-add-device");
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Add device failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  function init() {
    document.getElementById("device-add-btn").addEventListener("click", openAddModal);
    document.getElementById("adf-save").addEventListener("click", saveAdd);
    document.getElementById("adf-cancel").addEventListener("click", () => PG.hideModal("modal-add-device"));
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.devices = { refresh };
})();
