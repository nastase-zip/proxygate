/**
 * proxies.js — Proxy list + Add/Edit/Duplicate/Remove, part of the status panel.
 * Mirrors ui/status_panel.py's proxy-list section.
 */

(function () {
  "use strict";

  const TAG = "proxies";
  let rulesData = { proxies: [] };
  let latency = {};

  let statusFadeTimer = null;

  // Uses the shared topbar status element, same as rules.js. This used to
  // target a "#proxy-status" element that doesn't exist in the template, so
  // every call threw a TypeError on the null — which meant no proxy add,
  // edit, delete or validation message ever reached the user, and the
  // throw aborted whatever ran after it.
  function setStatus(msg, isError) {
    const el = document.getElementById("rules-status");
    if (!el) return;
    clearTimeout(statusFadeTimer);
    el.textContent = msg || "";
    el.className = "topbar-status" + (isError ? " error" : msg ? " ok" : " hidden");

    if (msg && !isError) {
      statusFadeTimer = setTimeout(() => {
        el.classList.add("fading");
        setTimeout(() => {
          el.classList.add("hidden");
          el.classList.remove("fading");
        }, 400);
      }, 3000);
    }
  }

  function render() {
    const list = document.getElementById("proxy-list");
    list.innerHTML = "";
    list.classList.remove("no-hover");
    const proxies = rulesData.proxies || [];

    if (!proxies.length) {
      const empty = document.createElement("div");
      empty.className = "dim-label";
      empty.textContent = "No proxies configured.";
      list.appendChild(empty);
      return;
    }

    for (const proxy of proxies) {
      const pid = proxy.id || proxy.name;
      const row = document.createElement("div");
      row.className = "proxy-row";
      row.dataset.pid = pid;

      const body = document.createElement("div");
      body.className = "proxy-body";

      const proxyType = (proxy.type || "").toLowerCase();
      row.dataset.proxyType = proxyType;

      const titleLine = document.createElement("div");
      titleLine.className = "proxy-title-line";

      const typeTag = document.createElement("span");
      typeTag.className = "proxy-type-tag";
      typeTag.textContent = `[${proxyType || "?"}]`;

      const nameSpan = document.createElement("span");
      nameSpan.className = "proxy-name-text";
      nameSpan.textContent = proxy.name;

      titleLine.appendChild(typeTag);
      titleLine.appendChild(nameSpan);
      body.appendChild(titleLine);

      const detail = document.createElement("div");
      detail.className = "proxy-detail";
      detail.textContent = `${proxy.host}:${proxy.port}`;
      body.appendChild(detail);
      row.appendChild(body);

      const lat = latency[proxy.name];
      const sideCol = document.createElement("div");
      sideCol.className = "proxy-side-col";
      const latSpan = document.createElement("span");
      latSpan.className = "proxy-lat-badge " + (lat != null ? (lat < 200 ? "lat-ok" : "lat-warn") : "");
      latSpan.textContent = lat != null ? `${Math.round(lat)} ms` : "n/a ms";
      sideCol.appendChild(latSpan);

      const actions = document.createElement("div");
      actions.className = "proxy-actions";
      const editBtn = document.createElement("button");
      editBtn.className = "rule-action-btn";
      editBtn.innerHTML = '<i class="fa-solid fa-pen"></i>';
      editBtn.title = "Edit";
      editBtn.addEventListener("click", (e) => { e.stopPropagation(); editProxy(pid); });
      const dupBtn = document.createElement("button");
      dupBtn.className = "rule-action-btn";
      dupBtn.innerHTML = '<i class="fa-solid fa-copy"></i>';
      dupBtn.title = "Duplicate";
      dupBtn.addEventListener("click", (e) => { e.stopPropagation(); duplicateProxy(pid); });
      const delBtn = document.createElement("button");
      delBtn.className = "rule-action-btn rule-action-del";
      delBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
      delBtn.title = "Delete";
      delBtn.addEventListener("click", (e) => { e.stopPropagation(); removeProxy(pid); });
      actions.appendChild(editBtn);
      actions.appendChild(dupBtn);
      actions.appendChild(delBtn);
      sideCol.appendChild(actions);
      row.appendChild(sideCol);

      list.appendChild(row);
    }
  }

  function onRulesDataChanged(data) {
    rulesData = data;
    render();
  }

  async function refreshLatency() {
    try {
      const res = await PG.api.get("/api/proxies/latency");
      latency = res.latency || {};
      render();
    } catch (e) {
      PG.log.warn(TAG, "Latency refresh failed", { error: e.message });
    }
  }

  function openAddModal() {
    for (const id of ["apf-name", "apf-host", "apf-port", "apf-login", "apf-pass"]) {
      document.getElementById(id).value = "";
    }
    document.getElementById("apf-type").value = "http";
    setPasswordVisible("apf-pass", "apf-pass-toggle", false);
    PG.showModal("modal-add-proxy");
  }

  async function saveAdd() {
    const name = document.getElementById("apf-name").value.trim();
    const type = document.getElementById("apf-type").value;
    const host = document.getElementById("apf-host").value.trim();
    const port = document.getElementById("apf-port").value.trim();
    const login = document.getElementById("apf-login").value.trim();
    const password = document.getElementById("apf-pass").value;

    if (!name || !host || !port) {
      setStatus("Name, host and port are required.", true);
      return;
    }
    if (!/^\d+$/.test(port)) {
      setStatus("Port must be a number.", true);
      return;
    }
    try {
      const res = await PG.api.post("/api/proxies", { name, type, host, port: Number(port), login, password });
      PG.log.info(TAG, "Proxy added", { name, type, host, port });
      PG.hideModal("modal-add-proxy");
      onRulesDataChanged(res.data);
      window.PG.rules && window.PG.rules.refresh();
      setStatus(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Add proxy failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  function proxyByPid(pid) {
    return (rulesData.proxies || []).find((p) => (p.id || p.name) === pid) || null;
  }

  function editProxy(pid) {
    const proxy = proxyByPid(pid);
    if (!proxy) return;
    _editingPid = pid;
    document.getElementById("epf-name").value = proxy.name || "";
    document.getElementById("epf-type").value = proxy.type || "http";
    document.getElementById("epf-host").value = proxy.host || "";
    document.getElementById("epf-port").value = String(proxy.port || "");
    document.getElementById("epf-login").value = proxy.login || "";
    document.getElementById("epf-pass").value = proxy.password || "";
    setPasswordVisible("epf-pass", "epf-pass-toggle", false);
    PG.showModal("modal-edit-proxy");
  }

  let _editingPid = null;

  async function saveEdit() {
    const origProxy = proxyByPid(_editingPid);
    if (!origProxy) return;
    const origName = origProxy.name;
    const name = document.getElementById("epf-name").value.trim();
    const type = document.getElementById("epf-type").value;
    const host = document.getElementById("epf-host").value.trim();
    const port = document.getElementById("epf-port").value.trim();
    const login = document.getElementById("epf-login").value.trim();
    const password = document.getElementById("epf-pass").value;

    if (!name || !host || !port) {
      setStatus("Name, host and port are required.", true);
      return;
    }
    if (!/^\d+$/.test(port)) {
      setStatus("Port must be a number.", true);
      return;
    }
    try {
      const res = await PG.api.put(`/api/proxies/${encodeURIComponent(origName)}`, {
        name, type, host, port: Number(port), login, password,
      });
      PG.log.info(TAG, "Proxy updated", { origName, name, type, host, port });
      PG.hideModal("modal-edit-proxy");
      _editingPid = null;
      onRulesDataChanged(res.data);
      window.PG.rules && window.PG.rules.refresh();
      setStatus(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Update proxy failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  async function removeProxy(pid) {
    const proxy = proxyByPid(pid);
    if (!proxy) return;
    const proxies = rulesData.proxies || [];
    const index = proxies.findIndex((p) => (p.id || p.name) === pid);
    try {
      const res = await PG.api.del(`/api/proxies/${encodeURIComponent(proxy.name)}`);
      PG.log.info(TAG, "Proxy removed", { name: proxy.name, index });
      window.PG.undoStack.push({ type: "proxy", index, proxy });
      onRulesDataChanged(res.data);
      window.PG.rules && window.PG.rules.refresh();
      setStatus(res.msg + " (Ctrl+Z to undo)", false);
    } catch (e) {
      PG.log.error(TAG, "Remove proxy failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  async function restoreDeletedProxy({ index, proxy }) {
    const res = await PG.api.post("/api/proxies/restore", { index, proxy });
    PG.log.info(TAG, "Proxy delete undone", { name: proxy.name, index });
    onRulesDataChanged(res.data);
    window.PG.rules && window.PG.rules.refresh();
    setStatus(`Restored '${proxy.name}'`, false);
  }

  async function duplicateProxy(pid) {
    const proxy = proxyByPid(pid);
    if (!proxy) return;
    try {
      const res = await PG.api.post(`/api/proxies/${encodeURIComponent(proxy.name)}/duplicate`);
      PG.log.info(TAG, "Proxy duplicated", { name: proxy.name, newName: res.new_name });
      onRulesDataChanged(res.data);
      window.PG.rules && window.PG.rules.refresh();
      setStatus(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Duplicate proxy failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  function togglePasswordField(inputId, btnId) {
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

  function hasSelection() { return false; }
  function clearSelection() {}

  function init() {
    document.getElementById("proxy-add-btn").addEventListener("click", openAddModal);

    document.getElementById("apf-save").addEventListener("click", saveAdd);
    document.getElementById("apf-cancel").addEventListener("click", () => PG.hideModal("modal-add-proxy"));
    document.getElementById("apf-pass-toggle").addEventListener("click", () => togglePasswordField("apf-pass", "apf-pass-toggle"));

    document.getElementById("epf-save").addEventListener("click", saveEdit);
    document.getElementById("epf-cancel").addEventListener("click", () => PG.hideModal("modal-edit-proxy"));
    document.getElementById("epf-pass-toggle").addEventListener("click", () => togglePasswordField("epf-pass", "epf-pass-toggle"));

    window.PG.undoStack.registerRestorer("proxy", restoreDeletedProxy);

    refreshLatency();
    setInterval(refreshLatency, 10000);
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.proxies = { onRulesDataChanged, refreshLatency, hasSelection, clearSelection };
})();
