/**
 * rules.js — Routing rules panel.
 *
 * Mirrors ui/rules_panel.py: list rules from rules.yaml (via GET /api/rules),
 * Add / Edit / Delete / Move / Toggle operations call the REST API which
 * writes rules.yaml and triggers reload_rules() server-side, same as the
 * old "Apply Rules Now" button did in the desktop app.
 */

(function () {
  "use strict";

  const TAG = "rules";
  let data = { proxies: [], rules: [], default: "DIRECT" };
  let selected = null;
  let isDragging = false;

  function proxyDisplayItems() {
    const items = [{ value: "DIRECT", label: "DIRECT" }, { value: "BLOCK", label: "BLOCK" }];
    for (const p of data.proxies || []) {
      items.push({ value: p.name, label: `[${(p.type || "?").toUpperCase()}] ${p.name}` });
    }
    return items;
  }

  function proxyLabel(name) {
    if (name === "DIRECT" || name === "BLOCK" || !name) return name || "DIRECT";
    const p = (data.proxies || []).find((p) => p.name === name);
    return p ? `[${(p.type || "?").toUpperCase()}] ${p.name}` : name;
  }

  function fillSelect(sel, items, selectedValue) {
    sel.innerHTML = "";
    for (const it of items) {
      const opt = document.createElement("option");
      opt.value = it.value;
      opt.textContent = it.label;
      if (it.value === selectedValue) opt.selected = true;
      sel.appendChild(opt);
    }
  }

  let statusFadeTimer = null;

  function setStatus(msg, isError) {
    const el = document.getElementById("rules-status");
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
    const list = document.getElementById("rules-list");
    list.innerHTML = "";
    list.classList.remove("no-hover");
    const rules = data.rules || [];

    if (!rules.length) {
      const empty = document.createElement("div");
      empty.className = "dim-label";
      empty.textContent = "No rules yet.";
      list.appendChild(empty);
    }

    rules.forEach((rule, i) => {
      const row = document.createElement("div");
      row.className = "rule-row" + (rule.enabled === false ? " disabled" : "");
      row.dataset.index = String(i);

      const toggleDot = document.createElement("span");
      toggleDot.className = "rule-toggle-dot";
      toggleDot.title = rule.enabled === false ? "Enable rule" : "Disable rule";
      toggleDot.addEventListener("click", (e) => { e.stopPropagation(); if (isDragging) return; selected = Number(row.dataset.index); toggleSelected(); });
      toggleDot.addEventListener("mousedown", (e) => e.stopPropagation());
      toggleDot.addEventListener("pointerdown", (e) => e.stopPropagation());
      const dotInner = document.createElement("span");
      dotInner.className = "dot " + (rule.enabled === false ? "dim" : "ok");
      toggleDot.appendChild(dotInner);
      row.appendChild(toggleDot);

      const body = document.createElement("div");
      body.className = "rule-body";

      const textCol = document.createElement("div");
      textCol.className = "rule-text-col";
      const nameRow = document.createElement("div");
      nameRow.className = "rule-name";
      const nameText = document.createElement("span");
      nameText.className = "rule-name-text";
      nameText.textContent = rule.name || "?";
      nameRow.appendChild(nameText);
      textCol.appendChild(nameRow);
      const sub = document.createElement("div");
      sub.className = "rule-sub";
      sub.textContent = `↳ ${proxyLabel(rule.proxy || "DIRECT")}`;
      textCol.appendChild(sub);

      const inlineActions = document.createElement("div");
      inlineActions.className = "rule-inline-actions";
      const editBtn = document.createElement("button");
      editBtn.className = "rule-action-btn";
      editBtn.innerHTML = '<i class="fa-solid fa-pen"></i>';
      editBtn.title = "Edit";
      editBtn.addEventListener("click", (e) => { e.stopPropagation(); if (isDragging) return; selected = Number(row.dataset.index); openEditModal(); });
      const dupBtn = document.createElement("button");
      dupBtn.className = "rule-action-btn";
      dupBtn.innerHTML = '<i class="fa-solid fa-copy"></i>';
      dupBtn.title = "Duplicate";
      dupBtn.addEventListener("click", (e) => { e.stopPropagation(); if (isDragging) return; selected = Number(row.dataset.index); duplicateSelected(); });
      const delBtn = document.createElement("button");
      delBtn.className = "rule-action-btn";
      delBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
      delBtn.title = "Delete";
      delBtn.addEventListener("click", (e) => { e.stopPropagation(); if (isDragging) return; selected = Number(row.dataset.index); deleteSelected(); });
      [editBtn, dupBtn, delBtn].forEach(btn => {
        btn.addEventListener("mousedown", (e) => e.stopPropagation());
        btn.addEventListener("pointerdown", (e) => e.stopPropagation());
      });
      inlineActions.appendChild(editBtn);
      inlineActions.appendChild(dupBtn);
      inlineActions.appendChild(delBtn);

      body.appendChild(textCol);
      body.appendChild(inlineActions);
      row.appendChild(body);

      row.addEventListener("click", () => {
        const idx = Number(row.dataset.index);
        selected = selected === idx ? null : idx;
        if (selected !== null) window.PG.proxies && window.PG.proxies.clearSelection();
        PG.log.info(TAG, "Rule selected", { index: selected });
        render();
      });
      list.appendChild(row);
    });

    const fallbackSel = document.getElementById("fallback-select");
    fillSelect(fallbackSel, proxyDisplayItems(), data.default || "DIRECT");
  }

  function initDragDrop() {
    const list = document.getElementById("rules-list");

    list.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      if (e.target.closest("button, input, select, textarea")) return;
      const row = e.target.closest(".rule-row");
      if (!row) return;
      if (!e.target.closest(".rule-text-col, .rule-name-text")) return;

      const startY = e.clientY;
      let cleanedUp = false;

      function cleanup() {
        if (cleanedUp) return;
        cleanedUp = true;
        clearTimeout(holdTimer);
        document.removeEventListener("pointermove", onEarlyMove);
        document.removeEventListener("pointerup", onEarlyUp);
        row.classList.remove("drag-pending");
      }

      function onEarlyUp() { cleanup(); }
      function onEarlyMove(ev) { if (Math.abs(ev.clientY - startY) > 6) cleanup(); }

      const holdTimer = setTimeout(() => {
        if (cleanedUp) return;
        document.removeEventListener("pointermove", onEarlyMove);
        document.removeEventListener("pointerup", onEarlyUp);
        row.classList.remove("drag-pending");
        beginDrag(e, row);
      }, 30);

      document.addEventListener("pointermove", onEarlyMove);
      document.addEventListener("pointerup", onEarlyUp);
    });

    function beginDrag(startEvent, row) {
      isDragging = true;
      const srcIndex = Number(row.dataset.index);
      const rowRect = row.getBoundingClientRect();
      const grabOffsetY = startEvent.clientY - rowRect.top;

      const placeholder = document.createElement("div");
      placeholder.className = "rule-drag-placeholder";
      placeholder.style.height = rowRect.height + "px";
      row.parentNode.insertBefore(placeholder, row.nextSibling);

      row.style.position = "fixed";
      row.style.top = rowRect.top + "px";
      row.style.left = rowRect.left + "px";
      row.style.width = rowRect.width + "px";
      row.style.zIndex = "999";
      row.style.pointerEvents = "none";
      row.classList.add("dragging");

      function onMove(e) {
        row.style.top = (e.clientY - grabOffsetY) + "px";
        const siblings = Array.from(list.querySelectorAll(".rule-row:not(.dragging)"));
        let insertBefore = null;
        for (const sib of siblings) {
          const r = sib.getBoundingClientRect();
          if (e.clientY < r.top + r.height / 2) { insertBefore = sib; break; }
        }
        if (insertBefore) {
          if (placeholder.nextSibling !== insertBefore) list.insertBefore(placeholder, insertBefore);
        } else {
          if (list.lastChild !== placeholder) list.appendChild(placeholder);
        }
      }

      async function onUp() {
        document.removeEventListener("pointermove", onMove);
        document.removeEventListener("pointerup", onUp);

        // Place row where placeholder is, clean up DOM
        list.insertBefore(row, placeholder);
        list.removeChild(placeholder);
        row.style.cssText = "";
        row.classList.remove("dragging");

        // Capture old indices before re-indexing, then rebuild rules from DOM order
        const domRows = Array.from(list.querySelectorAll(".rule-row"));
        const newRules = domRows.map(r => data.rules[Number(r.dataset.index)]);
        domRows.forEach((r, i) => { r.dataset.index = String(i); });

        // Check if anything actually moved
        const moved = newRules.some((r, i) => r !== data.rules[i]);
        if (!moved) { isDragging = false; return; }

        // Update local data immediately — no waiting for server
        data = { ...data, rules: newRules };

        isDragging = false;

        // Persist to server silently; on failure revert to server state
        try {
          await PG.api.post("/api/rules/reorder", { order: newRules.map(r => r.name) });
        } catch (err) {
          PG.log.error(TAG, "Drag reorder failed", { error: err.message });
          setStatus(err.message, true);
          refresh();
        }
      }

      document.addEventListener("pointermove", onMove);
      document.addEventListener("pointerup", onUp);
    }
  }

  async function refresh() {
    try {
      const res = await PG.api.get("/api/rules");
      data = res.data;
      PG.log.info(TAG, "Rules loaded", { ruleCount: (data.rules || []).length, proxyCount: (data.proxies || []).length });
      render();
      window.PG.proxies && window.PG.proxies.onRulesDataChanged(data);
    } catch (e) {
      PG.log.error(TAG, "Failed to load rules", { error: e.message });
      setStatus("Failed to load rules: " + e.message, true);
    }
  }

  // Height of the Patterns textarea, dragged from its corner. Per-browser
  // display preference, like the traffic pane and column sizes. Shared by the
  // Add and Edit dialogs, which hold the same field.
  const PATTERN_H_KEY = "proxygate_rule_pattern_h";
  const PATTERN_MIN_H = 40;

  function restorePatternHeight(ta) {
    try {
      const saved = parseFloat(localStorage.getItem(PATTERN_H_KEY));
      if (saved >= PATTERN_MIN_H) ta.style.height = saved + "px";
    } catch (e) { /* private mode — default height stays */ }
  }

  // A textarea's native resize fires no event of its own, so watch its size.
  // Only a visible field is saved: a hidden modal measures 0 and would
  // otherwise overwrite the stored height.
  function watchPatternHeight(ta) {
    if (typeof ResizeObserver === "undefined") return;
    new ResizeObserver(() => {
      if (!ta.offsetParent) return;
      const h = ta.getBoundingClientRect().height;
      if (h < PATTERN_MIN_H) return;
      try { localStorage.setItem(PATTERN_H_KEY, String(Math.round(h))); }
      catch (e) { /* private mode — applies for this session only */ }
    }).observe(ta);
  }

  function openAddModal() {
    document.getElementById("af-name").value = "";
    document.getElementById("af-pattern").value = "";
    restorePatternHeight(document.getElementById("af-pattern"));
    document.getElementById("af-enabled").checked = true;
    fillSelect(document.getElementById("af-proxy"), proxyDisplayItems(), "DIRECT");
    clearPatternError("af");
    PG.showModal("modal-add-rule");
  }

  function openEditModal() {
    if (selected === null) {
      setStatus("Select a rule first.", true);
      return;
    }
    const rule = (data.rules || [])[selected];
    if (!rule) return;
    document.getElementById("ef-name").value = rule.name || "";
    document.getElementById("ef-pattern").value = rule.pattern || "";
    restorePatternHeight(document.getElementById("ef-pattern"));
    document.getElementById("ef-enabled").checked = rule.enabled !== false;
    fillSelect(document.getElementById("ef-proxy"), proxyDisplayItems(), rule.proxy || "DIRECT");
    clearPatternError("ef");
    PG.showModal("modal-edit-rule");
  }

  // Validation feedback for the pattern field, shown inline under it rather
  // than only in the topbar — the user is looking at the dialog, not the top
  // of the page, and the message (an invalid or rejected regex) is about the
  // field directly above it.
  function setPatternError(prefix, msg) {
    const box = document.getElementById(`${prefix}-pattern-error`);
    if (!box) return;
    box.classList.toggle("hidden", !msg);
    box.querySelector("span").textContent = msg || "";
  }

  function clearPatternError(prefix) {
    setPatternError(prefix, "");
  }

  async function saveAdd() {
    const name = document.getElementById("af-name").value.trim();
    const pattern = document.getElementById("af-pattern").value.trim();
    const proxy = document.getElementById("af-proxy").value;
    const enabled = document.getElementById("af-enabled").checked;
    clearPatternError("af");
    if (!name || !pattern) {
      setPatternError("af", "Name and pattern are both required.");
      return;
    }
    try {
      const res = await PG.api.post("/api/rules", { name, pattern, proxy, enabled });
      PG.log.info(TAG, "Rule added", { name, pattern, proxy, enabled });
      PG.hideModal("modal-add-rule");
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Add rule failed", { error: e.message });
      // Stays open so the pattern can be corrected in place.
      setPatternError("af", e.message);
    }
  }

  async function saveEdit() {
    if (selected === null) return;
    const name = document.getElementById("ef-name").value.trim();
    const pattern = document.getElementById("ef-pattern").value.trim();
    const proxy = document.getElementById("ef-proxy").value;
    const enabled = document.getElementById("ef-enabled").checked;
    clearPatternError("ef");
    if (!name || !pattern) {
      setPatternError("ef", "Name and pattern are both required.");
      return;
    }
    try {
      const res = await PG.api.put(`/api/rules/${selected}`, { name, pattern, proxy, enabled });
      PG.log.info(TAG, "Rule updated", { index: selected, name, pattern, proxy, enabled });
      PG.hideModal("modal-edit-rule");
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Update rule failed", { error: e.message });
      setPatternError("ef", e.message);
    }
  }

  async function deleteSelected() {
    if (selected === null) {
      setStatus("Select a rule first.", true);
      return;
    }
    const rule = (data.rules || [])[selected];
    const index = selected;
    try {
      const res = await PG.api.del(`/api/rules/${index}`);
      PG.log.info(TAG, "Rule deleted", { index });
      if (rule) window.PG.undoStack.push({ type: "rule", index, rule });
      data = res.data;
      // Focus lands where the deleted rule was — i.e. the rule that shifted
      // up into its slot — or the new last rule if it was at the bottom.
      const rules = data.rules || [];
      selected = rules.length ? Math.min(index, rules.length - 1) : null;
      setStatus(res.msg + " (Ctrl+Z to undo)", false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Delete rule failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  async function restoreDeletedRule({ index, rule }) {
    const res = await PG.api.post("/api/rules/restore", { index, rule });
    PG.log.info(TAG, "Rule delete undone", { index });
    selected = index;
    window.PG.proxies && window.PG.proxies.clearSelection();
    data = res.data;
    setStatus(res.msg, false);
    render();
  }

  async function duplicateSelected() {
    if (selected === null) {
      setStatus("Select a rule first.", true);
      return;
    }
    try {
      const res = await PG.api.post(`/api/rules/${selected}/duplicate`);
      PG.log.info(TAG, "Rule duplicated", { index: selected });
      selected = res.new_index;
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Duplicate rule failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  async function toggleSelected() {
    if (selected === null) {
      setStatus("Select a rule first.", true);
      return;
    }
    try {
      const res = await PG.api.post(`/api/rules/${selected}/toggle`);
      PG.log.info(TAG, "Rule toggled", { index: selected });
      data = res.data;
      setStatus(res.msg, false);
      render();
    } catch (e) {
      PG.log.error(TAG, "Toggle rule failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  function hasSelection() {
    return selected !== null;
  }

  function clearSelection() {
    if (selected !== null) {
      selected = null;
      render();
    }
  }

  async function onFallbackChange(e) {
    const value = e.target.value;
    try {
      const res = await PG.api.post("/api/rules/default", { default: value });
      PG.log.info(TAG, "Fallback proxy changed", { value });
      data = res.data;
      setStatus(res.msg, false);
    } catch (err) {
      PG.log.error(TAG, "Set fallback failed", { error: err.message });
      setStatus(err.message, true);
    }
  }

  async function applyNow() {
    try {
      const res = await PG.api.post("/api/rules/apply");
      PG.log.info(TAG, "Apply Rules Now clicked");
      setStatus(res.msg, false);
    } catch (e) {
      PG.log.error(TAG, "Apply rules failed", { error: e.message });
      setStatus(e.message, true);
    }
  }

  function init() {
    document.getElementById("rule-add-btn").addEventListener("click", openAddModal);
    watchPatternHeight(document.getElementById("af-pattern"));
    watchPatternHeight(document.getElementById("ef-pattern"));
    const fallbackSelEl = document.getElementById("fallback-select");
    fallbackSelEl.addEventListener("change", (e) => { onFallbackChange(e); fallbackSelEl.blur(); });
    document.getElementById("apply-rules-btn").addEventListener("click", applyNow);

    document.getElementById("af-save").addEventListener("click", saveAdd);
    // Clear the inline error as soon as the user starts correcting it, so a
    // stale message doesn't sit under a field they've already fixed.
    document.getElementById("af-pattern").addEventListener("input", () => clearPatternError("af"));
    document.getElementById("ef-pattern").addEventListener("input", () => clearPatternError("ef"));
    document.getElementById("af-cancel").addEventListener("click", () => PG.hideModal("modal-add-rule"));
    document.getElementById("ef-save").addEventListener("click", saveEdit);
    document.getElementById("ef-cancel").addEventListener("click", () => PG.hideModal("modal-edit-rule"));

    initDragDrop();
    window.PG.undoStack.registerRestorer("rule", restoreDeletedRule);

    refresh();
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.rules = { refresh, getData: () => data, proxyDisplayItems, hasSelection, clearSelection };
})();
