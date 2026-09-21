/**
 * flow-detail.js — Charles/Burp-style request/response detail viewer.
 *
 * Opens on clicking a traffic row whose protocol is HTTP or HTTPS (the only
 * protocols that can ever have captured detail — see mitm_logger.py: only
 * decrypted flows reach the request()/response() hooks that populate
 * flow_details). Fetches /api/traffic/<id>/detail and renders headers +
 * body for both directions; a 404 (not decrypted, or a race where the flow
 * hasn't completed logging yet) shows a plain empty-state message instead
 * of an error.
 */

(function () {
  "use strict";

  const TAG = "flow-detail";

  function b64ToText(b64) {
    if (!b64) return "";
    try {
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch (e) {
      return "(binary data — could not decode as text)";
    }
  }

  // Headers arrive as newline-joined "Name: value" (see mitm_logger.py).
  function parseHeaders(text) {
    if (!text) return [];
    return text.split("\n").reduce((acc, line) => {
      const i = line.indexOf(":");
      if (i > 0) acc.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
      return acc;
    }, []);
  }

  function renderHeaders(el, pairs) {
    el.innerHTML = "";
    if (!pairs.length) {
      const note = document.createElement("div");
      note.className = "fd-empty-note";
      note.textContent = "No headers captured.";
      el.appendChild(note);
      return;
    }
    const frag = document.createDocumentFragment();
    for (const [name, value] of pairs) {
      const row = document.createElement("div");
      row.className = "fd-hrow";
      const n = document.createElement("span");
      n.className = "fd-hname";
      n.textContent = name;
      const v = document.createElement("span");
      v.className = "fd-hval";
      v.textContent = value;
      row.appendChild(n);
      row.appendChild(v);
      frag.appendChild(row);
    }
    el.appendChild(frag);
  }

  // Body text as shown, per side — what the body copy button yields. Kept
  // separate from the DOM so copying gets the prettified form rather than
  // whatever the browser's text extraction would produce.
  const bodyText = { request: "", response: "" };

  // Reformat JSON bodies with indentation. A truncated body is deliberately
  // left alone: it's cut mid-structure so it won't parse, and hammering it
  // into JSON.parse would just fail anyway.
  function prettifyJson(text, truncated) {
    if (truncated || !text) return text;
    const t = text.trim();
    if (!(t.startsWith("{") || t.startsWith("["))) return text;
    try {
      return JSON.stringify(JSON.parse(t), null, 2);
    } catch (e) {
      return text; // not actually JSON, leave it as-is
    }
  }

  function setSection(prefix, headers, bodyB64, truncated) {
    const pairs = parseHeaders(headers);
    renderHeaders(document.getElementById(`fd-${prefix}-headers`), pairs);
    document.getElementById(`fd-${prefix}-count`).textContent = pairs.length ? `(${pairs.length})` : "";

    const raw = bodyB64 ? b64ToText(bodyB64) : "";
    const shown = raw ? prettifyJson(raw, truncated) : "";
    bodyText[prefix] = shown;
    document.getElementById(`fd-${prefix}-body`).textContent = shown || "(empty body)";
    // Nothing to copy from an empty body.
    document.querySelector(`.fd-body-copy[data-side="${prefix}"]`)
      .classList.toggle("hidden", !shown);

    document.getElementById(`fd-${prefix}-truncated`).classList.toggle("hidden", !truncated);
    syncBodyScrollState(prefix);
    return pairs;
  }

  /* Whether the body's <pre> is actually scrolling right now. The copy
     button sits in the corner, so it has to shift left to clear the
     scrollbar when there is one — and only then, or it floats oddly far
     from the edge when there isn't. CSS can't branch on this (the gutter
     only exists while the content overflows), so it's measured and
     published as a class for .fd-body-copy to key off. */
  function syncBodyScrollState(prefix) {
    const pre = document.getElementById(`fd-${prefix}-body`);
    const wrap = document.getElementById(`fd-${prefix}-body-wrap`);
    if (!pre || !wrap) return;
    // Deferred a frame: a <pre> inside a .hidden wrapper has no layout yet,
    // so clientHeight/scrollHeight would both read 0 and never differ.
    requestAnimationFrame(() => {
      wrap.classList.toggle("fd-has-scroll", pre.scrollHeight > pre.clientHeight);
    });
  }

  function headerLookup(pairs) {
    const map = new Map(pairs.map(([k, v]) => [k.toLowerCase(), v]));
    return (name) => map.get(name);
  }

  function fmtBytes(n) {
    if (!(n >= 0)) return null;
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 ** 2).toFixed(1)} MB`;
  }

  function statusClass(code) {
    if (code == null || code === 0) return "fd-chip-dim";
    if (code >= 500) return "fd-chip-error";
    if (code >= 400) return "fd-chip-warn";
    if (code >= 200 && code < 300) return "fd-chip-ok";
    return "fd-chip-dim";
  }

  // Status sits left of the URL as a solid square-ish chip; size sits far
  // right next to the close button. Both are identity rather than detail,
  // which is why they're in the title bar and not the summary strip.
  function renderChips(row, respPairs) {
    const resp = headerLookup(respPairs);

    const status = document.getElementById("fd-status");
    const hasStatus = row.status_code != null && row.status_code !== 0;
    status.textContent = hasStatus ? String(row.status_code) : "—";
    // Rebuilding className also clears the `hidden` set in open().
    status.className = "fd-status " + statusClass(row.status_code);

    const size = fmtBytes(Number(resp("content-length"))) || fmtBytes(row.bytes_transferred) || "";
    document.getElementById("fd-size").textContent = size;
  }

  // The summary bar used to restate Type/Encoding/Server scraped out of the
  // response headers — which are one click away in the Headers tab, so it
  // was duplicating data rather than summarising anything. Kept as a no-op
  // hiding the element, so callers don't need to care.
  function renderSummary() {
    document.getElementById("fd-summary").classList.add("hidden");
  }

  // Headers/Body are tabs within each column, so the full pane height goes to
  // whichever one is being read.
  function showView(side, view) {
    document.querySelectorAll(`.fd-tab[data-side="${side}"]`).forEach((t) => {
      t.classList.toggle("active", t.dataset.view === view);
    });
    document.getElementById(`fd-${side}-headers`).classList.toggle("hidden", view !== "headers");
    document.getElementById(`fd-${side}-body-wrap`).classList.toggle("hidden", view !== "body");
    // The body only gets real dimensions once its wrapper is un-hidden, so
    // the overflow check has to run again here.
    if (view === "body") syncBodyScrollState(side);
  }

  function paneEl() {
    return document.getElementById("flow-pane");
  }

  // Host of the flow currently shown, without the :port — what the copy
  // button puts on the clipboard.
  let copyTarget = "";

  // The copy button only appears when the title is actually ellipsised, i.e.
  // when you can't read the whole thing anyway.
  function updateCopyVisibility() {
    const title = document.getElementById("fd-title");
    const btn = document.getElementById("fd-copy");
    const truncated = title.scrollWidth > title.clientWidth + 1;
    btn.classList.toggle("hidden", !truncated);
  }

  // navigator.clipboard only exists in a secure context. ProxyGate's UI is
  // served over plain HTTP on the LAN, so it's undefined in exactly the
  // normal case — hence the execCommand fallback, which still works there.
  async function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (e) { /* fall through to the textarea path */ }
    }
    const ta = document.createElement("textarea");
    ta.value = text;
    // Off-screen but still focusable, and readonly so mobile doesn't open a
    // keyboard for it.
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:-9999px;left:-9999px;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) { /* ok stays false */ }
    ta.remove();
    return ok;
  }

  // Copy `text`, confirming by swapping the button's glyph to a checkmark for
  // a moment. Deliberately no colour change — the icon itself is the
  // confirmation.
  async function copyWithFeedback(btn, text) {
    if (!text) return;
    const ok = await writeClipboard(text);
    if (!ok) {
      PG.log.warn(TAG, "Clipboard write failed");
      return;
    }
    const icon = btn.querySelector("i");
    clearTimeout(btn._copyTimer);
    icon.className = "fa-solid fa-check";
    btn._copyTimer = setTimeout(() => { icon.className = "fa-regular fa-copy"; }, 1200);
  }

  function copyUrl(e) {
    // The click can land on the <i>; keep it off the row/pane handlers.
    if (e) e.stopPropagation();
    return copyWithFeedback(document.getElementById("fd-copy"), copyTarget);
  }

  function close() {
    paneEl().classList.add("hidden");
    // Drop the row highlight — nothing is being inspected any more.
    document.querySelectorAll("#traffic-tbody tr.row-selected")
      .forEach((tr) => tr.classList.remove("row-selected"));
  }

  async function open(connectionId, row) {
    const host = row.dest_host || "?";
    const title = document.getElementById("fd-title");
    title.textContent = `${host}:${row.dest_port || "?"}`;
    title.title = title.textContent;
    // What the copy button yields: the host without the :port suffix.
    copyTarget = host;

    // The method belongs on the Request column's own title line.
    document.getElementById("fd-method").textContent = row.method || "";

    document.getElementById("fd-empty").classList.add("hidden");
    document.getElementById("fd-body").classList.add("hidden");
    document.getElementById("fd-summary").classList.add("hidden");
    document.getElementById("fd-status").classList.add("hidden");
    document.getElementById("fd-size").textContent = "";
    // Always start on Headers — carrying the previous flow's tab over is
    // disorienting when the new one has no body at all.
    showView("request", "headers");
    showView("response", "headers");

    // Mark which row is being shown, so it stays identifiable while the
    // feed keeps scrolling underneath.
    document.querySelectorAll("#traffic-tbody tr.row-selected")
      .forEach((tr) => tr.classList.remove("row-selected"));
    const tr = document.querySelector(`#traffic-tbody tr[data-id="${connectionId}"]`);
    if (tr) tr.classList.add("row-selected");

    paneEl().classList.remove("hidden");
    // After the pane is visible, so the title has real layout to measure.
    updateCopyVisibility();

    try {
      const res = await PG.api.get(`/api/traffic/${connectionId}/detail`);
      setSection("request", res.request_headers, res.request_body_b64, res.request_truncated);
      const respPairs = setSection("response", res.response_headers, res.response_body_b64, res.response_truncated);
      renderChips(row, respPairs);
      renderSummary();
      document.getElementById("fd-body").classList.remove("hidden");
      PG.log.info(TAG, "Flow detail loaded", { connectionId });
    } catch (e) {
      // 404 is the normal/expected case for anything not captured — not
      // every "clickable" row necessarily has a row in flow_details (e.g.
      // the response() hook hadn't fired yet when this was fetched).
      document.getElementById("fd-empty").classList.remove("hidden");
      PG.log.info(TAG, "No flow detail available", { connectionId, error: e.message });
    }
  }

  // Pane height is a per-browser display preference, like the column widths.
  const HEIGHT_KEY = "proxygate_flow_pane_h";
  const MIN_H = 80;

  /* Dragging the pane taller/shorter changes whether a body overflows, so
     the scroll state is re-measured on every size change rather than only
     when content is loaded. Covers tab switches and pane resizes alike. */
  function initBodyScrollWatch() {
    if (typeof ResizeObserver === "undefined") return;
    const obs = new ResizeObserver((entries) => {
      for (const e of entries) {
        const pre = e.target;
        const wrap = pre.parentElement;
        if (wrap) wrap.classList.toggle("fd-has-scroll", pre.scrollHeight > pre.clientHeight);
      }
    });
    for (const side of ["request", "response"]) {
      const pre = document.getElementById(`fd-${side}-body`);
      if (pre) obs.observe(pre);
    }
  }

  function initResize() {
    const pane = paneEl();
    const grip = document.getElementById("flow-pane-resize");
    if (!pane || !grip) return;

    try {
      const saved = parseFloat(localStorage.getItem(HEIGHT_KEY));
      if (saved >= MIN_H) pane.style.height = saved + "px";
    } catch (e) { /* private mode — default height stays */ }

    grip.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const startY = e.clientY;
      const startH = pane.getBoundingClientRect().height;
      // Leave room for the table above: the pane can't grow past the panel
      // minus a reasonable minimum for the traffic list itself.
      const maxH = pane.parentElement.getBoundingClientRect().height - 120;

      function onMove(ev) {
        // Dragging the grip UP grows the pane, hence the inverted delta.
        const h = Math.min(maxH, Math.max(MIN_H, startH - (ev.clientY - startY)));
        pane.style.height = h + "px";
      }
      function onUp() {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        document.body.classList.remove("row-resizing");
        try {
          localStorage.setItem(HEIGHT_KEY, pane.getBoundingClientRect().height);
        } catch (err) { /* private mode — applies for this session only */ }
      }
      document.body.classList.add("row-resizing");
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }

  function init() {
    document.getElementById("fd-close").addEventListener("click", close);
    document.getElementById("fd-copy").addEventListener("click", copyUrl);
    document.querySelectorAll(".fd-body-copy").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        copyWithFeedback(btn, bodyText[btn.dataset.side]);
      });
    });
    document.querySelectorAll(".fd-tab").forEach((tab) => {
      tab.addEventListener("click", () => showView(tab.dataset.side, tab.dataset.view));
    });
    // Whether the title is ellipsised depends on the pane's width.
    new ResizeObserver(updateCopyVisibility).observe(document.getElementById("fd-title"));
    initResize();
    initBodyScrollWatch();
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.flowDetail = { open, close };
})();
