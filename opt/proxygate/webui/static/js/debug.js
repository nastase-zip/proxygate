/**
 * debug.js — In-browser debug console + structured logging for ProxyGate web UI.
 *
 * Goal: if the desktop→web migration breaks something, whoever's looking at it
 * should be able to open the page, hit the 🐞 button (or Ctrl+Shift+D), and see:
 *   - every API call made, its URL/method/body, status, timing, and response
 *   - every state transition the UI made in response
 *   - any uncaught JS error or unhandled promise rejection, with stack trace
 *   - a running log they can copy out or export to a file
 *
 * Logs also mirror to the real browser console (console.log/warn/error) AND,
 * best-effort, to the server via POST /api/clientlog so they show up in the
 * server-side log file too (useful when testing from a phone with no devtools).
 *
 * Usage from other modules:
 *   PG.log.info('rules', 'Loaded rules', {count: 5})
 *   PG.log.warn('traffic', 'Poll returned no rows')
 *   PG.log.error('api', 'Request failed', {url, error})
 *   PG.log.net(method, url, status, durationMs, extra)
 */

(function () {
  "use strict";

  const MAX_LINES = 2000;
  const STORAGE_KEY = "proxygate_debug_open";

  const state = {
    lines: [],
    open: false,
    frozen: false,
    mirrorToServer: true,
  };

  function nowStamp() {
    const d = new Date();
    const pad = (n, w = 2) => String(n).padStart(w, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }

  function safeStringify(obj) {
    try {
      return JSON.stringify(obj, (_k, v) => (v instanceof Error ? { message: v.message, stack: v.stack } : v));
    } catch (e) {
      return String(obj);
    }
  }

  function render(entry) {
    const body = document.getElementById("debug-body");
    if (!body) return;
    const row = document.createElement("div");
    row.className = `dbg-line dbg-${entry.level}`;
    const ctx = entry.context !== undefined ? " " + safeStringify(entry.context) : "";
    row.innerHTML = `<span class="dbg-ts">${entry.ts}</span><span>[${entry.tag}] ${escapeHtml(entry.message)}${escapeHtml(ctx)}</span>`;
    body.appendChild(row);
    while (body.childElementCount > MAX_LINES) {
      body.removeChild(body.firstChild);
    }
    if (!state.frozen) body.scrollTop = body.scrollHeight;
    const countEl = document.getElementById("debug-count");
    if (countEl) countEl.textContent = `(${state.lines.length})`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function mirrorServer(entry) {
    if (!state.mirrorToServer) return;
    // fire-and-forget; never let logging itself throw or recurse
    try {
      fetch("/api/clientlog", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ level: entry.level, message: `[${entry.tag}] ${entry.message}`, context: entry.context }),
        keepalive: true,
      }).catch(() => { /* server log mirror is best-effort */ });
    } catch (e) { /* ignore */ }
  }

  function record(level, tag, message, context) {
    const entry = { level, tag, message, context, ts: nowStamp() };
    state.lines.push(entry);
    if (state.lines.length > MAX_LINES) state.lines.shift();

    const consoleFn = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
    consoleFn(`%c[PG:${tag}]`, "color:#0070cc;font-weight:bold", message, context !== undefined ? context : "");

    render(entry);
    if (level === "error" || level === "warn") mirrorServer(entry);
  }

  const log = {
    info: (tag, message, context) => record("info", tag, message, context),
    warn: (tag, message, context) => record("warn", tag, message, context),
    error: (tag, message, context) => record("error", tag, message, context),
    net: (method, url, status, durationMs, extra) =>
      record("net", "api", `${method} ${url} -> ${status} (${durationMs}ms)`, extra),
  };

  // ── Global error capture ────────────────────────────────────────────────────

  window.addEventListener("error", (e) => {
    log.error("window", e.message, { file: e.filename, line: e.lineno, col: e.colno, stack: e.error && e.error.stack });
  });

  window.addEventListener("unhandledrejection", (e) => {
    const reason = e.reason;
    log.error("promise", "Unhandled promise rejection", {
      message: reason && reason.message ? reason.message : String(reason),
      stack: reason && reason.stack,
    });
  });

  // ── Panel wiring ─────────────────────────────────────────────────────────────

  function setOpen(open) {
    state.open = open;
    const panel = document.getElementById("debug-panel");
    if (panel) panel.classList.toggle("hidden", !open);
    const indicator = document.getElementById("conn-indicator");
    if (indicator) indicator.classList.toggle("debug-open", open);
    try { localStorage.setItem(STORAGE_KEY, open ? "1" : "0"); } catch (e) { /* ignore */ }
  }

  function initPanel() {
    const toggle = document.getElementById("debug-dot");
    const close = document.getElementById("debug-close");
    const clear = document.getElementById("debug-clear");
    const freeze = document.getElementById("debug-freeze");

    if (toggle) toggle.addEventListener("click", () => setOpen(!state.open));
    if (close) close.addEventListener("click", () => setOpen(false));
    if (clear) clear.addEventListener("click", () => {
      state.lines = [];
      const body = document.getElementById("debug-body");
      if (body) body.innerHTML = "";
      const countEl = document.getElementById("debug-count");
      if (countEl) countEl.textContent = "(0)";
    });
    if (freeze) freeze.addEventListener("click", () => {
      state.frozen = !state.frozen;
      freeze.classList.toggle("active", state.frozen);
      freeze.textContent = state.frozen ? "▶ Unfreeze" : "❚❚ Freeze";
      const body = document.getElementById("debug-body");
      if (body) body.classList.toggle("frozen", state.frozen);
    });

    window.addEventListener("keydown", (e) => {
      if (e.ctrlKey && e.shiftKey && (e.key === "D" || e.key === "d")) {
        e.preventDefault();
        setOpen(!state.open);
      }
    });

    let wasOpen = false;
    try { wasOpen = localStorage.getItem(STORAGE_KEY) === "1"; } catch (e) { /* ignore */ }
    if (wasOpen) setOpen(true);

    log.info("debug", "Debug console initialized. Toggle with Ctrl+Shift+D or the status dot.");
  }

  document.addEventListener("DOMContentLoaded", initPanel);

  window.PG = window.PG || {};
  window.PG.log = log;
})();
