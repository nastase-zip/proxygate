/**
 * traffic.js — Live traffic feed, session-scoped and chunk-paginated.
 *
 * Two independent flows, both scoped to the current server session
 * (rows logged before this `sudo proxygate` process started are never
 * loaded automatically — that was the whole point of the rework: don't
 * dump the entire lifetime history into the browser on every startup):
 *
 *   1. Live tail — poll /api/traffic/live?since=<last id> every 500ms,
 *      append new rows at the bottom. Small, bounded, cheap.
 *
 *   2. History — the table's initial content and anything above it. Loaded
 *      in chunks of CHUNK_SIZE via /api/traffic/history?before_id=<cursor>.
 *      The browser never holds more than what's been explicitly paged in:
 *      scrolling near the top of the table asks the server for the next
 *      older chunk and prepends it, preserving scroll offset so the view
 *      doesn't jump. Search (`q`) is sent to the server and re-runs the
 *      whole paging sequence from scratch — no client-side filtering of
 *      rows already in the DOM, per the "search on the host" requirement.
 */

(function () {
  "use strict";

  const TAG = "traffic";
  const CHUNK_SIZE = 50;
  const LIVE_POLL_MS = 500;
  const SCROLL_LOAD_THRESHOLD_PX = 80; // load next chunk when this close to the top

  let sessionFloorId = 0;
  let liveSinceId = 0;       // cursor for the forward/live poll
  let oldestLoadedId = null; // cursor for the backward/history page (null = none loaded yet)
  let newestLoadedId = null;
  let hasMoreHistory = true;
  let loadingHistory = false;
  let filter = "";
  let focus = false;
  let rowCount = 0;
  let liveFailures = 0;

  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
  }

  function fmtTime(ts) {
    return ts && ts.length >= 19 ? ts.slice(11) : ts || "";
  }

  function rowClassForProxy(proxyUsed, status) {
    if (status != null && (status === 0 || status >= 500)) return "row-error";
    const p = (proxyUsed || "").toLowerCase();
    if (p === "direct") return "row-direct";
    if (p.includes("express")) return "row-expressvpn";
    return "row-other";
  }

  function buildRowEl(row) {
    const tr = document.createElement("tr");
    const proxy = row.proxy_used || "DIRECT";
    tr.className = rowClassForProxy(proxy, row.status_code);
    tr.dataset.id = String(row.id);

    const cells = [
      fmtTime(row.timestamp),
      row.source_ip || "—",
      row.dest_host || "—",
      row.dest_port || "",
      row.rule_matched || "—",
      proxy,
      row.status_code != null ? String(row.status_code) : "—",
      fmtBytes(row.bytes_transferred || 0),
    ];
    for (const c of cells) {
      const td = document.createElement("td");
      td.textContent = c;
      tr.appendChild(td);
    }
    return tr;
  }

  function updateStats(stats) {
    if (!stats) return;
    document.getElementById("traffic-count").textContent = `Connections: ${stats.total_count}`;
    document.getElementById("traffic-bytes").textContent = ` | Bytes: ${fmtBytes(stats.total_bytes)}`;
  }

  // ── Initial load / search reset ─────────────────────────────────────────────

  async function resetAndLoadNewest() {
    const tbody = document.getElementById("traffic-tbody");
    tbody.innerHTML = "";
    rowCount = 0;
    oldestLoadedId = null;
    newestLoadedId = null;
    hasMoreHistory = true;

    try {
      const sessRes = await PG.api.get("/api/traffic/session");
      sessionFloorId = sessRes.session_floor_id;
      liveSinceId = Math.max(liveSinceId, sessRes.max_id);
      updateStats(sessRes.stats);
      PG.log.info(TAG, "Session info loaded", sessRes);
    } catch (e) {
      PG.log.error(TAG, "Failed to load session info", { error: e.message });
    }

    await loadOlderChunk();
  }

  // ── Backward paging (scroll-up) ─────────────────────────────────────────────

  async function loadOlderChunk() {
    if (loadingHistory || !hasMoreHistory) return;
    loadingHistory = true;
    const wrap = document.querySelector("#panel-traffic .table-wrap");
    const prevScrollHeight = wrap.scrollHeight;
    const prevScrollTop = wrap.scrollTop;

    try {
      const params = new URLSearchParams({ limit: String(CHUNK_SIZE) });
      if (oldestLoadedId != null) params.set("before_id", String(oldestLoadedId));
      if (filter) params.set("q", filter);

      const res = await PG.api.get(`/api/traffic/history?${params.toString()}`);
      const rows = res.rows || [];
      hasMoreHistory = res.has_more;

      PG.log.info(TAG, "History chunk loaded", {
        count: rows.length, before_id: oldestLoadedId, filter, has_more: hasMoreHistory,
      });

      if (rows.length) {
        // Server returns newest-first; insert oldest-to-newest at the top
        // so the table stays chronological (oldest at top, newest at bottom).
        const tbody = document.getElementById("traffic-tbody");
        const frag = document.createDocumentFragment();
        for (let i = rows.length - 1; i >= 0; i--) {
          frag.appendChild(buildRowEl(rows[i]));
          rowCount++;
        }
        tbody.insertBefore(frag, tbody.firstChild);

        oldestLoadedId = rows[rows.length - 1].id;
        if (newestLoadedId === null) newestLoadedId = rows[0].id;

        // Preserve visual scroll position: the content we just prepended
        // pushed everything down by (newScrollHeight - prevScrollHeight).
        // Without this the browser keeps scrollTop fixed and the view
        // jumps to show the new rows instead of staying where the user was.
        requestAnimationFrame(() => {
          const delta = wrap.scrollHeight - prevScrollHeight;
          wrap.scrollTop = prevScrollTop + delta;
        });
      }
    } catch (e) {
      PG.log.error(TAG, "Failed to load history chunk", { error: e.message, before_id: oldestLoadedId });
    } finally {
      loadingHistory = false;
    }
  }

  function onScroll(e) {
    if (e.target.scrollTop <= SCROLL_LOAD_THRESHOLD_PX) {
      loadOlderChunk();
    }
  }

  // ── Live tail (forward) ──────────────────────────────────────────────────────

  async function pollLive() {
    try {
      const res = await PG.api.get(`/api/traffic/live?since=${liveSinceId}&limit=200`);
      if (res.rows && res.rows.length) {
        liveSinceId = res.rows[res.rows.length - 1].id;
        appendLiveRows(res.rows);
      }
      updateStats(res.stats);
      if (liveFailures > 0) {
        PG.log.info(TAG, "Live traffic poll recovered after failures", { failures: liveFailures });
      }
      liveFailures = 0;
    } catch (e) {
      liveFailures++;
      if (liveFailures <= 3 || liveFailures % 20 === 0) {
        PG.log.error(TAG, "Live traffic poll failed", { error: e.message, consecutiveFailures: liveFailures });
      }
    } finally {
      // Back off while the connection is down instead of hammering every
      // 500ms — a flaky client WiFi link (device roaming/reassociating)
      // otherwise floods the log and the network with retries that can't
      // succeed anyway. Caps at 5s, same cadence as the status poll.
      const delay = liveFailures === 0 ? LIVE_POLL_MS : Math.min(LIVE_POLL_MS * 2 ** Math.min(liveFailures, 4), 5000);
      setTimeout(pollLive, delay);
    }
  }

  function appendLiveRows(rows) {
    const tbody = document.getElementById("traffic-tbody");
    const frag = document.createDocumentFragment();
    let matched = 0;
    for (const row of rows) {
      newestLoadedId = row.id;
      if (filter) {
        const f = filter.toLowerCase();
        const hit = (row.dest_host || "").toLowerCase().includes(f) || (row.source_ip || "").toLowerCase().includes(f);
        if (!hit) continue;
      }
      frag.appendChild(buildRowEl(row));
      rowCount++;
      matched++;
    }
    if (matched) {
      tbody.appendChild(frag);
      if (focus) {
        const wrap = document.querySelector("#panel-traffic .table-wrap");
        wrap.scrollTop = wrap.scrollHeight;
      }
    }
  }

  // ── UI actions ───────────────────────────────────────────────────────────────

  let filterDebounceTimer = null;

  function onFilterChange(e) {
    const value = e.target.value.trim();
    clearTimeout(filterDebounceTimer);
    filterDebounceTimer = setTimeout(() => {
      filter = value;
      PG.log.info(TAG, "Search changed — re-querying server", { filter });
      resetAndLoadNewest();
    }, 250);
  }

  function onClear() {
    PG.log.info(TAG, "Traffic view cleared (local view only; DB rows untouched)");
    const tbody = document.getElementById("traffic-tbody");
    tbody.innerHTML = "";
    rowCount = 0;
    oldestLoadedId = null;
    newestLoadedId = liveSinceId;
    hasMoreHistory = false; // user explicitly cleared; don't silently repopulate from scroll
    updateStats({ total_count: 0, total_bytes: 0 });
  }

  function onFocusToggle() {
    focus = !focus;
    const btn = document.getElementById("traffic-focus-btn");
    btn.textContent = focus ? "Focus ●" : "Focus";
    btn.classList.toggle("active", focus);
    PG.log.info(TAG, "Focus toggled", { focus });
    if (focus) {
      const wrap = document.querySelector("#panel-traffic .table-wrap");
      wrap.scrollTop = wrap.scrollHeight;
    }
  }

  function onExport() {
    const tbody = document.getElementById("traffic-tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const headers = ["Time","Source IP","Destination","Port","Rule","Proxy","Status","Size"];
    const lines = [headers.join(",")];
    for (const tr of rows) {
      const cells = Array.from(tr.querySelectorAll("td")).map((td) => `"${td.textContent.replace(/"/g, '""')}"`);
      lines.push(cells.join(","));
    }
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "proxygate-traffic.csv";
    a.click();
    URL.revokeObjectURL(a.href);
    PG.log.info(TAG, "Traffic exported", { rows: rows.length });
  }

  function init() {
    document.getElementById("traffic-filter").addEventListener("input", onFilterChange);
    document.getElementById("traffic-clear-btn").addEventListener("click", onClear);
    document.getElementById("traffic-export-btn").addEventListener("click", onExport);
    document.getElementById("traffic-focus-btn").addEventListener("click", onFocusToggle);
    document.querySelector("#panel-traffic .table-wrap").addEventListener("scroll", onScroll);

    resetAndLoadNewest();
    setTimeout(pollLive, LIVE_POLL_MS);
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.traffic = { pollLive, loadOlderChunk };
})();
