/**
 * traffic.js — Live traffic feed, scoped to the current server session.
 *
 * Rows logged before this `sudo proxygate` process started are never loaded:
 * the table begins empty on each restart rather than dumping the entire
 * lifetime history into the browser.
 *
 *   1. History — fetched once at startup, in full (see loadHistory). This
 *      deliberately replaced scroll-up pagination, which grew the content
 *      every time you neared the top and made the scrollbar impossible to
 *      drag to the actual top.
 *
 *   2. Live tail — poll /api/traffic/live?since=<last id> every 500ms and
 *      append new rows at the bottom, never touching scrollTop. The thumb
 *      shrinks as content grows but stays where the user put it; following
 *      the newest rows is opt-in via the Focus button.
 *
 * Search (`q`) is sent to the server and reloads the table from scratch —
 * no client-side filtering of rows already in the DOM, per the "search on
 * the host" requirement.
 */

(function () {
  "use strict";

  const TAG = "traffic";
  const LIVE_POLL_MS = 500;
  // Upper bound on the session history fetched at startup. Not a page size —
  // there is no paging; see loadHistory for why.
  const HISTORY_LIMIT = 20000;

  let sessionFloorId = 0;
  let liveSinceId = 0;       // cursor for the forward/live poll
  let oldestLoadedId = null; // oldest row currently rendered
  let newestLoadedId = null;
  let loadingHistory = false;
  let filter = "";
  let focus = false;
  let rowCount = 0;
  let liveFailures = 0;

  // Whether to render "QUIC (blocked)" rows at all — a pure display
  // preference (see settings.js), not a server-side filter: the rows are
  // still logged and still counted in /api/traffic stats either way, this
  // just controls whether the traffic table shows them.
  // Off by default: blocked-QUIC rows are high-volume noise for most
  // sessions, so they're opt-in from Settings. Must match settings.js's
  // getShowQuic() default, or the toggle would read "off" while rows
  // still rendered.
  let showQuic = false;
  try {
    showQuic = localStorage.getItem("proxygate_show_quic") === "1";
  } catch (e) { /* ignore, default stays false */ }

  function shouldRenderRow(row) {
    return showQuic || row.protocol !== "QUIC (blocked)";
  }

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

  // Only these protocols ever have a flow_details row to show (see
  // mitm_logger.py: only the request()/response() hooks — which fire for
  // plain HTTP and decrypted HTTPS, never raw-TLS passthrough — insert into
  // flow_details). Clicking any other row would always hit an empty state,
  // so skip the click affordance entirely for them.
  const DETAIL_CAPABLE_PROTOCOLS = new Set(["HTTP", "HTTPS"]);

  function buildRowEl(row) {
    const tr = document.createElement("tr");
    const proxy = row.proxy_used || "DIRECT";
    tr.className = rowClassForProxy(proxy, row.status_code);
    tr.dataset.id = String(row.id);

    const protocol = row.protocol || "—";
    tr.dataset.protocol = protocol;
    if (DETAIL_CAPABLE_PROTOCOLS.has(protocol)) {
      tr.classList.add("row-clickable");
      tr.title = "Click to view request/response detail";
      tr.addEventListener("click", () => window.PG.flowDetail.open(row.id, row));
    }

    const cells = [
      fmtTime(row.timestamp),
      row.source_ip || "—",
      row.dest_host || "—",
      row.dest_port || "",
      protocol,
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
    document.getElementById("traffic-bytes").textContent = `  |  Bytes: ${fmtBytes(stats.total_bytes)}`;
  }

  // ── Initial load / search reset ─────────────────────────────────────────────

  async function resetAndLoadNewest() {
    const tbody = document.getElementById("traffic-tbody");
    tbody.innerHTML = "";
    rowCount = 0;
    oldestLoadedId = null;
    newestLoadedId = null;

    try {
      const sessRes = await PG.api.get("/api/traffic/session");
      sessionFloorId = sessRes.session_floor_id;
      liveSinceId = Math.max(liveSinceId, sessRes.max_id);
      updateStats(sessRes.stats);
      PG.log.info(TAG, "Session info loaded", sessRes);
    } catch (e) {
      PG.log.error(TAG, "Failed to load session info", { error: e.message });
    }

    await loadHistory();
  }

  // ── History ─────────────────────────────────────────────────────────────────

  // The whole session's history in one request, rather than paging it in as
  // the user scrolls up.
  //
  // Paging was what made the scrollbar unusable: every time you neared the
  // top it inserted another 50 rows and corrected scrollTop to keep your
  // visual position, so the content got taller, the thumb jumped back down
  // and the top receded. Reaching the actual top took several drags. Loading
  // once means the scroll height is fixed except when live rows arrive, so
  // dragging up goes up and dragging down goes down.
  //
  // Session rows are bounded (the view starts empty on each restart) and a
  // few thousand rows of plain text costs a browser nothing — especially
  // with content-visibility skipping layout for off-screen rows.
  async function loadHistory() {
    if (loadingHistory) return;
    loadingHistory = true;
    try {
      const params = new URLSearchParams({ limit: String(HISTORY_LIMIT) });
      if (filter) params.set("q", filter);

      const res = await PG.api.get(`/api/traffic/history?${params.toString()}`);
      const rows = res.rows || [];

      PG.log.info(TAG, "History loaded", { count: rows.length, filter, has_more: res.has_more });

      if (rows.length) {
        // Server returns newest-first; append oldest-to-newest so the table
        // reads chronologically, oldest at top.
        const tbody = document.getElementById("traffic-tbody");
        const frag = document.createDocumentFragment();
        for (let i = rows.length - 1; i >= 0; i--) {
          if (shouldRenderRow(rows[i])) {
            frag.appendChild(buildRowEl(rows[i]));
            rowCount++;
          }
        }
        tbody.appendChild(frag);

        oldestLoadedId = rows[rows.length - 1].id;
        newestLoadedId = rows[0].id;
      }
    } catch (e) {
      PG.log.error(TAG, "Failed to load history", { error: e.message });
    } finally {
      loadingHistory = false;
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
      if (!shouldRenderRow(row)) continue;
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
      // Appending at the bottom only ever grows the content below the
      // viewport: scrollTop is untouched, so the thumb keeps its position
      // and simply gets shorter. Nothing is trimmed and nothing is
      // corrected, which is what makes dragging predictable.
      tbody.appendChild(frag);
      // Following the newest rows is opt-in via the Focus button. With it
      // off, appending must never move the scroll position — otherwise it
      // fights you every time you try to drag up through the history.
      if (focus) scrollToBottom();
    }
  }

  function scrollToBottom() {
    const el = document.querySelector("#panel-traffic .table-scroll");
    if (!el) return;
    el.scrollTo({ top: el.scrollHeight + 1e6, behavior: "instant" });
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
    updateStats({ total_count: 0, total_bytes: 0 });
  }

  function onFocusToggle() {
    focus = !focus;
    const btn = document.getElementById("traffic-focus-btn");
    btn.textContent = focus ? "Focus ●" : "Focus";
    btn.classList.toggle("active", focus);
    PG.log.info(TAG, "Focus toggled", { focus });
    if (focus) scrollToBottom();
  }

  function onExport() {
    const tbody = document.getElementById("traffic-tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const headers = ["Time","Source IP","Destination","Port","Type","Rule","Proxy","Status","Size"];
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

    resetAndLoadNewest();
    setTimeout(pollLive, LIVE_POLL_MS);
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  function setShowQuic(show) {
    showQuic = show;
    // Toggle already-rendered rows in place rather than re-fetching/
    // re-rendering the whole table — the rows are already in the DOM
    // (tagged with data-protocol in buildRowEl), this is just a visibility
    // flip, purely cosmetic and instant.
    const tbody = document.getElementById("traffic-tbody");
    for (const tr of tbody.querySelectorAll('tr[data-protocol="QUIC (blocked)"]')) {
      tr.hidden = !show;
    }
    PG.log.info(TAG, "Show-QUIC preference changed", { show });
  }

  window.PG.traffic = { pollLive, setShowQuic };
})();
