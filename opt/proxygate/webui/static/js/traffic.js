/**
 * traffic.js — Live traffic feed.
 *
 * The table shows the most recent HISTORY_LIMIT rows on load, whichever
 * process logged them, and tails new ones from there. Keeping the window
 * small is what stops a restart or a refresh from dragging the whole
 * lifetime history into the browser; the counters in the footer are still
 * scoped to the current run.
 *
 *   1. History — the most recent HISTORY_LIMIT rows, fetched once at startup
 *      (see loadHistory). This deliberately replaced scroll-up pagination,
 *      which grew the content every time you neared the top and made the
 *      scrollbar impossible to drag to the actual top. The window is capped
 *      so a refresh stays fast however long the gateway has been running.
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

  // How many of the most recent rows to render on load. NOT a page size:
  // there is no paging, and nothing older than this window is fetched.
  //
  // SESSION_FLOOR_ID is fixed when the server process starts, so the session
  // keeps growing for as long as proxygate runs. Without a cap, a refresh a
  // few hours in meant a multi-megabyte payload and tens of thousands of
  // <tr>s built before anything appeared on screen. Capping keeps load
  // instant no matter how long the gateway has been up.
  //
  // Older rows aren't lost: they stay in traffic.db and still come out in a
  // CSV export. They're just not rendered, because nobody scrolls back
  // through thousands of rows looking for one, they filter instead (which
  // queries the whole session server-side, not just this window).
  const HISTORY_LIMIT = 50;

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

    // Everything the search bar can match on, lowercased once at build time
    // so filtering is a plain string compare per row rather than re-reading
    // and re-casing the DOM on every keystroke.
    tr._pg = {
      ip:     (row.source_ip || "").toLowerCase(),
      sni:    (row.dest_host || "").toLowerCase(),
      port:   String(row.dest_port || ""),
      type:   protocol.toLowerCase(),
      rule:   (row.rule_matched || "").toLowerCase(),
      proxy:  proxy.toLowerCase(),
      status: row.status_code != null ? String(row.status_code) : "",
    };
    tr._pgAll = Object.values(tr._pg).join(" ");
    return tr;
  }

  // ── Search ───────────────────────────────────────────────────────────────────
  //
  // Filtering is client-side over the rows already loaded, so typing is
  // instant and doesn't refetch.
  //
  // Plain substring search over every column is always on: typing
  // "google.com" or "192.168.100.5" narrows the table.
  //
  // FIELD_SEARCH additionally enables `field==value` syntax:
  //
  //   type==tls           field equals value exactly
  //   sni~=google         field contains value
  //   ip==192.168.100.5   field equals value
  //
  // ...with multiple terms AND-ed together, and these field names:
  // ip/src/source, sni/host/dest, port, type/protocol/proto, rule, proxy,
  // status/code.
  //
  // Off by default: the syntax works but the interaction needs more thought
  // before users see it. Flip this to true to turn it back on; nothing else
  // needs changing, and the placeholder text follows this flag automatically
  // (see initFilterPlaceholder).
  const FIELD_SEARCH = false;

  const FIELD_ALIASES = {
    ip: "ip", source: "ip", src: "ip",
    sni: "sni", host: "sni", dest: "sni", destination: "sni",
    port: "port",
    type: "type", protocol: "type", proto: "type",
    rule: "rule",
    proxy: "proxy",
    status: "status", code: "status",
  };

  // "type==tls", "sni~=google", or bare text. The operator is captured so
  // == can mean exact and ~= contains.
  const TERM_RE = /^([a-z]+)\s*(==|~=|=)\s*(.*)$/i;

  function parseQuery(text) {
    const trimmed = text.trim();
    if (!trimmed) return [];

    // With field search off, the query is one literal substring. Not split
    // on spaces: "Request Detail" should match that phrase, and a stray
    // "==" is then just characters to look for rather than syntax.
    if (!FIELD_SEARCH) {
      return [{ field: null, op: "~=", value: trimmed.toLowerCase() }];
    }

    return trimmed
      .split(/\s+/)
      .filter(Boolean)
      .map((raw) => {
        const m = raw.match(TERM_RE);
        if (!m) return { field: null, op: "~=", value: raw.toLowerCase() };
        const field = FIELD_ALIASES[m[1].toLowerCase()];
        if (!field) return { field: null, op: "~=", value: raw.toLowerCase() };
        // "==" is exact; "=" and "~=" both mean contains, since a bare "="
        // reads as "is" to most people but they rarely want it strict.
        return { field, op: m[2] === "==" ? "==" : "~=", value: m[3].toLowerCase() };
      });
  }

  function rowMatches(tr, terms) {
    for (const t of terms) {
      const hay = t.field ? (tr._pg[t.field] || "") : (tr._pgAll || "");
      const ok = t.op === "==" ? hay === t.value : hay.includes(t.value);
      if (!ok) return false;
    }
    return true;
  }

  // Keeps the input's hint in step with FIELD_SEARCH, so flipping that one
  // flag is genuinely all it takes: the box never advertises syntax that
  // isn't active, and never hides it when it is.
  function initFilterPlaceholder() {
    const el = document.getElementById("traffic-filter");
    if (!el) return;
    if (FIELD_SEARCH) {
      el.placeholder = "Filter… e.g. google.com, type==tls, ip==192.168.100.5";
      el.title = "Plain text matches any column.\n"
               + "field==value is exact, field~=value contains.\n"
               + "Fields: ip, sni (host), port, type, rule, proxy, status.\n"
               + "Several terms are combined with AND.";
    } else {
      el.placeholder = "Filter by host or IP…";
      el.title = "Matches any column in the loaded rows.";
    }
  }

  function applyFilter() {
    const tbody = document.getElementById("traffic-tbody");
    const terms = filter ? parseQuery(filter) : [];
    let shown = 0;
    for (const tr of tbody.children) {
      const visible = !terms.length || rowMatches(tr, terms);
      // A class rather than style.display so it can't fight the stylesheet,
      // and so content-visibility keeps skipping the hidden ones.
      tr.classList.toggle("row-filtered-out", !visible);
      if (visible) shown++;
    }
    return shown;
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
    // Re-apply any active search to the freshly loaded rows: this runs when
    // the QUIC toggle changes, and the search box keeps its text.
    if (filter) applyFilter();
  }

  // ── History ─────────────────────────────────────────────────────────────────

  // The most recent HISTORY_LIMIT rows in one request, rather than paging
  // more in as the user scrolls up.
  //
  // Paging was what made the scrollbar unusable: every time you neared the
  // top it inserted another 50 rows and corrected scrollTop to keep your
  // visual position, so the content got taller, the thumb jumped back down
  // and the top receded. Reaching the actual top took several drags. Loading
  // once means the scroll height only ever grows at the bottom, as live rows
  // arrive, so dragging up goes up and dragging down goes down.
  //
  // The window is capped rather than unbounded because the session grows for
  // as long as the server process runs (see HISTORY_LIMIT) — fetching all of
  // it made a mid-session refresh slow to the point of feeling broken.
  async function loadHistory() {
    if (loadingHistory) return;
    loadingHistory = true;
    try {
      const params = new URLSearchParams({ limit: String(HISTORY_LIMIT) });
      // Let the server drop blocked-QUIC rows when we're not showing them,
      // so HISTORY_LIMIT counts rows that actually get rendered. Without
      // this the window filled up with rows shouldRenderRow() then threw
      // away — on a QUIC-heavy session, 200 fetched rows could leave only a
      // handful on screen.
      if (!showQuic) params.set("quic", "0");

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
    // Parsed once per batch rather than per row.
    const terms = filter ? parseQuery(filter) : [];
    let matched = 0;
    for (const row of rows) {
      newestLoadedId = row.id;
      if (!shouldRenderRow(row)) continue;
      const tr = buildRowEl(row);
      // A live row that doesn't match the active search is still added,
      // just hidden — so clearing the search reveals it instead of leaving
      // a gap in the timeline that only a refresh would fill.
      if (terms.length && !rowMatches(tr, terms)) {
        tr.classList.add("row-filtered-out");
      } else {
        matched++;
      }
      frag.appendChild(tr);
      rowCount++;
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
    // Short debounce: this is a local show/hide pass over rows already in
    // the DOM, not a request, so it can be near-instant. The delay only
    // exists to avoid re-running mid-word on fast typing.
    filterDebounceTimer = setTimeout(() => {
      filter = value;
      const shown = applyFilter();
      PG.log.info(TAG, "Search applied (client-side)", { filter, shown });
    }, 80);
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
    initFilterPlaceholder();
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
    // Must refetch, not just unhide: the history request now asks the server
    // to leave blocked-QUIC rows out entirely when the preference is off
    // (so HISTORY_LIMIT counts visible rows), which means turning it back on
    // has no hidden rows to reveal — they were never sent.
    PG.log.info(TAG, "Show-QUIC preference changed — reloading history", { show });
    resetAndLoadNewest();
  }

  window.PG.traffic = { pollLive, setShowQuic };
})();
