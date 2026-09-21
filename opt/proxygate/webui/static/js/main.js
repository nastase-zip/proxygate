/**
 * main.js — App bootstrap: modal helpers, connection indicator, dark mode, column resizing.
 */

(function () {
  "use strict";

  const TAG = "main";
  const DARK_KEY = "proxygate_dark";

  function showModal(id) {
    document.getElementById("modal-backdrop").classList.remove("hidden");
    const modal = document.getElementById(id);
    modal.classList.remove("hidden");
    PG.log.info(TAG, "Modal opened", { id });
  }

  function hideModal(id) {
    document.getElementById("modal-backdrop").classList.add("hidden");
    document.getElementById(id).classList.add("hidden");
    PG.log.info(TAG, "Modal closed", { id });
  }

  function setConnIndicator(ok) {
    const el = document.getElementById("conn-indicator");
    const text = document.getElementById("conn-indicator-text");
    if (!el) return;
    el.classList.remove("conn-ok", "conn-error", "conn-unknown");
    el.classList.add(ok ? "conn-ok" : "conn-error");
    if (text) text.textContent = ok ? "server connected" : "server unreachable";
    el.title = "";
  }

  // ── Dark mode ────────────────────────────────────────────────────────────────

  function setDark(dark) {
    document.body.classList.toggle("dark", dark);
    const btn = document.getElementById("darkmode-toggle");
    if (btn) {
      btn.innerHTML = dark ? '<i class="fa-solid fa-moon"></i>' : '<i class="fa-solid fa-sun"></i>';
      btn.title = dark ? "Switch to light mode" : "Switch to dark mode";
    }
    try { localStorage.setItem(DARK_KEY, dark ? "1" : "0"); } catch (e) { /* ignore */ }
  }

  function initDarkMode() {
    const stored = (() => { try { return localStorage.getItem(DARK_KEY); } catch(e) { return null; } })();
    const dark = stored === null ? true : stored === "1";
    setDark(dark);
    const btn = document.getElementById("darkmode-toggle");
    if (btn) btn.addEventListener("click", () => setDark(!document.body.classList.contains("dark")));
  }

  // ── Column resizing ──────────────────────────────────────────────────────────
  //
  // Widths are per-browser only (localStorage) — deliberately never sent to
  // the backend. This is a personal display preference, not shared state:
  // nobody wants their column layout silently overwritten because someone
  // else on the same ProxyGate instance dragged a divider.

  const COL_WIDTHS_KEY = "proxygate_traffic_col_widths";
  const MIN_W = 40;

  // Whether the column dividers run the full height of the panel or just
  // across the header. Per-browser like the widths — a display preference,
  // not shared state. Toggled from Settings.
  const FULL_LINES_KEY = "proxygate_traffic_full_lines";
  let fullHeightLines = false;
  try {
    fullHeightLines = localStorage.getItem(FULL_LINES_KEY) === "1";
  } catch (e) { /* private mode — default stays false */ }

  // Sensible defaults so a first-time (or localStorage-cleared) view already
  // favors Destination — the column people actually read — over the
  // low-signal ones (Port/Type/Status/Size), instead of splitting evenly.
  //
  // Expressed as fractions of the panel's width (sums to 1), not fixed
  // pixels: a table this wide (~1090px worth of fixed columns) reliably
  // overflowed anything but the widest windows, forcing a permanent
  // horizontal scrollbar on first load. Percentages mean the default
  // layout always exactly fills whatever width the panel actually has, on
  // any screen — a scrollbar only appears once the user deliberately drags
  // a column wider than that. Once a column IS dragged, its saved width
  // (see loadColWidths) is a fixed px value from then on — only the
  // never-touched defaults need to scale with the panel.
  const DEFAULT_COL_FRACTIONS = {
    time: 0.08,
    source_ip: 0.12,
    destination: 0.42,
    port: 0.055,
    type: 0.065,
    rule: 0.08,
    proxy: 0.065,
    status: 0.055,
    size: 0.06,
  };

  function loadColWidths() {
    try {
      const raw = localStorage.getItem(COL_WIDTHS_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch (e) {
      return {};
    }
  }

  function saveColWidths(widths) {
    try {
      localStorage.setItem(COL_WIDTHS_KEY, JSON.stringify(widths));
    } catch (e) { /* private mode / quota — just skip persisting */ }
  }

  function initColumnResizing() {
    const wrap = document.querySelector(".table-wrap");
    const scroller = document.querySelector(".table-scroll");
    const headEl = document.querySelector(".table-head");
    const headTable = document.getElementById("traffic-head-table");
    const table = document.getElementById("traffic-table");
    const linesEl = document.getElementById("traffic-col-lines");
    if (!wrap || !scroller || !headEl || !headTable || !table || !linesEl) return;

    // The header row lives in its own table (headTable) above the scrolling
    // area; the body table only has a <colgroup>. Column widths are applied
    // to both in lockstep so they stay aligned.
    const ths = Array.from(headTable.querySelectorAll("th.resizable"));
    const cols = Array.from(table.querySelectorAll("col"));
    let lastFitWidth = null; // panelW this table was last fitted to, so fitColumns can skip redundant work

    // Whenever the available width changes (window resize, browser zoom, a
    // side panel toggled) every column has to be rescaled to match, or they
    // keep absolute widths from a differently-sized panel and either overflow
    // it or fall short — and when they don't add up, table-layout: fixed
    // silently redistributes the difference across ALL columns, so dragging
    // one visibly moves the others. Runs at init and on every resize, always
    // rescaling from the CURRENT on-screen widths so a user's drag layout is
    // preserved in proportion.
    //
    // Everything is fractional (getBoundingClientRect, no rounding of
    // results): clientWidth/offsetWidth round to whole pixels, and at
    // fractional zoom that rounding is what pushed columns a pixel past the
    // panel and tripped a scrollbar for content that actually fit.
    function panelInnerWidth() {
      // The scroller's content box — the space actually available to the
      // table, i.e. excluding the scrollbar. It's stable because the
      // scroller is overflow-y: scroll, not auto: the scrollbar is always
      // present, so this width never changes as rows come and go. (That
      // stability is the whole point; every earlier attempt to reclaim the
      // scrollbar's space made this value move, and the column fitting
      // chased it.)
      // Less 0.5px because clientWidth rounds up and can overshoot the real
      // box at fractional zoom.
      return Math.max(0, scroller.clientWidth - 0.5);
    }

    function fitColumns() {
      const panelW = panelInnerWidth();
      // Epsilon rather than equality: panelW is fractional now, and a
      // sub-pixel jitter shouldn't trigger a full re-fit on every observer tick.
      if (!panelW || (lastFitWidth !== null && Math.abs(panelW - lastFitWidth) < 0.5)) return;
      lastFitWidth = panelW;

      const saved = loadColWidths();
      const rawWidths = ths.map((th) => {
        const col = th.dataset.col;
        // Prefer this table's own current rendered width (already correct
        // relative proportions) once it has one; only fall back to
        // saved/default on the very first fit, before anything's rendered.
        return th.style.width ? th.getBoundingClientRect().width
          : saved[col] || (DEFAULT_COL_FRACTIONS[col] && DEFAULT_COL_FRACTIONS[col] * panelW)
          || th.getBoundingClientRect().width;
      });

      const rawSum = rawWidths.reduce((a, b) => a + b, 0);
      const scale = rawSum > 0 ? panelW / rawSum : 1;
      const widths = rawWidths.map((w) => Math.max(MIN_W, w * scale));
      // MIN_W clamping can push the sum over panelW; rescale the columns
      // that aren't clamped so the total lands exactly on panelW.
      const total = widths.reduce((a, b) => a + b, 0);
      if (total > panelW) {
        const slackTotal = widths.reduce((a, w) => a + Math.max(0, w - MIN_W), 0);
        if (slackTotal > 0) {
          const shrink = (total - panelW) / slackTotal;
          for (let i = 0; i < widths.length; i++) {
            widths[i] -= Math.max(0, widths[i] - MIN_W) * shrink;
          }
        }
      }

      // Pin both tables to exactly the width the columns sum to. Any CSS
      // width that disagrees with that sum gets redistributed across every
      // column by table-layout: fixed, which is what used to make resizing
      // one column visibly move all the others.
      applyWidths(widths, panelW);
    }

    // Header cells and body <col>s get the same widths, so the two tables
    // stay aligned. The header table is inset by the scrollbar's width (the
    // scroller has one, the header doesn't) or the columns would drift
    // apart by exactly that much.
    function applyWidths(widths, panelW) {
      // The scroller reserves space for its scrollbar; the header bar has no
      // scrollbar of its own, so pad its right edge by the same amount or
      // the two tables would be offset from each other by exactly that much.
      const sbW = scroller.offsetWidth - scroller.clientWidth;
      headEl.style.paddingRight = sbW + "px";
      headTable.style.width = panelW + "px";
      table.style.width = panelW + "px";
      for (let i = 0; i < widths.length; i++) {
        const w = widths[i] + "px";
        ths[i].style.width = w;
        if (cols[i]) cols[i].style.width = w;
      }
    }

    fitColumns();

    // One overlay line per column boundary (all but the last column), drawn
    // in #traffic-col-lines rather than as table/cell borders — a <table>
    // only ever sizes to its content, so cell borders stop wherever the
    // last row ends and can't reach the bottom of the panel when there are
    // only a few rows.
    //
    // The drag handle is a child of the LINE, not of the th it resizes.
    // thead th is position: sticky with a z-index, which makes every th its
    // own stacking context — a handle inside th N can't paint or receive
    // clicks above th N+1 (a later sibling at the same z-index), so the
    // half of the grab zone hanging past the column edge was dead. Hosting
    // it in the lines overlay (z-index 2, above the whole header) makes the
    // full width of the zone live, and it's already positioned exactly on
    // the boundary so the handle just centers on its parent.
    const lineEls = ths.slice(0, -1).map(() => {
      const line = document.createElement("div");
      line.className = "traffic-col-line";
      const handle = document.createElement("div");
      handle.className = "col-resize-handle";
      line.appendChild(handle);
      linesEl.appendChild(line);
      return line;
    });

    function repositionLines() {
      // ALL reads first, then all writes. Interleaving them forces the
      // browser to re-layout between each pair, and with a large table that
      // dominates the cost of a drag — every write invalidates the layout
      // the next read then has to rebuild.
      //
      // getBoundingClientRect (fractional) rather than offsetWidth/Height
      // (whole px): at fractional zoom the rounded values run up to a px
      // over the real box, and sizing the overlay from them makes it stick
      // out past the table, which the scroller counts as real overflow.
      const linesLeft = linesEl.getBoundingClientRect().left;
      const tableW = table.getBoundingClientRect().width;
      // Header-height by default; full panel height when the user turns on
      // full-height dividers in Settings. Running them through the rows
      // makes the table read as a grid, which is why it's opt-in.
      const headerH = ths[0] ? ths[0].getBoundingClientRect().height : 0;
      const lineH = fullHeightLines
        ? headerH + scroller.getBoundingClientRect().height
        : headerH;
      const rights = ths.slice(0, -1).map((th) => th.getBoundingClientRect().right);

      linesEl.style.width = tableW + "px";
      // Drag handles are sized from this rather than from their parent line,
      // which may run the full panel height — see .col-resize-handle.
      linesEl.style.setProperty("--header-h", headerH + "px");
      rights.forEach((right, i) => {
        lineEls[i].style.left = (right - linesLeft) + "px";
        lineEls[i].style.height = lineH + "px";
      });
    }

    function onPanelResize() {
      fitColumns();
      repositionLines();
    }

    // Settings toggles this; see FULL_LINES_KEY.
    window.PG.setFullHeightLines = (on) => {
      fullHeightLines = !!on;
      try {
        localStorage.setItem(FULL_LINES_KEY, fullHeightLines ? "1" : "0");
      } catch (e) { /* private mode — the toggle still applies for this session */ }
      repositionLines();
    };
    window.PG.getFullHeightLines = () => fullHeightLines;

    repositionLines();
    // Only the panel's own box matters: a resize there (side panel toggled,
    // window resized, zoom changed) means the columns need re-fitting and
    // the dividers repositioning.
    //
    // The table is deliberately NOT observed. It changes size on every
    // appended batch of rows, but only its HEIGHT does — and the dividers
    // span just the header row, so nothing about them depends on it. That
    // observer was firing a layout pass per batch on a live feed for no
    // visible effect.
    new ResizeObserver(onPanelResize).observe(wrap);
    window.addEventListener("resize", onPanelResize);

    // Every column except the last gets a handle on its right edge. Dragging
    // it only trades width between THIS column and its immediate right
    // neighbor (last column absorbs nothing, first column absorbs nothing
    // from its left) — total table width never changes, so the table never
    // grows/shrinks or makes other columns jump around.
    // Only one divider can be dragged at a time. Without this, moving the
    // cursor across other handles mid-drag fires their mouseenter (lighting
    // up lines you aren't dragging) and a second mousedown could start a
    // competing drag on top of the first.
    let dragging = false;

    ths.forEach((th, i) => {
      if (i === ths.length - 1) return; // last column has no right neighbor to trade with
      const next = ths[i + 1];
      const line = lineEls[i];
      const handle = line.querySelector(".col-resize-handle");
      let startX, startW, startNextW;

      handle.addEventListener("mouseenter", () => {
        if (!dragging) line.classList.add("active");
      });
      handle.addEventListener("mouseleave", () => {
        if (!dragging) line.classList.remove("active");
      });

      handle.addEventListener("mousedown", (e) => {
        if (dragging || e.button !== 0) return;
        e.preventDefault();
        dragging = true;
        startX = e.clientX;
        // Fractional widths, same reason as fitColumns: rounding here would
        // make the pair's sum drift off the panel width on every drag.
        startW = th.getBoundingClientRect().width;
        startNextW = next.getBoundingClientRect().width;
        line.classList.add("active");
        // Belt and braces alongside the `dragging` flag: with the handles
        // inert, the browser can't deliver hover/press events to them at
        // all while a drag is in flight.
        linesEl.classList.add("dragging");
        document.body.classList.add("col-resizing");

        // mousemove can fire several times per frame, and each update writes
        // two column widths and then reads every th's rect to reposition the
        // dividers — a forced synchronous layout of the whole table. With a
        // lot of rows that's the single most expensive thing in the app, so
        // coalesce to at most one update per animation frame.
        let pendingX = null;
        let rafId = 0;

        function applyMove() {
          rafId = 0;
          const dx = pendingX - startX;
          // Clamp so neither side can be dragged below MIN_W.
          const clampedDx = Math.max(MIN_W - startW, Math.min(startNextW - MIN_W, dx));
          const w = (startW + clampedDx) + "px";
          const nextW = (startNextW - clampedDx) + "px";
          // Header cell and matching body <col> together, or the two tables
          // drift out of alignment as you drag.
          th.style.width = w;
          next.style.width = nextW;
          if (cols[i]) cols[i].style.width = w;
          if (cols[i + 1]) cols[i + 1].style.width = nextW;
          repositionLines();
        }

        function onMove(e) {
          pendingX = e.clientX;
          if (!rafId) rafId = requestAnimationFrame(applyMove);
        }
        function onUp() {
          dragging = false;
          // Flush any frame queued by the last mousemove, then stop it from
          // firing after the drag has ended.
          if (rafId) {
            cancelAnimationFrame(rafId);
            applyMove();
          }
          line.classList.remove("active");
          linesEl.classList.remove("dragging");
          document.body.classList.remove("col-resizing");
          document.removeEventListener("mousemove", onMove);
          document.removeEventListener("mouseup", onUp);

          const widths = loadColWidths();
          widths[th.dataset.col] = th.getBoundingClientRect().width;
          widths[next.dataset.col] = next.getBoundingClientRect().width;
          saveColWidths(widths);
        }
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      });
    });
  }

  // ── Left tabs ────────────────────────────────────────────────────────────────

  // ── Left panel width ─────────────────────────────────────────────────────────
  //
  // Per-browser like the column widths and the flow pane's height: a display
  // preference, never sent to the backend.

  const LEFT_W_KEY = "proxygate_left_panel_w";
  const LEFT_MIN_W = 220;

  function initLeftPanelResize() {
    const panel = document.getElementById("panel-left");
    const grip = document.getElementById("panel-left-resize");
    if (!panel || !grip) return;

    try {
      const saved = parseFloat(localStorage.getItem(LEFT_W_KEY));
      if (saved >= LEFT_MIN_W) panel.style.width = saved + "px";
    } catch (e) { /* private mode — the CSS default stands */ }

    grip.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const startX = e.clientX;
      const startW = panel.getBoundingClientRect().width;
      // Leave the traffic panel a usable width whatever happens.
      const maxW = document.getElementById("panels").getBoundingClientRect().width - 360;
      document.body.classList.add("col-panel-resizing");

      function onMove(ev) {
        const w = Math.min(maxW, Math.max(LEFT_MIN_W, startW + (ev.clientX - startX)));
        panel.style.width = w + "px";
      }
      function onUp() {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        document.body.classList.remove("col-panel-resizing");
        try {
          localStorage.setItem(LEFT_W_KEY, panel.getBoundingClientRect().width);
        } catch (err) { /* private mode — applies for this session only */ }
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  }

  function initLeftTabs() {
    const panel = document.getElementById("panel-left");
    const ruleAddBtn   = document.getElementById("rule-add-btn");
    const proxyAddBtn  = document.getElementById("proxy-add-btn");
    const deviceAddBtn = document.getElementById("device-add-btn");

    function switchToRules() {
      panel.classList.remove("show-proxies", "show-devices");
      document.getElementById("tab-rules").classList.add("active");
      document.getElementById("tab-proxies").classList.remove("active");
      document.getElementById("tab-devices").classList.remove("active");
      ruleAddBtn.classList.remove("hidden");
      proxyAddBtn.classList.add("hidden");
      deviceAddBtn.classList.add("hidden");
    }
    function switchToProxies() {
      panel.classList.remove("show-devices");
      panel.classList.add("show-proxies");
      document.getElementById("tab-proxies").classList.add("active");
      document.getElementById("tab-rules").classList.remove("active");
      document.getElementById("tab-devices").classList.remove("active");
      proxyAddBtn.classList.remove("hidden");
      ruleAddBtn.classList.add("hidden");
      deviceAddBtn.classList.add("hidden");
    }
    function switchToDevices() {
      panel.classList.remove("show-proxies");
      panel.classList.add("show-devices");
      document.getElementById("tab-devices").classList.add("active");
      document.getElementById("tab-rules").classList.remove("active");
      document.getElementById("tab-proxies").classList.remove("active");
      deviceAddBtn.classList.remove("hidden");
      ruleAddBtn.classList.add("hidden");
      proxyAddBtn.classList.add("hidden");
      window.PG.devices && window.PG.devices.refresh();
    }

    document.getElementById("tab-rules").addEventListener("click", switchToRules);
    document.getElementById("tab-proxies").addEventListener("click", switchToProxies);
    document.getElementById("tab-devices").addEventListener("click", switchToDevices);

    switchToRules();
  }

  // ── Init ─────────────────────────────────────────────────────────────────────

  /* ── custom checkbox ───────────────────────────────────────────────────
     .checkbox-row has pointer-events: none so clicking the label text does
     nothing (only the box toggles). That also disables the browser's own
     label→input forwarding, so the box drives the input from here. */
  function initCheckboxes() {
    document.querySelectorAll(".checkbox-row .pg-check-box").forEach((box) => {
      box.addEventListener("click", () => {
        const input = box.parentElement.querySelector('input[type="checkbox"]');
        if (!input || input.disabled) return;
        input.checked = !input.checked;
        // Synthesised because setting .checked in script doesn't fire one,
        // and the display preferences listen for change.
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
  }

  function init() {
    window.PG.showModal = showModal;
    window.PG.hideModal = hideModal;
    window.PG.setConnIndicator = setConnIndicator;

    initDarkMode();
    initColumnResizing();
    initLeftTabs();
    initLeftPanelResize();
    initCheckboxes();

    document.getElementById("modal-backdrop").addEventListener("click", () => {
      document.querySelectorAll(".modal:not(.hidden)").forEach((m) => hideModal(m.id));
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.querySelectorAll(".modal:not(.hidden)").forEach((m) => hideModal(m.id));
      }
    });

    PG.log.info(TAG, "ProxyGate web UI initialized", {
      userAgent: navigator.userAgent,
      url: window.location.href,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
    });

    setInterval(async () => {
      try {
        await PG.api.get("/api/gateway/state");
      } catch (e) { /* api.js logged it */ }
    }, 7000);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
