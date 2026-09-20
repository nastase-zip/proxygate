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

  function initColumnResizing() {
    const table = document.getElementById("traffic-table");
    if (!table) return;

    const ths = Array.from(table.querySelectorAll("th.resizable"));

    // Set initial pixel widths from rendered layout so flex doesn't fight us
    ths.forEach((th) => {
      th.style.width = th.offsetWidth + "px";
      const handle = document.createElement("div");
      handle.className = "col-resize-handle";
      th.appendChild(handle);
    });

    ths.forEach((th, i) => {
      const handle = th.querySelector(".col-resize-handle");
      let startX, startW;

      handle.addEventListener("mousedown", (e) => {
        e.preventDefault();
        startX = e.clientX;
        startW = th.offsetWidth;
        handle.classList.add("dragging");

        function onMove(e) {
          const w = Math.max(40, startW + e.clientX - startX);
          th.style.width = w + "px";
        }
        function onUp() {
          handle.classList.remove("dragging");
          document.removeEventListener("mousemove", onMove);
          document.removeEventListener("mouseup", onUp);
        }
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      });
    });
  }

  // ── Left tabs ────────────────────────────────────────────────────────────────

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

  function init() {
    window.PG.showModal = showModal;
    window.PG.hideModal = hideModal;
    window.PG.setConnIndicator = setConnIndicator;

    initDarkMode();
    initColumnResizing();
    initLeftTabs();

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
