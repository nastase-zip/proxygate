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

  function setSection(prefix, headers, bodyB64, truncated) {
    document.getElementById(`fd-${prefix}-headers`).textContent = headers || "(no headers)";
    document.getElementById(`fd-${prefix}-body`).textContent = bodyB64 ? b64ToText(bodyB64) : "(empty body)";
    document.getElementById(`fd-${prefix}-truncated`).classList.toggle("hidden", !truncated);
  }

  async function open(connectionId, row) {
    const title = document.getElementById("fd-title");
    title.textContent = `${row.dest_host || "?"}:${row.dest_port || "?"} — ${row.status_code ?? "?"}`;
    document.getElementById("fd-empty").classList.add("hidden");
    document.getElementById("fd-body").classList.add("hidden");
    PG.showModal("modal-flow-detail");

    try {
      const res = await PG.api.get(`/api/traffic/${connectionId}/detail`);
      setSection("request", res.request_headers, res.request_body_b64, res.request_truncated);
      setSection("response", res.response_headers, res.response_body_b64, res.response_truncated);
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

  function init() {
    document.getElementById("fd-close").addEventListener("click", () => PG.hideModal("modal-flow-detail"));
  }

  document.addEventListener("DOMContentLoaded", init);

  window.PG = window.PG || {};
  window.PG.flowDetail = { open };
})();
