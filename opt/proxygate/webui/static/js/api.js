/**
 * api.js — Fetch wrapper for the ProxyGate REST API.
 *
 * Every call is logged via PG.log.net (method, url, status, duration, and
 * request/response bodies on failure) so the debug console gives a full
 * trace of what the frontend asked the backend to do and what came back.
 */

(function () {
  "use strict";

  async function request(method, url, body) {
    const start = performance.now();
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }

    let res, json;
    try {
      res = await fetch(url, opts);
    } catch (networkErr) {
      const duration = Math.round(performance.now() - start);
      PG.log.net(method, url, "NETWORK_ERROR", duration, { body, error: networkErr.message });
      PG.setConnIndicator && PG.setConnIndicator(false);
      throw new Error(`Network error calling ${method} ${url}: ${networkErr.message}`);
    }

    const duration = Math.round(performance.now() - start);

    try {
      json = await res.json();
    } catch (parseErr) {
      PG.log.net(method, url, res.status, duration, { body, error: "invalid JSON response" });
      throw new Error(`Invalid JSON from ${method} ${url}`);
    }

    if (!res.ok || json.ok === false) {
      PG.log.net(method, url, res.status, duration, { body, response: json });
    } else {
      PG.log.net(method, url, res.status, duration, body !== undefined ? { body } : undefined);
    }

    PG.setConnIndicator && PG.setConnIndicator(true);

    if (!res.ok || json.ok === false) {
      const err = new Error(json.msg || `Request failed: ${method} ${url}`);
      err.payload = json;
      err.status = res.status;
      throw err;
    }
    return json;
  }

  window.PG = window.PG || {};
  window.PG.api = {
    get: (url) => request("GET", url),
    post: (url, body) => request("POST", url, body === undefined ? {} : body),
    put: (url, body) => request("PUT", url, body === undefined ? {} : body),
    del: (url) => request("DELETE", url),
  };
})();
