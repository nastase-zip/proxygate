# ProxyGate — Architecture & How It Works

## What it does

ProxyGate turns your Linux machine into a WiFi hotspot that transparently proxies all connected devices through configurable upstream proxies (SOCKS5, HTTP CONNECT). Devices connect to the hotspot and browse normally — no proxy settings needed on the device, and by default no CA to install. A device can optionally be flagged (by MAC, in the web UI's Devices panel) to get real HTTPS decryption instead — see [Per-device TLS decryption](#per-device-tls-decryption-backendmitm_loggerpy--devicesengine) — while every other device on the same hotspot keeps the CA-free passthrough behavior unchanged.

Control happens through a **web UI** served over HTTP on the host's LAN-facing (Ethernet/WAN) network — see [Web UI](#web-ui-backendwebpy) below. The WiFi adapter stays dedicated to the ProxyGate hotspot; it is never used to serve the control panel.

---

## Traffic flow (end to end)

```
Phone makes TCP connection to google.com:443
        │
        ▼
[WiFi hotspot — wlp3s0]
        │
        ▼
iptables PREROUTING (nat)
  PROXYGATE_REDIRECT chain  ← inserted at position 1, before Docker/NM rules
  ├── DNS UDP/TCP :53  →  DNAT to 192.168.100.1:53  (NM's dnsmasq answers)
  └── all TCP          →  REDIRECT to :8080          (mitmproxy)
        │
        ▼
mitmproxy (transparent mode, port 8080)
  ├── tls_clienthello hook fires
  │     reads SNI from ClientHello  (e.g. "google.com")
  │     matches rule  →  finds proxy for this destination
  │     registers (host, port) → proxy_cfg in _dest_proxy dict
  │     sets ignore_connection=True  (raw TLS passthrough, no decryption)
  │
  └── asyncio.open_connection("google.com", 443)  ← patched at import time
        pops _dest_proxy[("google.com", 443)]  →  gets proxy_cfg
        runs PySocks CONNECT handshake in thread executor
        returns connected socket to mitmproxy
        │
        ▼
upstream proxy  (e.g. HTTP CONNECT to 127.0.0.1:8893)
        │
        ▼
Docker container  (xvpn / xvpn-fr)
  ExpressVPN tun interface  →  exits in GB / FR
        │
        ▼
Internet
```

---

## Key components

### iptables (`backend/services.py → apply_iptables`)

Three custom chains, all inserted at **position 1** so they run before NetworkManager's chains:

| Chain | Table | Purpose |
|---|---|---|
| `PROXYGATE_REDIRECT` | nat PREROUTING | DNAT DNS, REDIRECT all TCP to mitmproxy port 8080 |
| `PROXYGATE_MASQ` | nat POSTROUTING | MASQUERADE hotspot subnet out WAN interface |
| `PROXYGATE_FORWARD` | filter FORWARD | DROP all UDP from hotspot (no UDP proxy path); ACCEPT TCP return traffic |

**Critical:** `PROXYGATE_FORWARD` must be at position 1 in FORWARD. NetworkManager inserts `nm-sh-fw-wlp3s0` which has `ACCEPT all -s 192.168.100.0/24 -i wlp3s0`. If that runs first it accepts everything including UDP, bypassing all our rules and leaking the real IP.

**Why drop all UDP:** mitmproxy only handles TCP. Any UDP that reaches FORWARD would be masqueraded directly to WAN, bypassing the proxy entirely and leaking the device's real-destination traffic with the host's IP. DNS still works because it's DNAT'd to the gateway's dnsmasq before FORWARD is ever evaluated.

**Why flush conntrack on apply:** iptables REDIRECT only catches *new* TCP connections. Pre-existing connections (HTTP/2 keep-alive, long-lived TLS sessions) have ESTABLISHED entries in conntrack that route them directly through FORWARD, bypassing REDIRECT. `conntrack -D -s <subnet>` kills those entries so every connection reconnects fresh and hits the REDIRECT rule.

### mitmproxy transparent proxy (`backend/mitm_logger.py`)

Runs as `mitmdump --mode transparent --listen-port 8080`.

**`asyncio.open_connection` patch** — installed once at import time, never removed:

```python
asyncio.open_connection = _proxied_open_connection
```

mitmproxy's internal `server.py` opens all outbound TCP via a module-level `asyncio.open_connection` lookup. Patching the module attribute intercepts every outbound connection regardless of layer (TCPLayer, TLSLayer, HTTPLayer). The patch runs a hand-rolled proxy-protocol handshake in a `ThreadPoolExecutor` (so it doesn't block the event loop), then hands the connected socket back to asyncio.

**Why not PySocks:** the upstream proxy handshake used to go through the PySocks library, but PySocks has two hard problems: (1) `socksocket.connect()` unconditionally raises `"PySocks doesn't support IPv6"` for any IPv6 destination literal, regardless of proxy type — SOCKS5, SOCKS4, and HTTP CONNECT were all affected even though SOCKS5 and HTTP CONNECT support IPv6 destinations perfectly well as protocols; (2) its HTTP CONNECT negotiator sends `Proxy-Authorization: basic` (lowercase scheme) with no `Proxy-Connection`/`User-Agent` headers and never retries on a `407` challenge — some real-world HTTP proxies do case-sensitive scheme matching or expect those headers, which is why some HTTP proxies worked and others didn't. Both are now hand-rolled directly in `mitm_logger.py`:

- **SOCKS5** (`_socks5_connect`) — full RFC 1928 implementation, including address type `0x04` for IPv6 destination literals (the exact code path PySocks could never reach) and address type `0x03` for hostnames. Username/password auth negotiated per spec.
- **SOCKS4/SOCKS4a** (`_socks4_connect`) — IPv4-only by protocol design (the wire format has a fixed 4-byte address field); an IPv6 destination is rejected immediately with a clear error rather than silently mishandled. SOCKS4a hostname resolution (0.0.0.x placeholder + trailing hostname) is supported.
- **HTTP CONNECT** (`_http_connect`) — sends `Proxy-Connection: keep-alive` and a `User-Agent`, uses capital-`B` `"Basic"` for auth, and does a real `407` challenge/response retry (send unauthenticated first only if creds aren't required upfront; on `407`, retry once with `Proxy-Authorization`). IPv6 destinations are sent bracketed (`CONNECT [2001:db8::1]:443 HTTP/1.1`) per RFC 3986/7230. The response head is read one byte at a time up to `\r\n\r\n` specifically so a proxy that packs the first tunnelled byte into the same TCP segment as its response headers never has that byte silently swallowed — there's no reliable way to hand bytes back to the socket once it's handed to asyncio/TLS afterward.

All three raise `ProxyProtocolError` (a subclass of `OSError`) with a specific, human-readable reason (auth failure, protocol-level refusal reason, malformed response, etc.) instead of PySocks's one generic exception type for every kind of failure — this is what makes "why did proxy X fail" diagnosable from the mitmdump log instead of every failure looking identical.

**Why not ContextVar for per-connection routing:** mitmproxy's `server.py` spawns a *new asyncio Task* for each `OpenConnection` command via `create_task`. ContextVars do not inherit across `create_task` — the child task starts with the default value. This caused every connection to fall through to the default proxy regardless of rule.

**The `_dest_proxy` dict:** Instead of ContextVar, hooks register the chosen proxy keyed by `(host, port)` before `open_connection` is called for that destination. `_proxied_open_connection` pops the entry — one entry per connection, no stale state. Falls back to `_default_proxy` (the rules default) if nothing is registered (raw TCP flows that never trigger a hook).

**Why `connection_strategy=lazy`:** Without this, mitmproxy pre-connects to the server before `tls_clienthello` fires. The hook wouldn't have run yet so `_dest_proxy` would be empty and the connection would use the wrong proxy.

**Why `http2=false`:** HTTP/2 ALPN negotiation in passthrough mode causes some servers to reject connections. Disabling forces HTTP/1.1 which works cleanly through CONNECT proxies.

**Why `ignore_connection=True` in `tls_clienthello`:** This tells mitmproxy to pass raw TLS bytes through unchanged. Without it, mitmproxy tries to terminate TLS using its own CA certificate — the device would get a certificate error. No CA installation needed on the device.

**Why `socket.listen` patch:** mitmproxy calls `listen(100)`. Under burst traffic (phone opening many connections at once) the accept queue fills and the kernel drops SYNs. Dropped SYNs cause retransmits; apps with QUIC/UDP fallback switch to UDP which bypassed mitmproxy before the UDP DROP rule was added. The patch forces `listen(4096)` regardless of what mitmproxy passes.

**IPv6 support:** `apply_iptables()` now mirrors the IPv4 REDIRECT/MASQUERADE/FORWARD chains for IPv6 (`PROXYGATE_REDIRECT6`/`PROXYGATE_MASQ6`/`PROXYGATE_FORWARD6`) and enables `net.ipv6.conf.all.forwarding`, instead of unconditionally dropping all IPv6 from the hotspot interface as it used to. This matters even though the hotspot's own DHCP (NM "shared" mode) is IPv4-only — a device can still pick up an IPv6 address via SLAAC/router advertisement forwarded from the WAN side. IPv6 TCP now redirects into the same mitmproxy instance as IPv4; IPv6 UDP is still dropped for the same reason IPv4 UDP is (no UDP proxy path). There's no IPv6 DNS DNAT — devices resolve names over the existing IPv4 DNS path regardless of which family they browse over.

### Why upstream IPv6 proxies need this machine's own WAN to have real IPv6

The IPv6 support described above only helps once this machine's own WAN connection has real IPv6 in the first place — plenty of routers/ISPs still don't offer it, and this codebase doesn't try to change that (see setup.sh's comment on why it deliberately doesn't touch `nmcli ipv6.method`). When WAN has no IPv6, mitm_logger.py's outbound `connect()` to an IPv6-addressed **upstream proxy** fails outright — there's no route to any IPv6 address, independent of anything in ProxyGate's own code.

**A WireGuard tunnel (e.g. Cloudflare WARP via `wgcf`) was tried and reverted.** It does give the host a real, working IPv6 route — verified with a packet capture showing full TCP handshakes and CONNECT requests reaching the proxy successfully. But it doesn't solve the actual problem for an IP-allowlisted proxy: a tunnel's outbound packets carry the *tunnel provider's* address, not this machine's own — so a proxy that authorizes by source IP (allowlisting the Ethernet connection's real public IPv4) silently rejects the tunnel's address instead, indistinguishable from the proxy being dead until packet-level inspection shows otherwise. This isn't specific to WARP — any tunnel (Hurricane Electric, a VPS relay, etc.) has the same property, since presenting a different source identity is what a tunnel *is*.

NAT64/DNS64/Jool-style translation doesn't help either, for a different reason: that architecture solves the opposite direction (IPv6-only client reaching an IPv4-only server), and even in its reverse (NAT46/SIIT) mode still requires the translator itself to have a real IPv6 uplink — translating packet headers doesn't manufacture a route where none exists.

**Bottom line:** if an upstream proxy is IPv6-only and IP-allowlisted, the only way to reach it is from a machine whose WAN genuinely has that allowlisted IPv4 address AND real IPv6 on the same connection — no software-only trick on this host changes that. If it's IPv6-only but *not* IP-restricted, a tunnel remains a viable option; it just wasn't worth the added complexity/dependency for the proxies this was tested against.

### Per-rule proxy routing

Rules in `rules.yaml` map glob patterns to proxy names:

```yaml
rules:
  - pattern: "*.ipinfo.io"
    proxy: docker          # → GB ExpressVPN on 8893
default: fr docker         # → FR ExpressVPN on 8894
```

Flow:
1. `tls_clienthello` extracts SNI → `rules.match(sni)` → gets proxy name → `rules.resolve_proxy(name)` → gets proxy dict
2. Registers `(sni, port) → proxy_dict` in `_dest_proxy`
3. `open_connection("ipinfo.io", 443)` pops the entry → connects via GB proxy
4. `open_connection("google.com", 443)` finds no entry → falls back to `_default_proxy` → connects via FR proxy

### Web UI (`backend/web.py`)

A Flask app replaces the old DearPyGui desktop UI, served by **waitress** (a production WSGI server) rather than Flask's built-in dev server — the dev server is single-purpose and not meant for continuous multi-device use; a single slow request (e.g. checking a dead proxy's latency) could starve other clients' requests under it. `backend/web.py` imports `backend/services.py`, `backend/rules.py`, and `backend/db.py` completely unchanged — the web layer is purely a new transport for the same function calls a button click used to make directly. No proxy/gateway logic lives in `backend/web.py` itself.

```
Browser (any device on the LAN)
    │  HTTP :8765
    ▼
backend/web.py  (Flask app, served by waitress, binds 0.0.0.0, 8 request threads)
    │
    ├── /api/gateway/*        → services.connect_gateway() / disconnect_gateway() / get_gateway_state()
    ├── /api/rules/*          → rules.load_rules() / add_rule() / update_rule() / reload_rules() / ...
    ├── /api/proxies/*        → rules.add_proxy() / remove_proxy() / ... (proxy CRUD)
    ├── /api/proxies/latency  → services.check_proxy_latency() run concurrently (thread pool) per proxy
    ├── /api/settings         → services.load_config() / save_config()
    ├── /api/status           → services.check_all_services(), get_hotspot_ip(), resolve_ap_wifi_if(), detect_wan_if()
    ├── /api/traffic/session  → session floor id + live stats (fetched once on page load)
    ├── /api/traffic/live     → db.get_connections_since()   (polled every 500ms — forward tail)
    ├── /api/traffic/history  → db.get_history_page()        (chunked backward paging + server-side search)
    └── /api/clientlog        → mirrors browser console errors/warnings into the server log
```

**Why polling, not WebSockets:** the traffic feed and status panel poll on fixed intervals from the browser, exactly mirroring the old background-thread-plus-queue design in `traffic_panel.py`/`status_panel.py`. Simpler to reason about and debug than a persistent socket, and the intervals (500ms traffic, 5s status) match what the desktop UI already used.

**Traffic history is session-scoped and chunked, not a full dump.** `backend/web.py` records `SESSION_FLOOR_ID = db.get_max_id()` once at process start; every history/search query is `WHERE id > SESSION_FLOOR_ID`, so a fresh `sudo proxygate` never loads a machine's entire lifetime traffic history into the browser. History loads in chunks of 50 (`/api/traffic/history?before_id=<cursor>`) as the user scrolls up, and search (`?q=`) is evaluated in SQL server-side — the browser never filters rows it already has in memory.

**Why concurrent latency checks:** `check_proxy_latency()` does a real blocking TCP connect per proxy (up to a few seconds if the proxy is down). Checking N proxies serially could block the whole endpoint — and, under a naive server, other clients' requests — for `N × timeout` seconds. `/api/proxies/latency` now fires all checks into a small `ThreadPoolExecutor` and waits on all of them together, so total latency is bounded by the slowest single check, not the sum.

**Static frontend** lives under `opt/proxygate/webui/` (`templates/index.html`, `static/css/style.css`, `static/js/*.js`, `static/fonts/` for the bundled Font Awesome webfont), plain HTML/CSS/JS, no build step, no framework. One JS module per panel (`rules.js`, `proxies.js`, `status.js`, `traffic.js`, `settings.js`), plus `api.js` (fetch wrapper) and `debug.js`.

**Browser-side debug console (`debug.js`):** every API call, state transition, and uncaught JS error is logged to an in-page console (toggle via the bug icon next to the ProxyGate title, or Ctrl+Shift+D), mirrored to the real browser devtools console, and — for warnings/errors — POSTed to `/api/clientlog` so they land in the server's log file too. This exists specifically so a broken migration is debuggable without needing devtools access (e.g. testing from a phone).

**Reachability:** waitress binds `0.0.0.0:8765` by default, so it's reachable from any device on the same network as the host's Ethernet/WAN interface — not the hotspot WiFi, which is reserved for proxied client devices.

**WAN/AP interface resolution is dynamic, not cached.** `detect_wan_if()` re-evaluates on every call by reading live default routes (ordered by metric) and actively excludes whatever interface `resolve_ap_wifi_if()` reports the hotspot is using. This matters because a laptop's WiFi and Ethernet can both hold a default route at once (e.g. right after swapping routers) — without this exclusion, WAN detection could resolve to the same NIC the AP needs, which silently hangs `connect_gateway()` instead of failing. `_preflight_check()` in `services.py` runs this comparison before any network mutation and fails fast with a clear error if WAN and AP would collide, instead of leaving the UI stuck on "Connecting…". The resolved AP/WAN interfaces and any conflict are also exposed via `/api/status` and shown live in the web UI's Hotspot section.

**Startup self-healing.** If the app starts and finds `net.ipv4.ip_forward=1` or leftover `PROXYGATE_*` iptables chains with no hotspot actually running (e.g. after a crash or `kill -9` mid-connect, where `flush_iptables()` never got to run), `bootstrap()` detects and clears that stale state automatically via `_clear_stale_network_state()`. A live watchdog also compares the WAN interface baked into the active `PROXYGATE_MASQ` rule against a fresh `detect_wan_if()` every 5s while connected, and reapplies iptables if they've diverged (e.g. the cable moved to a different router mid-session).

### Hot-reload (`backend/rules.py → RulesWatcher`)

Polls `rules.yaml` mtime every 250ms. Also watches `/tmp/proxygate-reload` (touched by the UI's "Apply Rules Now" button) for instant reload without polling delay. On reload, `_set_default_proxy` is updated atomically. In-flight connections keep their already-registered proxy entry; new connections pick up the new rules immediately.

### Docker proxies (`xv_docker_amd64/`)

Two containers, same image, different `EVPN_CLUSTER` build arg:

| Container | Port | Country |
|---|---|---|
| `xvpn` | 8893 | GB (United Kingdom) |
| `xvpn-fr` | 8894 | FR (France) |

Each runs ExpressVPN inside a privileged container with `/dev/net/tun` and `NET_ADMIN`. 3proxy (compiled from source, single binary) runs on port 8888 inside the container, exposed to the host. All 3proxy traffic routes through the VPN tunnel automatically because the container's default route goes through the ExpressVPN tun interface.

3proxy replaced tinyproxy because tinyproxy's `StartServers` pre-fork model tried to spawn 100 processes on container start, exhausting memory and crashing.

---

## What status codes we can and can't get

| Traffic type | Status codes | Why |
|---|---|---|
| HTTP (port 80) | ✅ Real codes | mitmproxy fully intercepts, reads response |
| HTTPS (port 443), device not flagged for decryption | ❌ None | `ignore_connection=True` — raw TLS passthrough, no decryption |
| HTTPS (port 443), device flagged for decryption | ✅ Real codes | mitmproxy terminates TLS with its own CA (see "Per-device TLS decryption" below) — requires that CA installed+trusted on the device |
| TCP errors | ⚠️ `0` (error) | `error` hook fires, logged as status 0 |
| Proxy connect failures | ⚠️ `FAIL` in log | `_proxied_open_connection` raises OSError, mitmproxy closes connection |

---

## Per-device TLS decryption (`backend/mitm_logger.py → DevicesEngine`)

By default every device gets raw-TLS passthrough — `ignore_connection=True` in
`tls_clienthello`, no CA needed, no decrypted status codes (see table above).
A device can opt in to real decryption, and both modes run **simultaneously
on the same hotspot**: some phones passthrough, others get decrypted, decided
per-connection by source IP → MAC lookup, with zero impact on devices that
aren't flagged.

**Why per-device, and why by MAC, not IP:** the alternative (decrypt by
destination domain) helps debug one site regardless of device; per-device
was chosen instead because the actual goal is getting real status codes from
specific test devices the operator controls end-to-end (installing the CA is
the operator's own action, on their own device). MAC rather than IP so the
flag survives a DHCP lease renewal on the hotspot subnet — flip it once in
the UI and it keeps applying to that physical device indefinitely, instead
of silently detaching the next time dnsmasq hands out a different lease.

**Flow:**
1. `/etc/proxygate/devices.yaml` stores flagged devices: `{mac, label, decrypt}`.
   CRUD lives in `backend/rules.py` (`load_devices`/`save_devices`/
   `add_decrypt_device`/`set_decrypt_device`/`remove_decrypt_device`), same
   atomic-write-then-rename pattern as `rules.yaml`.
2. `mitm_logger.py`'s `DevicesEngine` loads `devices.yaml` into an in-memory
   MAC set (`decrypt_macs`), hot-reloaded by the same `RulesWatcher` that
   already polls `rules.yaml` mtime + the `/tmp/proxygate-reload` touch file
   — extended to also watch `devices.yaml`'s mtime.
3. In `tls_clienthello`, after the existing rule-matching/proxy-registration
   logic, the client's source IP is resolved to a MAC (`_resolve_mac`, backed
   by `backend.services.resolve_mac` — dnsmasq leases first, ARP/neighbor
   table as fallback for statically-addressed devices) and checked against
   `DevicesEngine.should_decrypt()`.
   - MAC in the decrypt set → `data.ignore_connection` is left `False` (i.e.
     explicitly NOT set to `True`) → mitmproxy proceeds with its normal
     TLS-terminating MITM using its own CA, exactly like running mitmproxy
     in its default (non-transparent-passthrough) mode.
   - MAC not in the set, or unresolvable → `ignore_connection=True`, same
     raw-TLS passthrough as before. This is also the fallback on any error,
     so a MAC-resolution failure fails closed to passthrough, never to an
     unexpected decrypt.
4. Once mitmproxy decrypts a flow, the existing `request()`/`response()`/
   `error()` hooks — already written generically for any HTTP flow — start
   firing for it exactly as they already do for plain HTTP, with zero
   additional code: `flow.response.status_code` is populated automatically.

**MAC resolution caching:** `_resolve_mac()` caches each IP → MAC lookup for
5 seconds (`_MAC_CACHE_TTL`) so a busy device opening many TLS connections in
a burst doesn't re-read the dnsmasq lease file / re-shell out to `ip neigh`
on every single handshake — a resolution can lag a real MAC change (e.g. a
device instantly rejoining with a new NIC) by at most that window.

**Serving the CA cert:** `GET /api/devices/ca-cert` (`backend/web.py`) serves
`~root/.mitmproxy/mitmproxy-ca-cert.pem` — mitmproxy (running as root, see
`main.py`) generates this unconditionally on first launch, so the file only
exists after the gateway has been started at least once. The web UI's
Devices panel links to it as a plain download; installing the profile and
trusting it as a CA is a per-OS action the device owner does themselves
(Android: Settings → install as a user/VPN CA; iOS: install the profile,
then separately enable full trust under Certificate Trust Settings) — this
project deliberately doesn't try to automate that part.

**UI:** a third left-panel tab ("Devices", `webui/static/js/devices.js`)
lists flagged devices with a lock/unlock toggle and a delete action, plus a
button to download the CA cert. "Add device" (`modal-add-device`) offers a
dropdown of devices currently visible on the hotspot subnet
(`GET /api/devices/seen`, sourced from dnsmasq leases + the live ARP/neighbor
table) as a convenience, with manual MAC entry as a fallback for devices not
currently connected.

---

## Why the device never sees its real IP

Every outbound TCP from the device hits the REDIRECT rule and goes into mitmproxy. mitmproxy connects upstream via the registered proxy (Docker container → ExpressVPN → internet). The device's packets never reach the WAN interface directly. UDP is dropped entirely at FORWARD before it can be masqueraded.

The only path to the real IP would be:
1. A bug in the `_dest_proxy` registration (hook doesn't fire before `open_connection`) — mitigated by `connection_strategy=lazy`
2. A pre-existing conntrack ESTABLISHED entry from before ProxyGate started — mitigated by conntrack flush on `apply_iptables`
3. UDP reaching FORWARD — mitigated by the UDP DROP rule at position 1 of `PROXYGATE_FORWARD`
