# ProxyGate

Turns a Linux machine into a WiFi hotspot that transparently routes every
connected device through upstream proxies you choose, with per-domain rules.

Devices just join the WiFi and browse normally. No proxy settings to configure
on the device, and no certificate to install unless you specifically want to
decrypt that device's HTTPS.

Everything is controlled from a web UI in your browser.

---

## Quick start

```bash
./setup.sh        # installs dependencies, creates the venv, adds the launcher
sudo proxygate    # starts the gateway and the web UI
```

Then open `http://<this-machine-ip>:8765/` from any device on the same LAN.

Root is required because ProxyGate manages iptables, the WiFi hotspot, and
DHCP. Press Ctrl+C to shut down: the hotspot drops and iptables is flushed
before the process exits.

---

## How it works

A phone on the hotspot opens a connection. Here is what happens to it:

```
Phone  ->  WiFi hotspot (wlp3s0)
             |
             v
       iptables PREROUTING
         DNS  -> local dnsmasq
         TCP  -> redirected to mitmproxy on :8080
             |
             v
       mitmproxy (transparent)
         reads the SNI from the TLS handshake  ("google.com")
         checks your rules  ->  picks a proxy
         logs the connection to the traffic table
             |
             v
       upstream proxy  (e.g. 127.0.0.1:8893)
             |
             v
       Internet
```

The important part: ProxyGate reads the **SNI** from the TLS ClientHello,
which is sent unencrypted at the start of every HTTPS connection. That is
enough to know which site is being visited and route it accordingly, without
decrypting anything. The connection is then forwarded untouched, which is why
devices need no certificate.

Decryption is opt-in per device. Flag a device by MAC in the Devices panel and
install the CA certificate on it, and its traffic gets fully decrypted so you
can read request and response bodies. Every other device on the same hotspot
is unaffected.

---

## Rules

Rules map hostnames to proxies, checked top to bottom, first match wins.
Anything that matches nothing uses the fallback proxy set at the bottom of the
Rules panel.

Two pattern styles:

| Pattern | Matches |
|---|---|
| `*.google.com` | wildcard, and the bare `google.com` too |
| `google.com` | exactly that host |
| `'^(www\.)?google\.com$'` | regex, in single quotes |
| `'^cdn\d+\.example\.com$'` | regex with digits, ranges, alternation |

Put several patterns in one rule, one per line or separated by `;`.

Regexes are case insensitive and match anywhere in the hostname unless you
anchor them with `^` and `$`. A regex that fails to compile is rejected when
you save it, so a typo cannot silently stop a rule from working.

---

## Layout

```
opt/proxygate/
  main.py               entry point, starts the web server
  backend/
    web.py              HTTP API the UI talks to
    services.py         hotspot, iptables, mitmproxy process, device discovery
    rules.py            reads and writes rules.yaml, devices.yaml
    patterns.py         hostname matching (globs and regexes)
    mitm_logger.py      the mitmproxy addon: routing, logging, decryption
    db.py              queries against the traffic database
  webui/                the browser UI (plain HTML, CSS and JS, no build step)

etc/proxygate/          your config, written by the UI
var/lib/proxygate/      traffic.db, the captured traffic log
var/log/proxygate/      logs

tests/                  pytest suite
run-tests.sh            runs it
setup.sh                installs everything
```

Everything lives inside the repo. Nothing is written to `/etc`, `/var` or
anywhere else on the system, so the whole project is self contained and safe
to move or copy.

Per-machine state (`devices.yaml`, `blocked_devices.yaml`, `config.yaml`, the
traffic database and logs) is gitignored, so sharing the repo never shares
another machine's devices or traffic.

---

## The two processes

ProxyGate runs as two cooperating pieces:

**The web server** (`main.py`) owns the hotspot, iptables, and the UI. It
starts and supervises mitmproxy, and restarts it if it dies.

**The mitmproxy addon** (`mitm_logger.py`) runs inside mitmdump and handles
each connection: matching rules, picking the upstream proxy, writing rows to
the traffic database, and decrypting flagged devices.

They share state through files rather than a socket. When you change a rule in
the UI, the web server writes `rules.yaml` and the addon notices the changed
mtime within about 250ms and reloads. No restart needed.

---

## Traffic log

Every connection is written to `var/lib/proxygate/traffic.db` (SQLite) and
shown live in the traffic table. Click a row to see the full request and
response, including headers and body, for decrypted flows.

Two things are deliberately excluded: traffic from the gateway machine itself,
and traffic from anything not on the hotspot subnet. Both would otherwise
appear mixed in with real device traffic and be impossible to tell apart.

---

## Tests

```bash
./run-tests.sh              # all of them
./run-tests.sh -k rules     # just the ones matching "rules"
./run-tests.sh --lf -v      # re-run what failed last time
```

No root needed. The tests redirect every config path into a temp directory and
stub out iptables and nmcli, so they never touch your real config, your
traffic database, or a running gateway. Safe to run while ProxyGate is up.

---

## Requirements

Ubuntu or Debian with NetworkManager, a WiFi adapter that supports AP mode, and Python
3.10 or newer (a mitmproxy constraint). `setup.sh` installs the rest.

The upstream proxies are yours to provide. ProxyGate ships pointing at three
local ones on ports 8893, 8894 and 8895, which is a convention, not a
requirement: any reachable HTTP or SOCKS proxy works.
