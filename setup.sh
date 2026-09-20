#!/usr/bin/env bash
# setup.sh — install or repair ProxyGate on this machine.
#
# Just run it, no flags:
#   ./setup.sh
#
# Safe to re-run any time — every step below checks the current state first
# and only changes what's actually wrong or missing, so running this on an
# already-working machine is a no-op except for picking up new Python deps.
#
# What this does NOT touch: WAN-side IPv6 configuration (nmcli ipv6.method
# etc). ProxyGate's own IPv6 support (ip6tables mirroring, upstream proxy
# protocol IPv6 handling) needs no special setup — it's just Python/iptables
# logic that runs when the gateway connects. Whether your WAN interface
# actually has global IPv6 connectivity is a network/ISP question, not
# something this script decides on your behalf.
set -euo pipefail

VENV=/opt/proxygate-venv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
APP_DIR="$SCRIPT_DIR/opt/proxygate"
REQS="$APP_DIR/requirements.txt"
MAIN="$APP_DIR/main.py"
LAUNCHER=/usr/local/bin/proxygate

# ── Re-exec under sudo if not root ──────────────────────────────────────────────
# Runs system package installs, writes to /opt and /usr/local/bin — needs root.
# Auto-elevating means `./setup.sh` alone is enough; no --install flag to remember.
# Deliberately NOT using `sudo -E`: preserving the calling user's environment
# (locale, TMPDIR, any CURL_*/http_proxy-style vars) into the root process is
# more likely to cause subtle divergences from a plain interactive `sudo`
# command than to help — this script doesn't need anything from that
# environment, so root gets a clean one.
if [[ $EUID -ne 0 ]]; then
    echo "==> Re-running as root (sudo)…"
    exec sudo bash "$SCRIPT_DIR/setup.sh" "$@"
fi

echo "==> ProxyGate setup — $SCRIPT_DIR"
echo ""

# ── System packages ──────────────────────────────────────────────────────────────
# iptables also provides ip6tables on Debian/Ubuntu (same package, same binary
# set) — no separate package needed for ProxyGate's IPv6 support.
echo "==> System packages"
apt-get update -q
apt-get install -y \
    python3 python3-pip python3-venv \
    iptables \
    conntrack \
    iw \
    iproute2 \
    procps \
    curl \
    sqlite3

# ── Python venv ────────────────────────────────────────────────────────────────
# A previously hand-created "venv" directory can end up being nothing more
# than bin/python3 symlinked straight to system python, with no actual venv
# underneath — pip installs into it then either fail outright
# (externally-managed-environment) or land in the system site-packages
# instead of an isolated one. A *real* venv always has a pyvenv.cfg at its
# root (python3 -m venv writes one unconditionally) — that's the reliable
# marker, not whether bin/python3 is a symlink, since every real venv's
# python3 is ALSO a symlink to the system interpreter by design.
echo ""
echo "==> Python venv: $VENV"
NEED_FRESH_VENV=0
if [[ ! -f "$VENV/bin/python3" ]] || [[ ! -f "$VENV/pyvenv.cfg" ]]; then
    echo "    $VENV is missing or isn't a real venv (no pyvenv.cfg) — (re)creating."
    NEED_FRESH_VENV=1
elif ! "$VENV/bin/python3" -c "import ensurepip" >/dev/null 2>&1; then
    echo "    Found $VENV but it looks broken — recreating."
    NEED_FRESH_VENV=1
fi

if [[ "$NEED_FRESH_VENV" == "1" ]]; then
    rm -rf "$VENV"
    python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$REQS"
echo "    OK — $("$VENV/bin/python3" --version)"

# ── Remove WARP/wgcf (reverted — see project history) ────────────────────────────
# WARP-tunneled IPv6 presented Cloudflare's address as the traffic source,
# which fails silently against any upstream proxy that authorizes by source
# IP (allowlisting this machine's real Ethernet IPv4). There's no tunnel
# that avoids this — a tunnel's whole mechanism is presenting the tunnel
# provider's identity, never the original one. Tearing down any install
# left by a previous version of this script.
if systemctl list-unit-files 2>/dev/null | grep -q "wg-quick@warp"; then
    echo ""
    echo "==> Removing previous WARP/wgcf install"
    systemctl disable --now wg-quick@warp >/dev/null 2>&1 || true
fi
rm -f /etc/wireguard/warp.conf
rm -rf /etc/proxygate/wgcf
rm -f /usr/local/bin/wgcf

# ── Launcher ───────────────────────────────────────────────────────────────────
# Always rewritten, pointing at THIS checkout's main.py. Prevents the launcher
# silently drifting to point at a stale/renamed/relocated copy of the app —
# which is exactly what happened when an old checkout was replaced by this one
# but /usr/local/bin/proxygate still pointed at the old path.
echo ""
echo "==> Launcher: $LAUNCHER"
cat > "$LAUNCHER" <<EOF
#!/bin/bash
exec $VENV/bin/python3 $MAIN "\$@"
EOF
chmod +x "$LAUNCHER"
echo "    -> $MAIN"

echo ""
echo "==> Done."
echo "  sudo proxygate"
echo ""
echo "Starts the ProxyGate web UI on port 8765. From any device on the same"
echo "LAN as this machine's Ethernet/WAN connection, open:"
echo "  http://<this-machine-ip>:8765/"
echo ""
echo "Ctrl+C (or systemctl stop, if you wrap this in a service) shuts the"
echo "gateway down cleanly — stops mitmproxy, drops the hotspot, flushes"
echo "iptables — before the process exits."
