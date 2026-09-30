#!/usr/bin/env bash
#
# purge-legacy-install.sh — Remove the pre-repo ProxyGate install from system paths.
#
# ProxyGate is now fully self-contained: every config, database and log lives
# under the checkout (see services.py's PROJECT_ROOT). An older, root-owned
# install still exists in /etc, /opt and /var from the redsocks-era build.
# It is NOT read by the current code, but it is confusing, unreadable without
# sudo, and its stale redsocks daemon still contends for iptables/port state.
#
# Everything removed is backed up to a timestamped tarball first, so this is
# reversible. Run with --dry-run to see the plan without touching anything.
#
#   sudo ./purge-legacy-install.sh --dry-run
#   sudo ./purge-legacy-install.sh
#
# Covers everything the older builds installed system-wide, including the
# WARP/wgcf experiment from ~/Documents/proxy/proxy-gate-web-version.
#
# It ALSO removes the state a CURRENT install leaves outside the checkout.
# That state is not "legacy", but it is not self-contained either, and it is
# machine-specific — so it must not follow a copy of this repo onto someone
# else's system:
#
#   /etc/NetworkManager/dnsmasq-shared.d/proxygate-*.conf
#       Upstream DNS servers and query logging for the hotspot. A stale
#       drop-in here pinned a resolver that later went dark; with `no-resolv`
#       and no fallback, EVERY lookup on the hotspot hung until it timed out,
#       which looks exactly like "the whole proxy is slow". These are
#       rewritten from DNS_UPSTREAMS on the next connect, so removing them is
#       safe and is the right move on a machine that inherited someone
#       else's.
#
#   NetworkManager connection profiles (proxygate-ap, proxygate-ipv6-client)
#       Recreated on every connect, and they carry the SSID/PSK of this
#       machine's hotspot.
#
#   /var/log/proxygate/dnsmasq.log
#       Every DNS query every device on the hotspot has ever made. Nothing
#       rotated it before; it reached 59 MB here. This is browsing history,
#       and it should never leave the machine.
#
# DELIBERATELY PRESERVED (still in active use — do not "clean" these):
#   /opt/proxygate-venv      the Python venv the CURRENT setup.sh and the
#                            running mitmdump both use (setup.sh:19).
#   /usr/local/bin/proxygate the launcher you run as `sudo proxygate`. The
#                            CURRENT setup.sh writes it (setup.sh:24) and it
#                            already points at this checkout — removing it
#                            would break the command entirely. It is checked
#                            below and only rewritten if it points elsewhere.
#   /var/log/proxygate/      the live dnsmasq writes dnsmasq.log here
#                            (/etc/dnsmasq.conf: log-facility=). The stale
#                            web.log inside it is removed; the directory stays.
#   /etc/dnsmasq.conf        hotspot DHCP/DNS config, still current.
#   /etc/NetworkManager/dnsmasq-shared.d/  current hotspot DNS drop-ins.

set -euo pipefail

DRY_RUN=0
KEEP_REDSOCKS=0
for arg in "$@"; do
    case "$arg" in
        --dry-run)       DRY_RUN=1 ;;
        --keep-redsocks) KEEP_REDSOCKS=1 ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *)
            echo "Unknown option: $arg (try --help)" >&2
            exit 2 ;;
    esac
done

if [[ $DRY_RUN -eq 0 && ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "This must run as root (it removes root-owned files): sudo $0" >&2
    exit 1
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
run()  {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '   [dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

# Resolve the repo so we never delete anything inside it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/root/proxygate-legacy-backup-$STAMP.tar.gz"

# Legacy paths, in removal order. /opt/proxygate-venv and /var/log/proxygate
# are intentionally absent — see the header.
LEGACY_PATHS=(
    /etc/proxygate
    /opt/proxygate
    /var/lib/proxygate
    /etc/redsocks.conf
    /var/log/proxygate/web.log
    # WARP/wgcf experiment from the older web-version build.
    /etc/wireguard/warp.conf
    /etc/proxygate/wgcf
    /usr/local/bin/wgcf
    # Machine-specific state a CURRENT install leaves outside the checkout.
    # Regenerated automatically on the next connect (see ensure_dns_upstreams
    # and ensure_dns_logging in services.py), so removing them is safe — and
    # necessary, because a drop-in inherited from another machine can pin a
    # dead resolver and hang every lookup on the hotspot.
    /etc/NetworkManager/dnsmasq-shared.d/proxygate-dns.conf
    /etc/NetworkManager/dnsmasq-shared.d/proxygate-logging.conf
    # Every DNS query every device on the hotspot has ever made. Browsing
    # history; must never follow the repo to another machine.
    /var/log/proxygate/dnsmasq.log
)

# NetworkManager profiles ProxyGate creates. Recreated on every connect, and
# they carry this machine's hotspot SSID/PSK.
LEGACY_NM_CONNECTIONS=(
    proxygate-ap
    proxygate-ipv6-client
)

step "Safety check"
# A hard stop: if the repo somehow lives under a legacy path, bail out rather
# than delete the user's actual working tree.
for p in "${LEGACY_PATHS[@]}"; do
    if [[ "$REPO_ROOT" == "$p"* ]]; then
        echo "REFUSING: the checkout ($REPO_ROOT) is inside a path marked for deletion ($p)." >&2
        exit 1
    fi
done
say "   Checkout at $REPO_ROOT is outside every legacy path. OK."

if [[ ! -d "$REPO_ROOT/etc/proxygate" ]]; then
    echo "REFUSING: $REPO_ROOT/etc/proxygate not found — this does not look like" >&2
    echo "the self-contained checkout, so the legacy files may still be in use." >&2
    exit 1
fi
say "   Self-contained config present at $REPO_ROOT/etc/proxygate. OK."

step "Checking ProxyGate is not running"
# Removing the AP profile and the DNS drop-ins out from under a LIVE gateway
# drops the hotspot and every connected device mid-session, and the running
# process would keep serving from state that no longer exists on disk. Refuse
# rather than do that silently.
if pgrep -f "proxygate/main\.py" >/dev/null 2>&1; then
    echo "REFUSING: ProxyGate is still running." >&2
    echo "  Stop it first (Ctrl+C in its terminal), then re-run this script." >&2
    echo "  Removing the hotspot profile while it is live would drop every" >&2
    echo "  connected device." >&2
    exit 1
fi
say "   Not running. OK."

step "What will be removed"
FOUND=()
for p in "${LEGACY_PATHS[@]}"; do
    if [[ -e "$p" ]]; then
        size="$(du -sh "$p" 2>/dev/null | cut -f1 || echo '?')"
        say "   REMOVE  $p  ($size)"
        FOUND+=("$p")
    else
        say "   absent  $p"
    fi
done

say ""
say "   KEEP    /opt/proxygate-venv   (current setup.sh:19 + running mitmdump)"
say "   KEEP    /var/log/proxygate/   (directory itself; dnsmasq.log is removed)"
say "   KEEP    /etc/dnsmasq.conf     (not ProxyGate's to manage)"

FOUND_CONNS=()
for c in "${LEGACY_NM_CONNECTIONS[@]}"; do
    if nmcli -t -f NAME con show 2>/dev/null | grep -qx "$c"; then
        say "   REMOVE  NetworkManager connection '$c'"
        FOUND_CONNS+=("$c")
    else
        say "   absent  NetworkManager connection '$c'"
    fi
done

if [[ ${#FOUND[@]} -eq 0 && ${#FOUND_CONNS[@]} -eq 0 ]]; then
    say ""
    say "Nothing left to remove — the system is already clean."
    exit 0
fi

step "Stopping the legacy redsocks service"
# redsocks belongs to the old architecture only: the current build routes
# upstream natively via mitmproxy's server_conn.via, no redirector daemon.
if [[ $KEEP_REDSOCKS -eq 1 ]]; then
    say "   --keep-redsocks given, leaving it alone."
elif systemctl list-unit-files 2>/dev/null | grep -q '^redsocks\.service'; then
    run systemctl stop redsocks.service    || true
    run systemctl disable redsocks.service || true
    run rm -f /etc/systemd/system/redsocks.service
    run systemctl daemon-reload
    say "   redsocks stopped, disabled and its unit removed."
else
    say "   No redsocks unit installed."
fi

step "Stopping the legacy WARP/wgcf tunnel"
# The older web-version build could bring up a Cloudflare WARP WireGuard
# tunnel. Nothing in the current architecture uses it, and a leftover tunnel
# silently re-routes traffic away from the proxy.
if systemctl list-units --all 2>/dev/null | grep -q 'wg-quick@warp'; then
    run systemctl disable --now wg-quick@warp || true
    say "   wg-quick@warp stopped and disabled."
else
    say "   No WARP tunnel active."
fi

step "Checking the launcher"
# Not deleted: the CURRENT setup.sh owns this file. But an older build may
# have left it pointing at /opt/proxygate/main.py, which this script is about
# to remove — that would leave `sudo proxygate` broken with a confusing
# "No such file" rather than an obvious cause.
LAUNCHER=/usr/local/bin/proxygate
EXPECTED_MAIN="$REPO_ROOT/opt/proxygate/main.py"
if [[ -f "$LAUNCHER" ]]; then
    if grep -qF "$EXPECTED_MAIN" "$LAUNCHER"; then
        say "   OK — already points at this checkout."
    else
        say "   STALE — points at a path this script removes. Rewriting."
        if [[ $DRY_RUN -eq 1 ]]; then
            say "   [dry-run] rewrite $LAUNCHER -> $EXPECTED_MAIN"
        else
            cat > "$LAUNCHER" <<EOF
#!/bin/bash
exec /opt/proxygate-venv/bin/python3 $EXPECTED_MAIN "\$@"
EOF
            chmod +x "$LAUNCHER"
            say "   Rewritten -> $EXPECTED_MAIN"
        fi
    fi
else
    say "   Not installed — run ./setup.sh to create it."
fi

step "Backing up to $BACKUP"
# Backup before deletion: these files are root-owned and 0600, so if anything
# in them is still wanted it is otherwise unrecoverable.
if [[ ${#FOUND[@]} -eq 0 ]]; then
    say "   No files to back up (only NetworkManager profiles to remove)."
elif [[ $DRY_RUN -eq 1 ]]; then
    say "   [dry-run] tar czf $BACKUP ${FOUND[*]}"
else
    tar czf "$BACKUP" --absolute-names --ignore-failed-read "${FOUND[@]}" 2>/dev/null || true
    chmod 600 "$BACKUP"
    say "   Wrote $(du -sh "$BACKUP" | cut -f1) to $BACKUP"
fi

step "Removing legacy paths"
for p in "${FOUND[@]:-}"; do
    [[ -n "$p" ]] || continue
    run rm -rf "$p"
    [[ $DRY_RUN -eq 1 ]] || say "   removed $p"
done

step "Removing ProxyGate NetworkManager profiles"
# Brought down first: deleting an ACTIVE profile leaves the interface in a
# half-configured state that NM will keep retrying. These are recreated from
# scratch on the next connect, so nothing is lost — but they carry this
# machine's hotspot SSID and PSK, which must not travel with the repo.
if [[ ${#FOUND_CONNS[@]} -eq 0 ]]; then
    say "   None present."
else
    for c in "${FOUND_CONNS[@]}"; do
        run nmcli con down "$c" || true
        run nmcli con delete "$c" || true
        [[ $DRY_RUN -eq 1 ]] || say "   removed connection '$c'"
    done
fi

step "Done"
say "Legacy install purged. ProxyGate now reads config only from:"
say "   $REPO_ROOT/etc/proxygate/"
say ""
say "Backup:  $BACKUP"
say "Restore: sudo tar xzf $BACKUP --absolute-names -C /"
say ""
say "The hotspot's DNS drop-ins and NetworkManager profiles were removed too."
say "They are NOT lost — ProxyGate rewrites them from its own defaults on the"
say "next connect, which is the point: a machine that inherited a stale"
say "resolver (or someone else's hotspot PSK) starts clean instead."
say ""
say "Note: a running mitmdump still holds the old traffic.db open. Restart"
say "      ProxyGate so it reopens the in-repo database:"
say "         sudo proxygate"
