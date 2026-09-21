#!/usr/bin/env python3
"""
ProxyGate — main entry point.
Run as root: sudo /opt/proxygate-venv/bin/python3 /opt/proxygate/main.py

Serves the web UI on the local network. Any device on the same LAN as the
host's Ethernet/WAN interface can browse to http://<host-ip>:<port>/ to
view and control the gateway. The WiFi adapter remains dedicated to the
ProxyGate hotspot, exactly as before — it is not used for the UI.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(__file__))

from backend import db
from backend import services
from backend import web

DEFAULT_PORT = 8765
_log = logging.getLogger("proxygate.main")


def _shutdown(signum, _frame) -> None:
    """
    Run on SIGINT (Ctrl+C) and SIGTERM — tears the gateway down the same way
    the web UI's Disconnect button does (stop mitmproxy, take the hotspot
    down, flush iptables, reset ip_forward) before the process actually
    exits, instead of leaving all of that behind for the next start to find
    and self-heal. Runs synchronously (not the threaded disconnect_gateway())
    because the process is about to exit — nothing left to poll for the
    async result afterward.
    """
    name = signal.Signals(signum).name
    _log.info("Received %s — shutting down gateway cleanly…", name)
    state, _ = services.get_gateway_state()
    if state != services.GatewayState.IDLE:
        services._disconnect_worker(on_done=None)
    _log.info("Shutdown complete.")
    sys.exit(0)


def _setup_logging() -> None:
    _app_dir = os.path.dirname(os.path.abspath(__file__))       # .../opt/proxygate
    _project_root = os.path.dirname(os.path.dirname(_app_dir))  # repo root
    log_dir = os.path.join(_project_root, "var/log/proxygate")
    try:
        from backend.rules import _restore_owner
        log_existed = os.path.isdir(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        if not log_existed:
            _restore_owner(log_dir, is_dir=True)
        log_file = os.path.join(log_dir, "web.log")
        file_existed = os.path.exists(log_file)
        handlers = [logging.StreamHandler(sys.stdout), logging.FileHandler(log_file)]
        if not file_existed:
            _restore_owner(log_file)
    except Exception:
        handlers = [logging.StreamHandler(sys.stdout)]

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="ProxyGate web UI server")
    parser.add_argument("--host", default="0.0.0.0",
                         help="Bind address (default: 0.0.0.0 — reachable from the LAN)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                         help=f"Bind port (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ProxyGate requires root privileges.")
        print("Run: sudo proxygate")
        print("  or: sudo /opt/proxygate-venv/bin/python3", __file__)
        sys.exit(1)

    _setup_logging()
    log = logging.getLogger("proxygate.main")

    # Create dirs, config files, detect existing gateway state — no network changes
    services.bootstrap()
    db.init_db()

    wan_if = services.detect_wan_if()
    wan_ip = services.get_interface_ip(wan_if) if wan_if else "—"
    if wan_if and wan_ip != "—":
        log.info("ProxyGate starting — web UI on http://%s:%s/", wan_ip, args.port)
    else:
        log.info("ProxyGate starting — web UI on http://0.0.0.0:%s/ "
                  "(couldn't detect a LAN IP — open this from the machine itself, "
                  "or set the WAN interface in Settings)", args.port)
    log.info("WAN interface: %s (this is the network the web UI should be reached on)",
              wan_if or "unknown — set it in Settings")

    # Ctrl+C or `kill`/`systemctl stop` now tears the gateway down cleanly
    # (mitmproxy stopped, hotspot down, iptables flushed) instead of leaving
    # ip_forward=1 and PROXYGATE_* chains behind for bootstrap() to have to
    # notice and clean up on the next start.
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    web.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
