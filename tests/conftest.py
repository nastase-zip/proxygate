"""
Shared fixtures.

mitm_logger imports mitmproxy at module scope, which isn't installed outside
the app's venv. The addon's pure logic (rule matching, own-traffic filtering,
lease parsing) doesn't touch mitmproxy at all, so a stub lets those be tested
anywhere without pulling in the whole proxy.
"""
import os
import sys
import types

APP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "opt", "proxygate")
sys.path.insert(0, APP_DIR)


def _stub_mitmproxy() -> None:
    if "mitmproxy" in sys.modules:
        return
    mm = types.ModuleType("mitmproxy")
    mm.ctx = types.SimpleNamespace()
    mm.http = types.SimpleNamespace()
    sys.modules["mitmproxy"] = mm
    for sub in ("http", "ctx", "connection", "tls", "proxy", "net"):
        sys.modules[f"mitmproxy.{sub}"] = types.ModuleType(f"mitmproxy.{sub}")


_stub_mitmproxy()
