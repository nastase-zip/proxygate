#!/usr/bin/env bash
# run-tests.sh — run ProxyGate's test suite.
#
#   ./run-tests.sh              # everything, quiet
#   ./run-tests.sh -v           # show each test name
#   ./run-tests.sh tests/test_api.py          # one file
#   ./run-tests.sh -k devices                 # tests matching "devices"
#   ./run-tests.sh --lf                       # only what failed last time
#
# Any arguments are passed straight through to pytest.
#
# Deliberately does NOT need root: every test redirects its config/database
# paths into a temp dir and stubs the privileged calls (iptables, nmcli,
# signalling mitmdump), so this never touches the real gateway, your
# rules.yaml, or traffic.db. Safe to run while ProxyGate itself is running.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR"

VENV=/opt/proxygate-venv

# ── Pick an interpreter ────────────────────────────────────────────────────────
# Prefer the app's own venv — that's the environment ProxyGate actually runs
# under, so it's the one whose dependency versions matter. It only qualifies
# if pytest is installed there; the venv is built from requirements.txt, which
# is runtime-only, so a fresh machine won't have it. System python is the
# fallback, and needs flask + pyyaml (which setup.sh installs system-wide too).
if [ -x "$VENV/bin/python3" ] && "$VENV/bin/python3" -c "import pytest" 2>/dev/null; then
    PY="$VENV/bin/python3"
    WHICH="app venv ($VENV)"
elif python3 -c "import pytest" 2>/dev/null; then
    PY=python3
    WHICH="system python3"
else
    echo "error: pytest isn't installed for either interpreter." >&2
    echo >&2
    echo "Install it into the app venv (preferred):" >&2
    echo "    sudo $VENV/bin/pip install pytest" >&2
    echo >&2
    echo "...or system-wide:" >&2
    echo "    sudo apt install python3-pytest" >&2
    exit 1
fi

# The tests import backend.* directly; conftest.py adds opt/proxygate to
# sys.path, so nothing needs installing as a package.
if ! "$PY" -c "import flask, yaml" 2>/dev/null; then
    echo "error: missing app dependencies (flask, pyyaml) for $WHICH." >&2
    echo "Run ./setup.sh first, or install them for that interpreter." >&2
    exit 1
fi

echo "Running ProxyGate tests with $WHICH"
echo

# No -v: conftest_report.py already replaces the progress dots with one
# readable line per test, grouped by area. Adding -v on top would print
# pytest's raw node id as well, duplicating every line.
#
# Pass -q for just the summary, or -v for the raw node ids (handy when you
# want to copy one back into `pytest` or `--lf`).
ARGS=("$@")

set +e
"$PY" -m pytest "${ARGS[@]}"
STATUS=$?
set -e

echo
if [ "$STATUS" -eq 0 ]; then
    echo "All tests passed."
elif [ "$STATUS" -eq 5 ]; then
    # pytest's "no tests collected" — usually a typo in a -k filter or path,
    # which is not the same as a green run and shouldn't look like one.
    echo "No tests ran — check the filter or path you passed."
else
    echo "Tests FAILED (pytest exit $STATUS)."
    echo "Re-run just the failures with:  ./run-tests.sh --lf -v"
fi
exit "$STATUS"
