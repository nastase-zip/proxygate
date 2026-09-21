"""
Readable console output for the test run.

pytest -v prints `tests/test_api.py::test_add_rule_rejects_a_broken_regex[...]`,
which is precise but hard to skim. The point of running these by hand is to
see what the suite actually covers, so this rewrites each line into a plain
sentence grouped under a heading per file.

Opt-out: PG_PLAIN_TEST_OUTPUT=1 keeps pytest's own format (useful when you
want the exact node id to pass back to `pytest` or `--lf`).
"""
import os

# Human titles for each test module, in the order the run should read.
_FILE_TITLES = {
    "test_patterns.py":          "Host pattern matching (globs, regexes, ReDoS defence)",
    "test_rule_matching.py":     "Rule engine: which proxy a hostname routes to",
    "test_rules_persistence.py": "rules.yaml: load, save, CRUD, corruption recovery",
    "test_api.py":               "HTTP API contract",
    "test_devices.py":           "Hotspot device discovery",
    "test_traffic_filter.py":    "Traffic filter: whose traffic gets logged",
    "test_db.py":                "Traffic database queries",
    "test_history_query.py":     "Traffic history window",
    "test_decrypt_gate.py":      "TLS decryption gating (per-device, circuit breaker)",
    "test_settings_api.py":      "Settings API validation",
    "test_mac_validation.py":    "MAC address validation (blocked / decrypt lists)",
}

_seen_files = set()


def _sentence(nodeid: str) -> str:
    """`test_add_rule_rejects_a_broken_regex[x]` -> `add rule rejects a broken regex [x]`."""
    name = nodeid.split("::", 1)[-1]
    param = ""
    if "[" in name:
        name, _, rest = name.partition("[")
        param = " [" + rest.rstrip("]") + "]"
    if name.startswith("test_"):
        name = name[5:]
    return name.replace("_", " ") + param


def _disabled(config) -> bool:
    """Stand down when the caller explicitly asked for pytest's own format:
    -v/-q both mean "I want the standard output", and doubling up would print
    each test twice."""
    if os.environ.get("PG_PLAIN_TEST_OUTPUT"):
        return True
    return config.getoption("verbose", 0) != 0


def pytest_report_teststatus(report, config):
    if _disabled(config):
        return None
    if report.when != "call" and not (report.when == "setup" and report.skipped):
        return None

    # The SHORT field is what pytest prints without -v (normally one char).
    # Putting the sentence there, newline-prefixed, gives one readable line
    # per test; the long field is what -v would use, and -v disables us.
    line = _sentence(report.nodeid)
    if report.passed:
        return "passed", f"  ok    {line}\n", ("PASSED", {"green": True})
    if report.failed:
        return "failed", f"  FAIL  {line}\n", ("FAILED", {"red": True})
    if report.skipped:
        return "skipped", f"  skip  {line}\n", ("SKIPPED", {"yellow": True})
    return None


def pytest_runtest_logstart(nodeid, location):
    """Print a heading the first time a test from a new file runs."""
    if _headings_off:
        return
    fname = nodeid.split("::", 1)[0].split("/")[-1]
    if fname in _seen_files:
        return
    _seen_files.add(fname)
    title = _FILE_TITLES.get(fname, fname)
    print(f"\n\033[1m── {title} \033[0m")


_headings_off = False


def pytest_configure(config):
    global _headings_off
    _headings_off = _disabled(config)
