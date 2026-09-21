"""
Rule matching (mitm_logger.RulesEngine.match).

This decides which upstream proxy every connection uses, so a mistake here
silently misroutes traffic rather than failing loudly — the case most worth
pinning down.
"""
import pytest

from backend import mitm_logger as ml


def engine(rules, default="DIRECT", proxies=None):
    """A RulesEngine with its file loading bypassed."""
    eng = ml.RulesEngine.__new__(ml.RulesEngine)
    import threading
    eng._lock = threading.RLock()
    eng.rules = rules
    eng.proxies = proxies or {}
    eng.default = default
    return eng


def rule(name, pattern, proxy="XVPN", enabled=True):
    return {"name": name, "pattern": pattern, "proxy": proxy, "enabled": enabled}


# ── the shipped defaults ──────────────────────────────────────────────────────

@pytest.fixture
def default_rules():
    """The two rules a fresh install ships with."""
    return engine([
        rule("IP Info", "*.ipinfo.io"),
        rule("Google", "google.com"),
    ])


@pytest.mark.parametrize("host,expected_rule", [
    ("ipinfo.io", "IP Info"),          # bare domain via the *. lstrip fallback
    ("api.ipinfo.io", "IP Info"),
    ("v4.api.ipinfo.io", "IP Info"),
    ("google.com", "Google"),
])
def test_default_rules_match(default_rules, host, expected_rule):
    name, target = default_rules.match(host)
    assert name == expected_rule
    assert target == "XVPN"


@pytest.mark.parametrize("host", [
    "example.com",
    "notgoogle.com",
    "ipinfo.io.evil.com",
    "www.google.com",   # 'google.com' is exact — no implicit subdomain match
])
def test_unmatched_hosts_fall_through(default_rules, host):
    assert default_rules.match(host) == ("default", "DIRECT")


# ── pattern semantics ─────────────────────────────────────────────────────────

def test_wildcard_matches_bare_domain():
    """
    '*.example.com' also matches 'example.com' via the lstrip("*.") fallback —
    otherwise the obvious pattern would miss the apex domain.
    """
    eng = engine([rule("R", "*.example.com")])
    assert eng.match("example.com")[0] == "R"
    assert eng.match("a.example.com")[0] == "R"
    assert eng.match("a.b.example.com")[0] == "R"


@pytest.mark.parametrize("sep", [";", "\n"])
def test_multiple_patterns_per_rule(sep):
    eng = engine([rule("Multi", f"*.foo.com{sep}*.bar.com")])
    assert eng.match("a.foo.com")[0] == "Multi"
    assert eng.match("a.bar.com")[0] == "Multi"
    assert eng.match("a.baz.com")[0] == "default"


def test_whitespace_around_patterns_is_ignored():
    eng = engine([rule("R", "  *.foo.com  ;  *.bar.com  ")])
    assert eng.match("a.foo.com")[0] == "R"
    assert eng.match("a.bar.com")[0] == "R"


def test_empty_patterns_are_skipped():
    """A trailing ';' must not produce an empty pattern that matches all."""
    eng = engine([rule("R", "*.foo.com;;")])
    assert eng.match("anything.com")[0] == "default"


# ── regex patterns (single-quoted) ────────────────────────────────────────────

def test_regex_rule_matches():
    eng = engine([rule("Regex", r"'^cdn\d+\.example\.com$'", proxy="CGVPN")])
    assert eng.match("cdn42.example.com") == ("Regex", "CGVPN")
    assert eng.match("cdnx.example.com") == ("default", "DIRECT")


def test_rule_can_mix_globs_and_regexes():
    eng = engine([rule("Mixed", "*.foo.com;'\\d'")])
    assert eng.match("a.foo.com")[0] == "Mixed"
    assert eng.match("cdn7.bar.com")[0] == "Mixed"
    assert eng.match("plain.bar.com")[0] == "default"


def test_broken_regex_does_not_break_routing():
    """An invalid pattern must not stop later rules from being evaluated."""
    eng = engine([
        rule("Broken", "'[unclosed'", proxy="XVPN"),
        rule("Good", "*.example.com", proxy="CGVPN"),
    ])
    assert eng.match("a.example.com") == ("Good", "CGVPN")


def test_regex_with_semicolon_survives_rule_splitting():
    eng = engine([rule("Semi", r"'^[a-z;]+\.com$'")])
    assert eng.match("abc.com")[0] == "Semi"


# ── precedence and enablement ─────────────────────────────────────────────────

def test_first_matching_rule_wins():
    eng = engine([
        rule("First", "*.example.com", proxy="XVPN"),
        rule("Second", "*.example.com", proxy="CGVPN"),
    ])
    assert eng.match("a.example.com") == ("First", "XVPN")


def test_disabled_rules_are_skipped():
    eng = engine([
        rule("Off", "*.example.com", proxy="XVPN", enabled=False),
        rule("On", "*.example.com", proxy="CGVPN"),
    ])
    assert eng.match("a.example.com") == ("On", "CGVPN")


def test_all_disabled_falls_through_to_default():
    eng = engine([rule("Off", "*.example.com", enabled=False)], default="PIAVPN")
    assert eng.match("a.example.com") == ("default", "PIAVPN")


def test_rule_without_enabled_key_defaults_to_on():
    eng = engine([{"name": "R", "pattern": "*.example.com", "proxy": "XVPN"}])
    assert eng.match("a.example.com")[0] == "R"


# ── targets ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("default", ["DIRECT", "BLOCK", "XVPN"])
def test_default_target_is_returned_unmatched(default):
    eng = engine([], default=default)
    assert eng.match("anything.com") == ("default", default)


def test_block_target_on_a_rule():
    eng = engine([rule("Blocked", "*.ads.com", proxy="BLOCK")])
    assert eng.match("x.ads.com") == ("Blocked", "BLOCK")


# ── resolve_proxy ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target", ["DIRECT", "BLOCK", "", None])
def test_pseudo_targets_resolve_to_no_proxy(target):
    eng = engine([], proxies={"XVPN": {"host": "127.0.0.1", "port": 8893}})
    assert eng.resolve_proxy(target) is None


def test_unknown_proxy_name_resolves_to_none():
    """A rule pointing at a deleted proxy must not raise — it goes direct."""
    eng = engine([], proxies={"XVPN": {"host": "127.0.0.1", "port": 8893}})
    assert eng.resolve_proxy("GHOST") is None


def test_known_proxy_resolves():
    cfg = {"host": "127.0.0.1", "port": 8893}
    eng = engine([], proxies={"XVPN": cfg})
    assert eng.resolve_proxy("XVPN") == cfg
