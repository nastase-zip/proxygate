"""
Host pattern matching (backend/patterns.py) — globs and 'regex' patterns.

The single most important property here is that adding regex support did not
change what any pre-existing glob pattern means, since those are already in
users' rules.yaml files and silently re-interpreting one would misroute live
traffic.
"""
import pytest

from backend.patterns import (
    is_regex,
    matches_any,
    pattern_matches,
    split_patterns,
    validate,
)


# ── globs must behave exactly as before ───────────────────────────────────────

@pytest.mark.parametrize("pattern,host,expected", [
    ("*.ipinfo.io", "api.ipinfo.io", True),
    ("*.ipinfo.io", "v4.api.ipinfo.io", True),
    # The lstrip("*.") fallback: "*.x.com" must also match the apex "x.com".
    ("*.ipinfo.io", "ipinfo.io", True),
    ("*.ipinfo.io", "notipinfo.io", False),
    ("google.com", "google.com", True),
    # Exact patterns stay exact — no implicit subdomain matching.
    ("google.com", "www.google.com", False),
    ("*.foo.com", "a.bar.com", False),
    ("*", "anything.com", True),
])
def test_glob_behaviour_unchanged(pattern, host, expected):
    assert pattern_matches(pattern, host) is expected


def test_globs_are_case_insensitive():
    assert pattern_matches("*.GOOGLE.com", "www.google.com") is True
    assert pattern_matches("*.google.com", "WWW.GOOGLE.COM") is True


# ── regex form ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pattern", ["'^a$'", "'x'", "'\\d+'"])
def test_is_regex_detects_quoted(pattern):
    assert is_regex(pattern) is True


@pytest.mark.parametrize("pattern", ["*.google.com", "google.com", "'", "''", ""])
def test_is_regex_rejects_non_regex(pattern):
    assert is_regex(pattern) is False


@pytest.mark.parametrize("pattern,host,expected", [
    (r"'^google\.com$'", "google.com", True),
    (r"'^google\.com$'", "www.google.com", False),
    (r"'^(www\.)?google\.com$'", "www.google.com", True),
    (r"'^(www\.)?google\.com$'", "google.com", True),
    # \d — the case from the feature request.
    (r"'\d'", "cdn3.example.com", True),
    (r"'\d'", "cdn.example.com", False),
    (r"'^cdn\d+\.example\.com$'", "cdn42.example.com", True),
    (r"'^cdn\d+\.example\.com$'", "cdnx.example.com", False),
    # Alternation and unanchored search.
    (r"'(googlevideo|ytimg)\.com$'", "r1.googlevideo.com", True),
    (r"'(googlevideo|ytimg)\.com$'", "i.ytimg.com", True),
    (r"'(googlevideo|ytimg)\.com$'", "example.com", False),
])
def test_regex_matching(pattern, host, expected):
    assert pattern_matches(pattern, host) is expected


def test_regex_is_case_insensitive():
    assert pattern_matches("'GOOGLE'", "google.com") is True


def test_regex_searches_rather_than_fullmatches():
    """Unanchored patterns find the substring anywhere."""
    assert pattern_matches("'google'", "www.google.com") is True
    assert pattern_matches("'^google'", "www.google.com") is False


@pytest.mark.parametrize("bad", ["'[unclosed'", "'*invalid'", "'(unbalanced'"])
def test_invalid_regex_never_matches_and_never_raises(bad):
    """
    A malformed pattern must fail closed. Raising here would abort routing
    for every connection that reached this rule.
    """
    assert pattern_matches(bad, "anything.com") is False


def test_regex_cannot_be_confused_with_a_glob():
    """
    An unquoted regex-looking string is still treated as a glob, so existing
    rules can't change meaning. '.*' as a glob matches nothing real.
    """
    assert pattern_matches(r".*\.google\.com", "www.google.com") is False


# ── splitting ─────────────────────────────────────────────────────────────────

def test_split_on_semicolons_and_newlines():
    assert split_patterns("*.a.com;*.b.com") == ["*.a.com", "*.b.com"]
    assert split_patterns("*.a.com\n*.b.com") == ["*.a.com", "*.b.com"]


def test_split_ignores_empty_fragments():
    assert split_patterns("*.a.com;;\n\n*.b.com;") == ["*.a.com", "*.b.com"]


def test_semicolon_inside_a_regex_is_not_a_separator():
    """A quoted regex containing ';' must survive splitting intact."""
    assert split_patterns(r"*.a.com;'[a-z;]+\.com';*.b.com") == [
        "*.a.com", r"'[a-z;]+\.com'", "*.b.com",
    ]


def test_newline_inside_a_regex_is_not_a_separator():
    assert split_patterns("'a\nb'") == ["'a\nb'"]


def test_braces_in_regex_survive_splitting():
    assert split_patterns(r"'\d{1,3}'") == [r"'\d{1,3}'"]


# ── matches_any (what a whole rule does) ──────────────────────────────────────

def test_matches_any_mixes_globs_and_regexes():
    raw = "*.ipinfo.io\n'^cdn\\d+\\.example\\.com$'"
    assert matches_any(raw, "api.ipinfo.io") is True
    assert matches_any(raw, "cdn7.example.com") is True
    assert matches_any(raw, "other.com") is False


def test_matches_any_on_empty_is_false():
    assert matches_any("", "example.com") is False
    assert matches_any(None, "example.com") is False


def test_one_broken_pattern_does_not_disable_the_others():
    """A typo in one pattern must not stop the rest of the rule working."""
    raw = "'[broken';*.good.com"
    assert matches_any(raw, "a.good.com") is True


# ── validation (what the API rejects) ─────────────────────────────────────────

@pytest.mark.parametrize("pattern", ["*.google.com", "google.com", r"'^ok$'", r"'\d+'"])
def test_valid_patterns_pass(pattern):
    assert validate(pattern) is None


@pytest.mark.parametrize("pattern,fragment", [
    ("", "empty"),
    ("   ", "empty"),
    ("''", "Empty regex"),
    ("'[bad'", "Invalid regex"),
    ("'(unbalanced'", "Invalid regex"),
])
def test_invalid_patterns_are_rejected_with_a_message(pattern, fragment):
    err = validate(pattern)
    assert err is not None
    assert fragment.lower() in err.lower()


# ── edge cases ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", ["", None])
def test_empty_host_never_matches(host):
    assert pattern_matches("*", host) is False


def test_whitespace_around_patterns_is_ignored():
    assert pattern_matches("  *.google.com  ", "www.google.com") is True
    assert pattern_matches("  '^google\\.com$'  ", "google.com") is True


# ── ReDoS defence ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("evil", [
    "'(a+)+$'",
    "'(a*)*b'",
    r"'(\d+)+x'",
    "'(a+)*'",
    "'([a-z]+)+$'",
])
def test_nested_quantifiers_are_rejected(evil):
    """
    Catastrophic backtracking is uniquely dangerous here: rules run inside
    the addon on every connection, so one such pattern wedges the gateway
    for every device, not just one request. `'(a+)+$'` against a 60-char
    host ran for over 60s before this guard.
    """
    assert validate(evil) is not None
    assert "nested quantifiers" in validate(evil).lower()


@pytest.mark.parametrize("evil", ["'(a+)+$'", "'([a-z]+)+$'"])
def test_nested_quantifiers_never_match_at_runtime(evil):
    """
    Second line of defence: rules.yaml can be hand-edited past validate(),
    so the matcher itself must refuse to compile these rather than hang.
    """
    import time
    start = time.perf_counter()
    assert pattern_matches(evil, "a" * 60 + "!") is False
    assert time.perf_counter() - start < 1.0, "pattern was not short-circuited"


@pytest.mark.parametrize("good", [
    r"'^cdn\d+\.example\.com$'",
    r"'^(www\.)?google\.com$'",
    r"'(googlevideo|ytimg)\.com$'",
    r"'\d{1,3}'",
    "'^a+$'",
    r"'^[a-z]+\.com$'",
])
def test_ordinary_regexes_are_not_false_positives(good):
    """The guard must not reject the patterns people actually write."""
    assert validate(good) is None
