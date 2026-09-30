"""
Host pattern matching for routing rules.

Two pattern styles, distinguished unambiguously by quoting:

    *.google.com              glob  — the original style, unchanged
    '^(www\\.)?google\\.com$'   regex — anything inside single quotes

The quotes matter. A regex like `.*\\.google\\.com` is *also* a valid glob (it
just wouldn't match anything useful), so guessing the style from the
characters present would silently change what existing rules do. Requiring
'...' means every pattern written before regex existed keeps its exact
meaning, and the intent is explicit in the rule itself. Single quotes are
also the one common regex character that never appears in a hostname, so
they can't collide with a real pattern the way "/" would.

Regexes are matched case-insensitively with re.search (not fullmatch), so
`google\\.com` finds the host anywhere in the string — anchor with ^ and $ when
you want the whole thing. Hostnames are lowercased before matching, matching
DNS semantics.

Long regexes are usually pasted from somewhere (chat, docs, a terminal), and
the paste brings damage with it: a line break or space where the source
wrapped the line, curly quotes that chat apps substitute for ', invisible
zero-width characters. Each one used to save without complaint and then
silently never match. The field is cleaned before it's split, because none of
that damage can be meaningful in a hostname pattern:

    - curly/prime quotes become ' and zero-width characters are dropped
    - whitespace INSIDE quotes is removed (no hostname contains whitespace,
      so it can only be a wrapped paste), rejoining the regex
    - whitespace OUTSIDE quotes separates patterns, like ";" and newlines

What cleaning can't repair — an unclosed quote, or an unquoted pattern using
regex syntax that a glob can never match — is rejected by validate_field()
at save time, with a message saying what to fix.

Shared by mitm_logger (the hot path, on every connection) and web.py (to
validate a pattern before it's saved), so the two can never disagree about
what a rule means.
"""
from __future__ import annotations

import fnmatch
import functools
import logging
import re
from typing import Optional

_log = logging.getLogger(__name__)

# Nested quantifiers: a quantified group that itself ends in a quantifier,
# e.g. (a+)+, (a*)*, (a+)*, (\d+){2,}. These are the classic catastrophic
# backtracking shapes — matching time grows exponentially with input length,
# so `(a+)+$` against a 40-character hostname runs effectively forever.
#
# This matters far more here than in most apps: rules are evaluated inside
# the mitmproxy addon on EVERY connection, so one such pattern doesn't slow
# a page down, it wedges the gateway for every device on the hotspot. Python
# has no regex timeout and no way to bound a match, so the only place to stop
# it is before it's saved.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]|\([^)]*[+*][^)]*\)\s*\{\d+,")


def _log_rejected_pattern(body: str) -> None:
    """Say why a rule silently stopped matching, once, where anyone looking
    at the mitmproxy log will see it."""
    if body in _rejected_logged:
        return
    _rejected_logged.add(body)
    _log.warning("[proxygate] refusing regex %r: nested quantifiers risk "
                 "catastrophic backtracking, which would stall every "
                 "connection. This rule will never match.", body)


_rejected_logged: set = set()


# Compiled regexes are cached: match() runs on every single connection, and
# re.compile on a cache miss is far more expensive than a dict lookup.
# Bounded so a rules file full of distinct patterns can't grow it without
# limit (each entry is small, but this is a long-lived process).
_MAX_CACHE = 512
_regex_cache: dict[str, Optional[re.Pattern]] = {}


def is_regex(pattern: str) -> bool:
    """True if `pattern` uses the 'regex' (single-quoted) form."""
    p = pattern.strip()
    # Needs both quotes plus at least one character of body.
    return len(p) >= 3 and p.startswith("'") and p.endswith("'")


def regex_body(pattern: str) -> str:
    """The expression inside the quotes, for a 'regex' pattern."""
    return pattern.strip()[1:-1]


def compile_pattern(pattern: str) -> Optional[re.Pattern]:
    """
    Compile a 'regex' pattern, or return None if it isn't valid.

    Returning None rather than raising keeps the caller on the hot path
    simple: an unparseable rule just never matches, instead of taking down
    routing for every subsequent connection.
    """
    body = regex_body(pattern)
    if body in _regex_cache:
        return _regex_cache[body]

    try:
        compiled = re.compile(body, re.IGNORECASE)
    except re.error:
        compiled = None

    # Second line of defence behind validate(). The API refuses to save a
    # pattern with nested quantifiers, but rules.yaml can also be edited by
    # hand — and this runs in the addon, where one such pattern would hang
    # every connection rather than just one request. Refusing to compile it
    # degrades to "this rule never matches", which is recoverable; a hung
    # gateway is not.
    if compiled is not None and _NESTED_QUANTIFIER_RE.search(body):
        _log_rejected_pattern(body)
        compiled = None

    if len(_regex_cache) >= _MAX_CACHE:
        _regex_cache.clear()
    _regex_cache[body] = compiled
    return compiled


def validate(pattern: str) -> Optional[str]:
    """
    Return an error message if `pattern` is unusable, else None.

    Used by the API so a typo'd regex is rejected while the user is looking
    at the dialog, rather than silently never matching later.
    """
    p = (pattern or "").strip()
    if not p:
        return "Pattern cannot be empty."
    # "''" is too short for is_regex (which needs a body), but it's clearly a
    # regex attempt rather than a hostname glob — catch it explicitly instead
    # of letting it fall through and silently match nothing.
    if p == "''":
        return "Empty regex — write something between the quotes."
    if not is_regex(p):
        return _validate_glob(p)
    body = regex_body(p)
    if not body:
        return "Empty regex — write something between the quotes."
    try:
        re.compile(body, re.IGNORECASE)
    except re.error as e:
        return f"Invalid regex: {e}"
    if _NESTED_QUANTIFIER_RE.search(body):
        return ("Regex rejected: nested quantifiers like (a+)+ can take "
                "exponential time to match and would stall every connection. "
                "Rewrite without a quantifier directly on a group that "
                "already contains one.")
    return None


def pattern_matches(pattern: str, host: str) -> bool:
    """
    True if `host` matches this single pattern (glob or 'regex').

    Never raises: a malformed pattern is treated as "doesn't match", so one
    bad rule can't break routing for everything after it.
    """
    if not pattern or not host:
        return False

    host = host.lower()
    pattern = pattern.strip()

    if is_regex(pattern):
        compiled = compile_pattern(pattern)
        return bool(compiled and compiled.search(host))

    # Glob, unchanged from the original behaviour. The lstrip fallback is what
    # makes "*.example.com" also match the apex "example.com" — without it the
    # obvious pattern would miss the bare domain, which surprises everyone.
    pattern = pattern.lower()
    return fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(host, pattern.lstrip("*."))


# Characters that arrive with a pasted pattern but can't be what was meant.
# Chat apps, word processors and macOS "smart quotes" swap ' for a curly or
# prime lookalike, which silently turned a regex into a glob. Zero-width
# characters come along with copies out of web pages and are invisible in
# the textarea, but make a pattern that looks right never match.
_PASTE_CLEANUP = str.maketrans({
    "‘": "'", "’": "'", "‚": "'", "‛": "'",   # ‘ ’ ‚ ‛
    "′": "'", "´": "'",                                 # ′ ´
    "​": None, "‌": None, "‍": None,               # zero-width
    "⁠": None, "﻿": None,                               # word joiner, BOM
})

# In a glob, only * ? [ ] ! have special meaning. These are regex syntax that
# no hostname contains, so an unquoted pattern using them can never match —
# it's a regex that's missing its quotes.
_REGEX_ONLY_CHARS = set("()|^$\\+{}")


def _validate_glob(p: str) -> Optional[str]:
    if "'" in p:
        return (f"Stray quote in {p!r}. A regex must be wrapped in single quotes "
                f"from start to end, like '^api\\.example\\.com$'.")
    if "/" in p:
        return (f"{p!r} looks like a URL. Rules match the hostname only — "
                f"drop the scheme and path, e.g. example.com.")
    if _REGEX_ONLY_CHARS & set(p):
        return (f"{p!r} uses regex syntax but isn't in single quotes, so it would "
                f"be treated as a wildcard pattern and never match. "
                f"Wrap it in quotes: '{p}'")
    return None


@functools.lru_cache(maxsize=1024)
def _parse(raw: str) -> tuple[tuple[str, ...], bool]:
    """
    Clean and split a rule's pattern field. Returns (patterns, balanced).

    Cached because this runs for every rule on every connection, and a
    rule's field is the same string every time.
    """
    text = raw.translate(_PASTE_CLEANUP)
    out: list[str] = []
    buf: list[str] = []
    in_quotes = False

    for ch in text:
        if ch == "'":
            in_quotes = not in_quotes
            buf.append(ch)
        elif in_quotes:
            # Separators inside quotes belong to the regex (a ';' in a
            # character class), but whitespace can't: it's where the source
            # wrapped the line, so dropping it rejoins the regex.
            if not ch.isspace():
                buf.append(ch)
        elif ch == ";" or ch.isspace():
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))

    return tuple(p for p in out if p), not in_quotes


def split_patterns(raw: str) -> list[str]:
    """
    Split a rule's pattern field into individual, cleaned patterns.

    Newlines, ";" and spaces all separate — but anything *inside* quotes
    belongs to the regex, so '[a-z;]+\\.com' survives intact, and a regex
    broken across lines by a paste is joined back together (see the module
    docstring for the full cleanup).
    """
    patterns, balanced = _parse(raw or "")
    if not balanced:
        _log_unbalanced(raw)
    return list(patterns)


def _log_unbalanced(raw: str) -> None:
    if raw in _unbalanced_logged:
        return
    _unbalanced_logged.add(raw)
    _log.warning("[proxygate] rule pattern %r has an unclosed quote; everything "
                 "after it is read as one pattern and will not match.", raw)


_unbalanced_logged: set = set()


def validate_field(raw: str) -> Optional[str]:
    """
    Return an error message if a rule's whole pattern field is unusable,
    else None. This is what the API checks before saving.
    """
    patterns, balanced = _parse(raw or "")
    if not balanced:
        return ("Unclosed quote: a regex must start and end with a single "
                "quote ('). Everything after the unclosed one would be read "
                "as a single pattern.")
    if not patterns:
        return "Pattern cannot be empty."
    for i, p in enumerate(patterns, 1):
        err = validate(p)
        if err:
            return f"Pattern {i}: {err}" if len(patterns) > 1 else err
    return None


def clean_field(raw: str) -> str:
    """
    The canonical stored form of a pattern field: cleaned patterns, one per
    line. Saving this rather than the raw paste means rules.yaml and the edit
    dialog show exactly what will be matched.
    """
    return "\n".join(split_patterns(raw))


def matches_any(raw: str, host: str) -> bool:
    """True if `host` matches any pattern in a rule's pattern field."""
    return any(pattern_matches(p, host) for p in split_patterns(raw))
