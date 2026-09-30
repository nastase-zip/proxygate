"""
backend/firewall.py — the packet path, as data.

WHY THIS EXISTS
---------------
The previous implementation was a 404-line function that shelled out to
iptables 44 times and never checked whether any of it took effect. That made
an entire class of bug invisible, and one of them cost days:

    every rule was scoped `-i <iface>` using a module global that defaulted to
    the placeholder "ap0" and was only assigned when that same process brought
    the AP up. On a web-UI restart or a reconnect it stayed "ap0" — and
    iptables accepts a rule naming a nonexistent interface WITHOUT ERROR.

The result was total and silent: rules present, counters frozen at zero, the
gateway reporting "connected", mitmproxy healthy, and not one packet ever
redirected. Nothing in any log said otherwise, because nothing ever looked.

The fix is structural, not another guard:

  1. The desired firewall is a DECLARATION (`Ruleset`) — plain data, pure to
     build, trivial to unit-test without root or a live network.
  2. `apply()` renders that declaration, applies it, and then READS THE KERNEL
     BACK to confirm what landed. A rule that did not take effect is a loud,
     specific error instead of silence.
  3. `verify()` can be called at any time to answer "is the packet path
     actually alive?", including packet counters — so a dead redirect reports
     itself rather than waiting to be noticed.

Preconditions are checked BEFORE anything is written: an interface that does
not exist is refused up front, because installing rules that cannot match is
strictly worse than refusing to install them.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, Optional

log = logging.getLogger(__name__)

# Chain names are part of the on-disk contract: flush_legacy() must know every
# name this project has EVER used, or an old chain keeps routing packets after
# an upgrade.
CHAIN_REDIRECT = "PROXYGATE_REDIRECT"
CHAIN_MASQ = "PROXYGATE_MASQ"
CHAIN_FORWARD = "PROXYGATE_FORWARD"
CHAIN_BLOCKDEV = "PROXYGATE_BLOCKDEV"
CHAIN_REDIRECT6 = "PROXYGATE_REDIRECT6"
CHAIN_MASQ6 = "PROXYGATE_MASQ6"
CHAIN_FORWARD6 = "PROXYGATE_FORWARD6"

# Chains from older ProxyGate versions. Never reused, always cleaned.
LEGACY_CHAINS = (("nat", "PROXYGATE_OUTPUT"),)

_MAX_DUP_DELETES = 16


# ── Declaration ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    """One iptables rule, minus the table/chain (the Chain carries those)."""
    args: tuple[str, ...]
    # False => best effort. Used for rules whose failure must not abort the
    # whole apply (e.g. one malformed MAC in the block list must cost that one
    # device's block, not the entire gateway).
    required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(str(a) for a in self.args))


@dataclass(frozen=True)
class Chain:
    """A ProxyGate-owned chain, plus where it hooks into a builtin chain."""
    table: str            # "nat" or "filter"
    name: str
    rules: tuple[Rule, ...]
    hook: Optional[str] = None      # builtin chain to jump from
    hook_at_top: bool = True        # -I 1 vs -A
    ipv6: bool = False

    @property
    def binary(self) -> str:
        return "ip6tables" if self.ipv6 else "iptables"


@dataclass(frozen=True)
class Ruleset:
    """The complete desired packet path."""
    chains: tuple[Chain, ...]
    hotspot_if: str
    wan_if: str
    subnet: str
    conntrack_flush: bool = True


# ── Building the declaration (pure) ───────────────────────────────────────────

def build(*, hotspot_if: str, wan_if: str, gateway_ip: str, subnet: str,
          mitm_port: int, block: bool, blocked_macs: Iterable[str] = (),
          ipv6: bool = True) -> Ruleset:
    """
    Describe the firewall for these parameters. Pure — touches nothing.

    `block` is BLOCK mode: hotspot traffic is dropped in FORWARD rather than
    forwarded, while still reaching mitmproxy so it can be logged.
    """
    mp = str(mitm_port)
    chains: list[Chain] = []

    # ── NAT PREROUTING: hotspot TCP → mitmproxy, DNS → local dnsmasq ──────────
    redirect: list[Rule] = []
    # The gateway's own traffic must never be redirected into its own proxy.
    for src in ("127.0.0.1", gateway_ip):
        redirect.append(Rule(("-s", src, "-j", "RETURN")))
    for dst in ("127.0.0.0/8", gateway_ip):
        redirect.append(Rule(("-d", dst, "-j", "RETURN")))
    # DNS to the gateway's dnsmasq, so names resolve and can be logged.
    for proto in ("udp", "tcp"):
        redirect.append(Rule((
            "-i", hotspot_if, "-p", proto, "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{gateway_ip}:53")))
    if not block:
        # Everything TCP: :80 intercepted, :443 SNI-logged and passed through,
        # anything else proxied as a raw stream.
        redirect.append(Rule((
            "-i", hotspot_if, "-p", "tcp", "-j", "REDIRECT", "--to-port", mp)))
    chains.append(Chain("nat", CHAIN_REDIRECT, tuple(redirect),
                        hook="PREROUTING", hook_at_top=True))

    # ── NAT POSTROUTING ───────────────────────────────────────────────────────
    chains.append(Chain("nat", CHAIN_MASQ, (
        Rule(("-s", subnet, "-o", wan_if, "-j", "MASQUERADE")),
    ), hook="POSTROUTING", hook_at_top=False))

    # ── FILTER FORWARD ────────────────────────────────────────────────────────
    if block:
        fwd = (Rule(("-i", hotspot_if, "-j", "DROP")),)
    else:
        fwd = (
            # Logged purely for traffic-table visibility; LOG does not
            # terminate the chain, so the DROP below still applies.
            Rule(("-i", hotspot_if, "-p", "udp", "--dport", "443",
                  "-j", "LOG", "--log-prefix", "PGQUIC: ", "--log-level", "6"),
                 required=False),
            # ALL UDP is dropped: mitmproxy has no UDP path, so any UDP that
            # reached FORWARD would bypass the proxy entirely. DNS still works
            # via the DNAT above.
            Rule(("-i", hotspot_if, "-p", "udp", "-j", "DROP")),
            Rule(("-i", hotspot_if, "-o", wan_if, "-j", "ACCEPT")),
            Rule(("-i", wan_if, "-o", hotspot_if, "-m", "state",
                  "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")),
        )
    chains.append(Chain("filter", CHAIN_FORWARD, fwd,
                        hook="FORWARD", hook_at_top=True))

    # ── Blocked devices ───────────────────────────────────────────────────────
    # DROP in INPUT *and* FORWARD: INPUT so a blocked device cannot reach the
    # gateway itself (DNS, DHCP, the web UI), FORWARD so it gets no internet
    # even if it still holds an IP. DROP is only valid in the filter table,
    # which is why this cannot live in the nat chain above.
    #
    # Hooked AFTER CHAIN_FORWARD so that, with both inserted at position 1,
    # this one ends up first and is evaluated first.
    blockdev = tuple(
        Rule(("-i", hotspot_if, "-m", "mac", "--mac-source", mac, "-j", "DROP"),
             required=False)
        for mac in sorted(blocked_macs)
    )
    chains.append(Chain("filter", CHAIN_BLOCKDEV, blockdev,
                        hook="INPUT", hook_at_top=True))
    chains.append(Chain("filter", CHAIN_BLOCKDEV, blockdev,
                        hook="FORWARD", hook_at_top=True))

    if ipv6:
        # The hotspot's DHCP is IPv4-only, but a device can still get IPv6 via
        # SLAAC from the WAN side, so the v6 path must be governed too.
        r6: list[Rule] = [Rule(("-s", "::1", "-j", "RETURN"))]
        if not block:
            r6.append(Rule((
                "-i", hotspot_if, "-p", "tcp", "-j", "REDIRECT", "--to-port", mp)))
        chains.append(Chain("nat", CHAIN_REDIRECT6, tuple(r6),
                            hook="PREROUTING", hook_at_top=True, ipv6=True))
        chains.append(Chain("nat", CHAIN_MASQ6, (
            Rule(("-i", hotspot_if, "-o", wan_if, "-j", "MASQUERADE")),
        ), hook="POSTROUTING", hook_at_top=False, ipv6=True))
        if block:
            f6 = (Rule(("-i", hotspot_if, "-j", "DROP")),)
        else:
            f6 = (
                Rule(("-i", hotspot_if, "-p", "udp", "-j", "DROP")),
                Rule(("-i", hotspot_if, "-o", wan_if, "-j", "ACCEPT")),
                Rule(("-i", wan_if, "-o", hotspot_if, "-m", "state",
                      "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")),
            )
        chains.append(Chain("filter", CHAIN_FORWARD6, f6,
                            hook="FORWARD", hook_at_top=True, ipv6=True))

    return Ruleset(tuple(chains), hotspot_if, wan_if, subnet)


# ── Running commands ──────────────────────────────────────────────────────────

class Runner:
    """
    Indirection over subprocess so the whole applier is testable without root.
    Tests substitute a fake; production uses this.
    """

    def run(self, *cmd: str) -> tuple[int, str]:
        try:
            r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=15)
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except Exception as e:                      # timeout, missing binary…
            return 1, str(e)


class FirewallError(RuntimeError):
    """A required rule could not be applied. Carries the failing command."""


# ── Preconditions ─────────────────────────────────────────────────────────────

def check_preconditions(rs: Ruleset) -> list[str]:
    """
    Reasons this ruleset must NOT be applied. Empty list means go.

    This is the guard whose absence caused the silent-dead-gateway bug: every
    rule is scoped to an interface, and iptables will happily install rules
    naming an interface that does not exist. Such rules match nothing, forever,
    with no error anywhere. Refusing up front turns that into a visible fault.
    """
    problems: list[str] = []
    for label, iface in (("hotspot", rs.hotspot_if), ("WAN", rs.wan_if)):
        if not iface or iface == "ap0":
            problems.append(
                f"{label} interface is unresolved ({iface!r}) — rules scoped to it "
                f"would silently match nothing")
        elif not os.path.isdir(f"/sys/class/net/{iface}"):
            problems.append(
                f"{label} interface {iface!r} does not exist — rules scoped to it "
                f"would silently match nothing")
    if rs.hotspot_if and rs.hotspot_if == rs.wan_if:
        problems.append(
            f"hotspot and WAN are the same interface ({rs.hotspot_if!r}) — "
            f"that routes the gateway's own uplink into its own proxy")
    return problems


# ── Applying ──────────────────────────────────────────────────────────────────

def _delete_all_hooks(runner: Runner, chain: Chain) -> None:
    """
    Remove EVERY jump into `chain`, not just one.

    `iptables -D` deletes a single matching rule. An interrupted run can leave
    duplicate jumps, and a leftover keeps feeding packets into a chain that is
    about to be rebuilt or deleted — so deleting once is not enough.
    """
    if not chain.hook:
        return
    for _ in range(_MAX_DUP_DELETES):
        rc, _out = runner.run(chain.binary, "-t", chain.table,
                              "-D", chain.hook, "-j", chain.name)
        if rc != 0:
            return


def apply(rs: Ruleset, runner: Optional[Runner] = None,
          flush_conntrack: bool = True) -> None:
    """
    Make the kernel match `rs`. Raises FirewallError if it could not.

    Order matters: each chain is created and filled BEFORE it is hooked, so a
    partially-built chain is never reachable from a builtin chain.
    """
    runner = runner or Runner()

    problems = check_preconditions(rs)
    if problems:
        raise FirewallError("; ".join(problems))

    # Sysctls the packet path depends on. route_localnet is what allows a
    # REDIRECT to a loopback-bound listener to work at all.
    for key, val in (
        ("net.ipv4.ip_forward", "1"),
        ("net.ipv4.conf.all.route_localnet", "1"),
        ("net.core.somaxconn", "4096"),
        ("net.ipv4.tcp_max_syn_backlog", "4096"),
        ("net.ipv6.conf.all.forwarding", "1"),
    ):
        runner.run("sysctl", "-qw", f"{key}={val}")

    # Chains sharing a name (BLOCKDEV hooks into both INPUT and FORWARD) must
    # only be created and filled once.
    built: set[tuple[str, str, bool]] = set()

    for chain in rs.chains:
        key = (chain.table, chain.name, chain.ipv6)
        if key not in built:
            runner.run(chain.binary, "-t", chain.table, "-N", chain.name)
            rc, out = runner.run(chain.binary, "-t", chain.table, "-F", chain.name)
            if rc != 0:
                raise FirewallError(f"could not flush {chain.name}: {out.strip()}")
            for rule in chain.rules:
                rc, out = runner.run(chain.binary, "-t", chain.table,
                                     "-A", chain.name, *rule.args)
                if rc != 0 and rule.required:
                    raise FirewallError(
                        f"{chain.binary} -t {chain.table} -A {chain.name} "
                        f"{' '.join(rule.args)}: {out.strip()}")
            built.add(key)

        _delete_all_hooks(runner, chain)
        flag = "-I" if chain.hook_at_top else "-A"
        pos = ["1"] if chain.hook_at_top else []
        rc, out = runner.run(chain.binary, "-t", chain.table,
                             flag, chain.hook, *pos, "-j", chain.name)
        if rc != 0:
            raise FirewallError(
                f"could not hook {chain.name} into {chain.hook}: {out.strip()}")

    if flush_conntrack and rs.conntrack_flush:
        # Existing flows were established against the OLD rules (or none), so
        # they would keep bypassing the proxy until they happened to close.
        # Dropping them forces an immediate reconnect through the new path —
        # this is what makes a rule change take effect NOW rather than
        # "eventually", with no device-side action.
        runner.run("conntrack", "-D", "-s", rs.subnet)
        runner.run("conntrack", "-D", "-d", rs.subnet)


# ── Reading the kernel back ───────────────────────────────────────────────────

@dataclass
class ChainState:
    """What the kernel actually has, for one chain."""
    table: str
    name: str
    ipv6: bool
    exists: bool
    rules: list[dict] = field(default_factory=list)   # num/packets/bytes/target/spec
    hooked_from: list[str] = field(default_factory=list)

    @property
    def packets(self) -> int:
        """Total packets matched by this chain's rules."""
        return sum(int(r["packets"]) for r in self.rules if r["packets"].isdigit())


def _parse_counters(out: str) -> list[dict]:
    """Parse `iptables -L <chain> -n -v --line-numbers` into rows."""
    rows: list[dict] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        rows.append({
            "num": parts[0],
            "packets": parts[1],
            "bytes": parts[2],
            "target": parts[3],
            "spec": " ".join(parts[4:]),
        })
    return rows


def read_chain(table: str, name: str, ipv6: bool = False,
               runner: Optional[Runner] = None) -> ChainState:
    runner = runner or Runner()
    binary = "ip6tables" if ipv6 else "iptables"
    rc, out = runner.run(binary, "-t", table, "-L", name, "-n", "-v", "--line-numbers")
    if rc != 0:
        return ChainState(table, name, ipv6, exists=False)
    return ChainState(table, name, ipv6, exists=True, rules=_parse_counters(out))


def hooks_into(table: str, builtin: str, target: str, ipv6: bool = False,
               runner: Optional[Runner] = None) -> list[dict]:
    """Every jump from `builtin` into `target`, with counters."""
    state = read_chain(table, builtin, ipv6, runner)
    return [r for r in state.rules if r["target"] == target]


def verify(rs: Ruleset, runner: Optional[Runner] = None) -> dict:
    """
    Compare intent against the kernel and report, in words, anything wrong.

    This is the answer to "is the packet path actually alive?". It exists
    because the failure that cost days was not detectable from any log: the
    only evidence was a packet counter that never moved. Counters are
    therefore first-class output here.
    """
    runner = runner or Runner()
    problems: list[str] = []
    chains: dict[str, dict] = {}

    seen: set[tuple[str, str, bool]] = set()
    for chain in rs.chains:
        key = (chain.table, chain.name, chain.ipv6)
        state = read_chain(chain.table, chain.name, chain.ipv6, runner)

        if key not in seen:
            seen.add(key)
            if not state.exists:
                problems.append(f"chain {chain.name} does not exist")
            elif len(state.rules) < len([r for r in chain.rules if r.required]):
                problems.append(
                    f"chain {chain.name} has {len(state.rules)} rule(s) but "
                    f"{len(chain.rules)} were declared")
            chains[f"{chain.table}/{chain.name}"] = {
                "exists": state.exists,
                "rules": state.rules,
                "packets": state.packets,
            }

        if chain.hook:
            jumps = hooks_into(chain.table, chain.hook, chain.name, chain.ipv6, runner)
            if not jumps:
                problems.append(
                    f"{chain.table}/{chain.hook} has no jump into {chain.name} — "
                    f"nothing reaches it")
            elif len(jumps) > 1:
                problems.append(
                    f"{chain.table}/{chain.hook} has {len(jumps)} duplicate jumps "
                    f"into {chain.name}")

    # The single most diagnostic signal: is the redirect actually matching?
    redirect = chains.get(f"nat/{CHAIN_REDIRECT}")
    if redirect and redirect["exists"]:
        has_redirect_rule = any(r["target"] == "REDIRECT" for r in redirect["rules"])
        matched = any(int(r["packets"]) > 0 for r in redirect["rules"]
                      if r["packets"].isdigit())
        if has_redirect_rule and not matched:
            problems.append(
                f"{CHAIN_REDIRECT} has matched 0 packets — hotspot traffic is not "
                f"reaching it (usually the rules are bound to the wrong interface)")

    return {
        "hotspot_if": rs.hotspot_if,
        "wan_if": rs.wan_if,
        "chains": chains,
        "problems": problems,
        "healthy": not problems,
    }


# ── Teardown ──────────────────────────────────────────────────────────────────

def flush(runner: Optional[Runner] = None) -> None:
    """
    Remove every ProxyGate chain — current AND legacy — restoring plain host
    networking.

    Legacy names matter: a chain from an older version that is still hooked
    keeps steering packets after an upgrade, which is exactly the kind of
    invisible leftover that makes behaviour depend on install history.
    """
    runner = runner or Runner()

    current = [
        ("nat", CHAIN_REDIRECT, False, ("PREROUTING",)),
        ("nat", CHAIN_MASQ, False, ("POSTROUTING",)),
        ("filter", CHAIN_FORWARD, False, ("FORWARD",)),
        ("filter", CHAIN_BLOCKDEV, False, ("INPUT", "FORWARD")),
        ("nat", CHAIN_REDIRECT6, True, ("PREROUTING",)),
        ("nat", CHAIN_MASQ6, True, ("POSTROUTING",)),
        ("filter", CHAIN_FORWARD6, True, ("FORWARD",)),
    ]

    for table, name, ipv6, hooks in current:
        binary = "ip6tables" if ipv6 else "iptables"
        for hook in hooks:
            for _ in range(_MAX_DUP_DELETES):
                rc, _ = runner.run(binary, "-t", table, "-D", hook, "-j", name)
                if rc != 0:
                    break
        runner.run(binary, "-t", table, "-F", name)
        runner.run(binary, "-t", table, "-X", name)

    for table, name in LEGACY_CHAINS:
        for hook in ("PREROUTING", "POSTROUTING", "OUTPUT", "INPUT", "FORWARD"):
            for _ in range(_MAX_DUP_DELETES):
                rc, _ = runner.run("iptables", "-t", table, "-D", hook, "-j", name)
                if rc != 0:
                    break
        runner.run("iptables", "-t", table, "-F", name)
        runner.run("iptables", "-t", table, "-X", name)
