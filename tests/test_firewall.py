"""
The firewall layer: declaration, verified application, teardown.

Pins the behaviour whose absence caused a silent dead gateway — rules bound to
a nonexistent interface, installed without error, matching nothing forever.
"""
import pytest

from backend import firewall as fw


class FakeRunner(fw.Runner):
    """Records commands; can be told which ones fail."""

    def __init__(self, fail=(), fail_once=()):
        self.calls: list[tuple[str, ...]] = []
        self._fail = list(fail)
        self._fail_once = list(fail_once)
        self.outputs: dict[str, str] = {}

    def run(self, *cmd):
        self.calls.append(tuple(cmd))
        joined = " ".join(cmd)
        for pat in self._fail_once:
            if pat in joined:
                self._fail_once.remove(pat)
                return 1, f"simulated failure: {pat}"
        for pat in self._fail:
            if pat in joined:
                return 1, f"simulated failure: {pat}"
        for pat, out in self.outputs.items():
            if pat in joined:
                return 0, out
        return 0, ""

    def find(self, *fragments):
        return [c for c in self.calls
                if all(f in " ".join(c) for f in fragments)]


@pytest.fixture
def exists(monkeypatch):
    monkeypatch.setattr(fw.os.path, "isdir", lambda p: True)


def make(**kw):
    params = dict(hotspot_if="wlp2s0", wan_if="enp3s0",
                  gateway_ip="192.168.100.1", subnet="192.168.100.0/24",
                  mitm_port=8080, block=False)
    params.update(kw)
    return fw.build(**params)


# ── Declaration is pure and correct ───────────────────────────────────────────

def test_build_touches_nothing(monkeypatch):
    """Building must never shell out — it is pure data."""
    def boom(*a, **kw):
        raise AssertionError("build() executed a command")
    monkeypatch.setattr(fw.subprocess, "run", boom)
    make()


def test_redirect_sends_hotspot_tcp_to_mitm():
    rs = make()
    chain = next(c for c in rs.chains if c.name == fw.CHAIN_REDIRECT)
    rule = next(r for r in chain.rules if "REDIRECT" in r.args)
    assert "--to-port" in rule.args and "8080" in rule.args
    assert "-i" in rule.args and "wlp2s0" in rule.args


def test_gateway_traffic_is_never_redirected():
    """The gateway must not route its own traffic into its own proxy."""
    rs = make()
    chain = next(c for c in rs.chains if c.name == fw.CHAIN_REDIRECT)
    returns = [r for r in chain.rules if "RETURN" in r.args]
    flat = [" ".join(r.args) for r in returns]
    assert any("127.0.0.1" in f for f in flat)
    assert any("192.168.100.1" in f for f in flat)
    # …and they come before the REDIRECT, or they would never be reached.
    idx_return = max(i for i, r in enumerate(chain.rules) if "RETURN" in r.args)
    idx_redirect = next(i for i, r in enumerate(chain.rules) if "REDIRECT" in r.args)
    assert idx_return < idx_redirect


def test_dns_is_dnatted_to_the_gateway():
    rs = make()
    chain = next(c for c in rs.chains if c.name == fw.CHAIN_REDIRECT)
    dns = [r for r in chain.rules if "53" in r.args]
    assert len(dns) == 2, "both udp and tcp DNS must be redirected"
    assert all("DNAT" in r.args for r in dns)


def test_block_mode_drops_instead_of_forwarding():
    rs = make(block=True)
    fwd = next(c for c in rs.chains if c.name == fw.CHAIN_FORWARD)
    assert any("DROP" in r.args for r in fwd.rules)
    redirect = next(c for c in rs.chains if c.name == fw.CHAIN_REDIRECT)
    assert not any("REDIRECT" in r.args for r in redirect.rules)


def test_udp_is_always_dropped_when_forwarding():
    """UDP cannot traverse mitmproxy, so any UDP reaching FORWARD would
    bypass the proxy entirely."""
    rs = make()
    fwd = next(c for c in rs.chains if c.name == fw.CHAIN_FORWARD)
    assert any("udp" in r.args and "DROP" in r.args for r in fwd.rules)


def test_blocked_macs_produce_drop_rules():
    rs = make(blocked_macs=["20:ef:bd:65:a3:30", "02:da:96:dc:a5:de"])
    chains = [c for c in rs.chains if c.name == fw.CHAIN_BLOCKDEV]
    assert chains, "no block chain built"
    macs = [a for c in chains for r in c.rules for a in r.args if ":" in a and len(a) == 17]
    assert "20:ef:bd:65:a3:30" in macs


def test_block_rules_are_best_effort():
    """One malformed MAC must cost that device's block, not the gateway."""
    rs = make(blocked_macs=["20:ef:bd:65:a3:30"])
    chain = next(c for c in rs.chains if c.name == fw.CHAIN_BLOCKDEV)
    assert all(not r.required for r in chain.rules)


def test_blockdev_hooks_both_input_and_forward():
    """INPUT so a blocked device cannot reach the gateway at all; FORWARD so
    it gets no internet even if it still holds an IP."""
    rs = make(blocked_macs=["20:ef:bd:65:a3:30"])
    hooks = {c.hook for c in rs.chains if c.name == fw.CHAIN_BLOCKDEV}
    assert hooks == {"INPUT", "FORWARD"}


# ── Preconditions: refuse rather than fail silently ───────────────────────────

def test_refuses_unresolved_interface():
    rs = make(hotspot_if="ap0")
    problems = fw.check_preconditions(rs)
    assert any("unresolved" in p for p in problems)


def test_refuses_missing_interface(monkeypatch):
    monkeypatch.setattr(fw.os.path, "isdir", lambda p: False)
    problems = fw.check_preconditions(make())
    assert any("does not exist" in p for p in problems)


def test_refuses_when_hotspot_and_wan_are_the_same(exists):
    problems = fw.check_preconditions(make(wan_if="wlp2s0"))
    assert any("same interface" in p for p in problems)


def test_apply_raises_instead_of_installing_dead_rules(monkeypatch):
    """THE regression. Installing rules that cannot match is strictly worse
    than refusing, because the failure is then invisible."""
    monkeypatch.setattr(fw.os.path, "isdir", lambda p: False)
    runner = FakeRunner()
    with pytest.raises(fw.FirewallError, match="does not exist"):
        fw.apply(make(), runner=runner)
    assert not runner.find("REDIRECT"), "rules were installed anyway"


# ── Applying ──────────────────────────────────────────────────────────────────

def test_apply_creates_fills_then_hooks(exists):
    """A chain must be complete before anything can jump into it."""
    runner = FakeRunner()
    fw.apply(make(), runner=runner, flush_conntrack=False)
    order = [" ".join(c) for c in runner.calls]
    # Anchor on the exact chain: "PROXYGATE_REDIRECT" is a prefix of
    # "PROXYGATE_REDIRECT6", whose rules are written later.
    fill = max(i for i, c in enumerate(order)
               if c.startswith(f"iptables -t nat -A {fw.CHAIN_REDIRECT} "))
    hook = next(i for i, c in enumerate(order)
                if c == f"iptables -t nat -I PREROUTING 1 -j {fw.CHAIN_REDIRECT}")
    assert fill < hook, "chain was hooked before it was fully built"


def test_apply_deletes_duplicate_hooks_before_inserting(exists):
    """`iptables -D` removes one match; duplicates from an interrupted run
    would otherwise survive and keep routing packets."""
    runner = FakeRunner()
    fw.apply(make(), runner=runner, flush_conntrack=False)
    deletes = runner.find("-D", "PREROUTING", fw.CHAIN_REDIRECT)
    assert len(deletes) > 1


def test_apply_raises_on_required_rule_failure(exists):
    runner = FakeRunner(fail=["-A PROXYGATE_REDIRECT -i wlp2s0 -p tcp"])
    with pytest.raises(fw.FirewallError):
        fw.apply(make(), runner=runner, flush_conntrack=False)


def test_apply_tolerates_optional_rule_failure(exists):
    """A failing LOG rule must not take the gateway down."""
    runner = FakeRunner(fail=["--log-prefix"])
    fw.apply(make(), runner=runner, flush_conntrack=False)   # must not raise


def test_apply_flushes_conntrack(exists):
    """Existing flows were established against the old rules and would keep
    bypassing the proxy until they closed on their own."""
    runner = FakeRunner()
    fw.apply(make(), runner=runner, flush_conntrack=True)
    assert runner.find("conntrack", "-D")


def test_shared_chain_is_built_once(exists):
    """BLOCKDEV hooks into two builtins but must only be created and filled
    once, or the second pass would wipe the first."""
    runner = FakeRunner()
    fw.apply(make(blocked_macs=["20:ef:bd:65:a3:30"]), runner=runner,
             flush_conntrack=False)
    flushes = runner.find("-F", fw.CHAIN_BLOCKDEV)
    assert len(flushes) == 1


def test_route_localnet_is_enabled(exists):
    """Without it a REDIRECT to a loopback listener cannot work at all."""
    runner = FakeRunner()
    fw.apply(make(), runner=runner, flush_conntrack=False)
    assert runner.find("sysctl", "route_localnet=1")


# ── Verification ──────────────────────────────────────────────────────────────

DEAD = """Chain PREROUTING (policy ACCEPT)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 PROXYGATE_REDIRECT  all  --  *  *  0.0.0.0/0   0.0.0.0/0
"""
LIVE = """Chain PREROUTING (policy ACCEPT)
num   pkts bytes target     prot opt in     out     source               destination
1     4213  999 PROXYGATE_REDIRECT  all  --  *  *  0.0.0.0/0   0.0.0.0/0
"""
REDIRECT_DEAD = """Chain PROXYGATE_REDIRECT (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 REDIRECT   tcp  --  wlp2s0 *  0.0.0.0/0   0.0.0.0/0
"""
REDIRECT_LIVE = """Chain PROXYGATE_REDIRECT (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1     1201 5000 REDIRECT   tcp  --  wlp2s0 *  0.0.0.0/0   0.0.0.0/0
"""


def test_verify_flags_a_redirect_that_matches_nothing(exists):
    """The exact signature of the bug: rules present, counters frozen."""
    runner = FakeRunner()
    runner.outputs = {"-L PREROUTING": DEAD, "-L PROXYGATE_REDIRECT": REDIRECT_DEAD}
    report = fw.verify(make(), runner=runner)
    assert report["healthy"] is False
    assert any("0 packets" in p for p in report["problems"])


def test_verify_is_healthy_when_packets_flow(exists):
    runner = FakeRunner()
    runner.outputs = {"-L PREROUTING": LIVE, "-L PROXYGATE_REDIRECT": REDIRECT_LIVE}
    report = fw.verify(make(ipv6=False, blocked_macs=[]), runner=runner)
    assert not any("0 packets" in p for p in report["problems"])


def test_verify_flags_a_missing_hook(exists):
    runner = FakeRunner()
    runner.outputs = {"-L PROXYGATE_REDIRECT": REDIRECT_LIVE}   # PREROUTING empty
    report = fw.verify(make(), runner=runner)
    assert any("no jump" in p for p in report["problems"])


def test_verify_flags_a_missing_chain(exists):
    runner = FakeRunner(fail=["-L PROXYGATE_REDIRECT"])
    report = fw.verify(make(), runner=runner)
    assert any("does not exist" in p for p in report["problems"])


# ── Teardown ──────────────────────────────────────────────────────────────────

def test_flush_removes_every_duplicate_hook():
    """Three stacked jumps must all go."""
    state = {"n": 3}

    class R(FakeRunner):
        def run(self, *cmd):
            self.calls.append(tuple(cmd))
            j = " ".join(cmd)
            if "-D PREROUTING -j PROXYGATE_REDIRECT" in j:
                if state["n"] > 0:
                    state["n"] -= 1
                    return 0, ""
                return 1, "no match"
            return 0, ""

    fw.flush(runner=R())
    assert state["n"] == 0


def test_flush_cleans_legacy_chains():
    """A chain from an older version that is still hooked keeps steering
    packets after an upgrade."""
    runner = FakeRunner()
    fw.flush(runner=runner)
    assert runner.find("PROXYGATE_OUTPUT")


def test_flush_removes_ipv6_chains():
    runner = FakeRunner()
    fw.flush(runner=runner)
    assert runner.find("ip6tables", fw.CHAIN_REDIRECT6)
