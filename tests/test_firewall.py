from ipaddress import IPv4Address

import pytest

from fwsim import (
    Action,
    Direction,
    Firewall,
    Packet,
    Protocol,
    Rule,
    RuleError,
    TrafficGenerator,
    firewall_from_dict,
)


def pkt(src="198.51.100.5", dst="192.168.1.10", proto=Protocol.TCP,
        direction=Direction.INBOUND, sport=40000, dport=443, ts=0.0):
    return Packet(IPv4Address(src), IPv4Address(dst), proto, direction, sport, dport, ts, 100)


def rule(rule_id, action="allow", **kwargs):
    return Rule.from_dict({"id": rule_id, "action": action, **kwargs})


def test_default_policy_applies_when_no_rule_matches():
    assert Firewall([]).evaluate(pkt()).action is Action.DENY
    assert Firewall([], Action.ALLOW).evaluate(pkt()).action is Action.ALLOW


def test_lower_priority_number_wins():
    fw = Firewall([
        rule("allow-all", "allow", priority=50),
        rule("deny-https", "deny", priority=10, dst_ports=443),
    ])
    decision = fw.evaluate(pkt())
    assert decision.action is Action.DENY
    assert decision.rule_id == "deny-https"


def test_cidr_and_port_range_matching():
    fw = Firewall([rule("r", src="198.51.100.0/24", protocol="tcp", dst_ports="8000-8100")])
    assert fw.evaluate(pkt(dport=8050)).action is Action.ALLOW
    assert fw.evaluate(pkt(dport=8101)).action is Action.DENY
    assert fw.evaluate(pkt(src="192.0.2.1", dport=8050)).action is Action.DENY


def test_disabled_rule_is_ignored():
    assert Firewall([rule("r", enabled=False)]).evaluate(pkt()).action is Action.DENY


def test_port_rules_never_match_icmp():
    fw = Firewall([rule("r", dst_ports="0-65535")])
    assert fw.evaluate(pkt(proto=Protocol.ICMP, sport=0, dport=0)).action is Action.DENY


def test_stateful_reply_allowed_but_unsolicited_inbound_denied():
    fw = Firewall([rule("out", direction="outbound", protocol="tcp", dst_ports=443)])
    out = pkt("192.168.1.30", "198.51.100.9", direction=Direction.OUTBOUND, sport=50000, dport=443)
    reply = pkt("198.51.100.9", "192.168.1.30", sport=443, dport=50000, ts=1.0)
    unsolicited = pkt("198.51.100.9", "192.168.1.30", sport=443, dport=50001, ts=1.0)

    assert fw.evaluate(out).action is Action.ALLOW
    assert fw.evaluate(reply).reason == "established connection"
    assert fw.evaluate(unsolicited).action is Action.DENY


def test_connection_expires_after_timeout():
    fw = Firewall([rule("out", direction="outbound")], connection_timeout=10)
    fw.evaluate(pkt("192.168.1.30", "198.51.100.9", direction=Direction.OUTBOUND,
                    sport=50000, dport=443))
    late = pkt("198.51.100.9", "192.168.1.30", sport=443, dport=50000, ts=11.0)
    assert fw.evaluate(late).action is Action.DENY


def test_stateless_mode_does_not_track_connections():
    fw = Firewall([rule("out", direction="outbound")], stateful=False)
    fw.evaluate(pkt("192.168.1.30", "198.51.100.9", direction=Direction.OUTBOUND,
                    sport=50000, dport=443))
    reply = pkt("198.51.100.9", "192.168.1.30", sport=443, dport=50000, ts=1.0)
    assert fw.evaluate(reply).action is Action.DENY


def test_rate_limit_blocks_floods_then_recovers():
    fw = Firewall([rule("open")], rate_limit=(3, 1.0))
    results = [fw.evaluate(pkt(ts=i * 0.1)).action for i in range(5)]
    assert results == [Action.ALLOW] * 3 + [Action.DENY] * 2
    assert fw.evaluate(pkt(ts=5.0)).action is Action.ALLOW


def test_duplicate_rule_ids_rejected():
    with pytest.raises(RuleError, match="duplicate"):
        Firewall([rule("a"), rule("a")])


@pytest.mark.parametrize("bad", [
    {"action": "allow"},
    {"id": "x", "action": "maybe"},
    {"id": "x", "action": "allow", "src": "not-an-ip"},
    {"id": "x", "action": "allow", "dst_ports": "70000"},
    {"id": "x", "action": "allow", "protocol": "gre"},
])
def test_invalid_rules_raise_rule_error(bad):
    with pytest.raises(RuleError):
        Rule.from_dict(bad)


def test_config_validation():
    with pytest.raises(RuleError):
        firewall_from_dict({"rules": "nope"})
    with pytest.raises(RuleError):
        firewall_from_dict({"rules": [], "rate_limit": {"max_packets": 0, "window_seconds": 1}})
    fw = firewall_from_dict({"rules": [], "default_policy": "allow"})
    assert fw.default_policy is Action.ALLOW


def test_traffic_is_reproducible_with_a_seed():
    a = list(TrafficGenerator(seed=7).generate(200))
    b = list(TrafficGenerator(seed=7).generate(200))
    c = list(TrafficGenerator(seed=8).generate(200))
    assert a == b
    assert a != c
    assert len(a) == 200
    assert all(x.timestamp <= y.timestamp for x, y in zip(a, a[1:]))
