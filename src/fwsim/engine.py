"""Packet-filtering engine: ordered rules, connection tracking, rate limiting.

Evaluation order for every packet:
  1. Per-source rate limit (inbound only)
  2. Stateful connection table (inbound replies to allowed outbound flows)
  3. Rules, lowest priority number first
  4. Default policy
"""

from __future__ import annotations

from collections import deque
from ipaddress import IPv4Address
from typing import Any, Iterable

from .models import Action, Decision, Direction, FlowKey, Packet, Protocol, Rule, RuleError
from .stats import Stats

_TRACKED = (Protocol.TCP, Protocol.UDP)


class RateLimiter:
    """Sliding-window limiter: at most `max_packets` per source per `window` seconds."""

    def __init__(self, max_packets: int, window: float) -> None:
        if max_packets <= 0 or window <= 0:
            raise ValueError("max_packets and window must be positive")
        self.max_packets = max_packets
        self.window = window
        self._events: dict[IPv4Address, deque[float]] = {}

    def allow(self, source: IPv4Address, now: float) -> bool:
        events = self._events.setdefault(source, deque())
        cutoff = now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= self.max_packets:
            return False
        events.append(now)
        return True


class ConnectionTracker:
    """Remembers allowed outbound flows so their replies can come back in."""

    def __init__(self, timeout: float = 60.0, max_entries: int = 10_000) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout
        self.max_entries = max_entries
        self._table: dict[FlowKey, float] = {}

    def __len__(self) -> int:
        return len(self._table)

    def track(self, packet: Packet) -> None:
        key = packet.flow_key
        self._table.pop(key, None)
        self._table[key] = packet.timestamp
        while len(self._table) > self.max_entries:
            self._table.pop(next(iter(self._table)))  # evict least recently used

    def is_established(self, packet: Packet) -> bool:
        key = packet.reverse_flow_key
        last_seen = self._table.get(key)
        if last_seen is None:
            return False
        if packet.timestamp - last_seen > self.timeout:
            del self._table[key]
            return False
        del self._table[key]
        self._table[key] = packet.timestamp  # refresh
        return True


class Firewall:
    def __init__(
        self,
        rules: Iterable[Rule],
        default_policy: Action = Action.DENY,
        *,
        stateful: bool = True,
        connection_timeout: float = 60.0,
        rate_limit: tuple[int, float] | None = None,
    ) -> None:
        rule_list = list(rules)
        ids = [r.rule_id for r in rule_list]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise RuleError(f"duplicate rule ids: {', '.join(duplicates)}")

        # sorted() is stable, so equal priorities keep their file order
        self.rules: tuple[Rule, ...] = tuple(
            sorted((r for r in rule_list if r.enabled), key=lambda r: r.priority)
        )
        self.default_policy = default_policy
        self.stateful = stateful
        self.connection_timeout = connection_timeout
        self.rate_limit = rate_limit
        self._tracker = ConnectionTracker(connection_timeout) if stateful else None
        self._limiter = RateLimiter(*rate_limit) if rate_limit else None
        self.stats = Stats()

    def evaluate(self, packet: Packet) -> Decision:
        decision = self._decide(packet)
        if (
            decision.action is Action.ALLOW
            and self._tracker is not None
            and packet.direction is Direction.OUTBOUND
            and packet.protocol in _TRACKED
        ):
            self._tracker.track(packet)
        self.stats.record(packet, decision)
        return decision

    def _decide(self, packet: Packet) -> Decision:
        inbound = packet.direction is Direction.INBOUND
        if inbound and self._limiter and not self._limiter.allow(packet.src_ip, packet.timestamp):
            return Decision(Action.DENY, "rate limit exceeded")
        if inbound and self._tracker and self._tracker.is_established(packet):
            return Decision(Action.ALLOW, "established connection")
        for rule in self.rules:
            if rule.matches(packet):
                return Decision(rule.action, f"matched rule '{rule.rule_id}'", rule.rule_id)
        return Decision(self.default_policy, "default policy")

    def describe(self) -> dict[str, Any]:
        return {
            "rules": len(self.rules),
            "default_policy": self.default_policy.value,
            "stateful": self.stateful,
            "connection_timeout_seconds": self.connection_timeout,
            "rate_limit": (
                {"max_packets": self.rate_limit[0], "window_seconds": self.rate_limit[1]}
                if self.rate_limit
                else None
            ),
        }
