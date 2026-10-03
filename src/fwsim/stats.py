"""Traffic statistics collected while the firewall runs."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .models import Action, Decision, Packet


@dataclass
class Stats:
    total: int = 0
    allowed: int = 0
    denied: int = 0
    bytes_allowed: int = 0
    bytes_denied: int = 0
    by_decision: Counter[str] = field(default_factory=Counter)
    by_protocol: Counter[str] = field(default_factory=Counter)
    denied_sources: Counter[str] = field(default_factory=Counter)
    denied_ports: Counter[int] = field(default_factory=Counter)

    def record(self, packet: Packet, decision: Decision) -> None:
        self.total += 1
        self.by_protocol[packet.protocol.value] += 1
        self.by_decision[f"{decision.action.value}  {decision.label}"] += 1
        if decision.action is Action.ALLOW:
            self.allowed += 1
            self.bytes_allowed += packet.size
        else:
            self.denied += 1
            self.bytes_denied += packet.size
            self.denied_sources[str(packet.src_ip)] += 1
            if packet.dst_port:
                self.denied_ports[packet.dst_port] += 1

    def to_dict(self, top: int = 5) -> dict[str, Any]:
        return {
            "total": self.total,
            "allowed": self.allowed,
            "denied": self.denied,
            "bytes_allowed": self.bytes_allowed,
            "bytes_denied": self.bytes_denied,
            "by_decision": dict(self.by_decision.most_common()),
            "by_protocol": dict(self.by_protocol.most_common()),
            "top_denied_sources": dict(self.denied_sources.most_common(top)),
            "top_denied_ports": {str(p): n for p, n in self.denied_ports.most_common(top)},
        }
