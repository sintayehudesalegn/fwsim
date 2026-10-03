"""Core data models: packets, rules, and decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Any


class Action(str, Enum):
    """What the firewall does with a packet."""

    ALLOW = "allow"
    DENY = "deny"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class RuleError(ValueError):
    """Raised when a rule or ruleset definition is invalid."""


FlowKey = tuple[IPv4Address, int, IPv4Address, int, Protocol]


@dataclass(frozen=True)
class Packet:
    """A simplified network packet (L3/L4 header fields only)."""

    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Protocol
    direction: Direction
    src_port: int = 0
    dst_port: int = 0
    timestamp: float = 0.0
    size: int = 0

    @property
    def flow_key(self) -> FlowKey:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    @property
    def reverse_flow_key(self) -> FlowKey:
        return (self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.protocol)


@dataclass(frozen=True)
class Decision:
    """The outcome of evaluating one packet."""

    action: Action
    reason: str
    rule_id: str | None = None

    @property
    def label(self) -> str:
        return f"rule:{self.rule_id}" if self.rule_id else self.reason


@dataclass(frozen=True)
class PortRange:
    """An inclusive port range, e.g. 80 or 8000-8100."""

    low: int
    high: int

    def __post_init__(self) -> None:
        if not 0 <= self.low <= self.high <= 65535:
            raise RuleError(f"invalid port range: {self.low}-{self.high}")

    def __contains__(self, port: int) -> bool:
        return self.low <= port <= self.high

    @classmethod
    def parse(cls, value: int | str) -> PortRange:
        text = str(value).strip()
        try:
            parts = [int(p) for p in text.split("-", 1)]
        except ValueError as exc:
            raise RuleError(f"invalid port specification: {value!r}") from exc
        return cls(parts[0], parts[-1])


def parse_ports(value: Any) -> tuple[PortRange, ...]:
    """Accept 443, "80-90", "80,443", or a list of those."""
    if value is None:
        return ()
    if isinstance(value, str):
        items: list[Any] = value.split(",")
    elif isinstance(value, int):
        items = [value]
    else:
        items = list(value)
    return tuple(PortRange.parse(item) for item in items)


def _enum_or_none(enum_cls: type[Enum], value: Any) -> Any:
    return None if value is None else enum_cls(str(value).lower())


def _network_or_none(value: Any) -> IPv4Network | None:
    return None if value is None else IPv4Network(str(value), strict=False)


@dataclass(frozen=True)
class Rule:
    """A firewall rule. Unset fields are wildcards. Lower priority runs first."""

    rule_id: str
    action: Action
    priority: int = 100
    protocol: Protocol | None = None
    direction: Direction | None = None
    src: IPv4Network | None = None
    dst: IPv4Network | None = None
    src_ports: tuple[PortRange, ...] = ()
    dst_ports: tuple[PortRange, ...] = ()
    description: str = ""
    enabled: bool = True

    def matches(self, packet: Packet) -> bool:
        if not self.enabled:
            return False
        if self.protocol is not None and packet.protocol is not self.protocol:
            return False
        if self.direction is not None and packet.direction is not self.direction:
            return False
        if self.src is not None and packet.src_ip not in self.src:
            return False
        if self.dst is not None and packet.dst_ip not in self.dst:
            return False
        if self.src_ports or self.dst_ports:
            if packet.protocol is Protocol.ICMP:
                return False
            if self.src_ports and not any(packet.src_port in r for r in self.src_ports):
                return False
            if self.dst_ports and not any(packet.dst_port in r for r in self.dst_ports):
                return False
        return True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        if not isinstance(data, dict):
            raise RuleError(f"each rule must be an object, got {type(data).__name__}")
        try:
            rule_id = str(data["id"])
            action = Action(str(data["action"]).lower())
        except KeyError as exc:
            raise RuleError(f"rule is missing required field {exc}") from exc
        except ValueError as exc:
            raise RuleError(f"rule {data.get('id')!r}: invalid action {data.get('action')!r}") from exc
        try:
            return cls(
                rule_id=rule_id,
                action=action,
                priority=int(data.get("priority", 100)),
                protocol=_enum_or_none(Protocol, data.get("protocol")),
                direction=_enum_or_none(Direction, data.get("direction")),
                src=_network_or_none(data.get("src")),
                dst=_network_or_none(data.get("dst")),
                src_ports=parse_ports(data.get("src_ports")),
                dst_ports=parse_ports(data.get("dst_ports")),
                description=str(data.get("description", "")),
                enabled=bool(data.get("enabled", True)),
            )
        except (ValueError, TypeError) as exc:
            raise RuleError(f"rule {rule_id!r}: {exc}") from exc
