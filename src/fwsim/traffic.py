"""Seedable synthetic traffic: normal browsing, replies, probes, scans, and noise."""

from __future__ import annotations

import random
from collections import deque
from ipaddress import IPv4Address
from typing import Iterator

from .models import Direction, Packet, Protocol

_REPLY_PORTS = {80, 443, 53, 123}


class TrafficGenerator:
    """Generates a realistic mix of packets for the default example network.

    Addresses use documentation ranges (RFC 5737) and RFC 1918 space only.
    The same seed always produces the same traffic.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._clients = [IPv4Address(f"192.168.1.{i}") for i in range(30, 61)]
        self._web_server = IPv4Address("192.168.1.10")
        self._ssh_server = IPv4Address("192.168.1.20")
        self._db_server = IPv4Address("192.168.1.40")
        self._vpn_peers = [IPv4Address(f"10.8.0.{i}") for i in range(2, 12)]
        self._scanner = IPv4Address("198.51.100.77")
        self._flows: deque[Packet] = deque(maxlen=64)

    # -- public API ---------------------------------------------------------

    def generate(self, count: int) -> Iterator[Packet]:
        clock = 0.0
        emitted = 0
        while emitted < count:
            clock += self._rng.expovariate(25.0)  # ~40 ms between events
            burst = self._next_event(clock)
            for packet in burst:
                if emitted >= count:
                    return
                yield packet
                emitted += 1
            if burst:
                clock = max(clock, burst[-1].timestamp)

    # -- event builders -----------------------------------------------------

    def _next_event(self, now: float) -> list[Packet]:
        roll = self._rng.random()
        if roll < 0.35:
            return [self._outbound(now)]
        if roll < 0.55:
            return [self._reply(now)] if self._flows else [self._outbound(now)]
        if roll < 0.73:
            return [self._inbound_service(now)]
        if roll < 0.74:
            return self._port_scan(now)
        if roll < 0.82:
            return [self._ping(now)]
        return [self._inbound_noise(now)]

    def _external_ip(self) -> IPv4Address:
        prefix = self._rng.choice(("198.51.100", "192.0.2"))
        return IPv4Address(f"{prefix}.{self._rng.randint(1, 254)}")

    def _bad_ip(self) -> IPv4Address:
        return IPv4Address(f"203.0.113.{self._rng.randint(1, 254)}")

    def _ephemeral(self) -> int:
        return self._rng.randint(49152, 65535)

    def _size(self) -> int:
        return self._rng.randint(40, 1500)

    def _outbound(self, now: float) -> Packet:
        proto, port = self._rng.choices(
            [
                (Protocol.TCP, 443),
                (Protocol.TCP, 80),
                (Protocol.UDP, 53),
                (Protocol.UDP, 123),
                (Protocol.TCP, 23),
                (Protocol.TCP, 6667),
            ],
            weights=[10, 4, 5, 1, 1, 1],
        )[0]
        packet = Packet(
            src_ip=self._rng.choice(self._clients),
            dst_ip=self._external_ip(),
            protocol=proto,
            direction=Direction.OUTBOUND,
            src_port=self._ephemeral(),
            dst_port=port,
            timestamp=now,
            size=self._size(),
        )
        if port in _REPLY_PORTS:
            self._flows.append(packet)
        return packet

    def _reply(self, now: float) -> Packet:
        flow = self._rng.choice(self._flows)
        return Packet(
            src_ip=flow.dst_ip,
            dst_ip=flow.src_ip,
            protocol=flow.protocol,
            direction=Direction.INBOUND,
            src_port=flow.dst_port,
            dst_port=flow.src_port,
            timestamp=now,
            size=self._size(),
        )

    def _inbound_service(self, now: float) -> Packet:
        source = self._rng.choices(
            [self._external_ip(), self._rng.choice(self._vpn_peers), self._bad_ip()],
            weights=[6, 2, 2],
        )[0]
        target, port = self._rng.choice(
            [
                (self._web_server, 443),
                (self._web_server, 443),
                (self._web_server, 80),
                (self._web_server, 8080),
                (self._ssh_server, 22),
                (self._rng.choice(self._clients), 3389),
                (self._db_server, 3306),
            ]
        )
        return Packet(
            src_ip=source,
            dst_ip=target,
            protocol=Protocol.TCP,
            direction=Direction.INBOUND,
            src_port=self._ephemeral(),
            dst_port=port,
            timestamp=now,
            size=self._size(),
        )

    def _port_scan(self, now: float) -> list[Packet]:
        target = self._rng.choice(self._clients)
        return [
            Packet(
                src_ip=self._scanner,
                dst_ip=target,
                protocol=Protocol.TCP,
                direction=Direction.INBOUND,
                src_port=self._ephemeral(),
                dst_port=self._rng.randint(1, 1024),
                timestamp=now + i * 0.01,
                size=60,
            )
            for i in range(self._rng.randint(25, 45))
        ]

    def _ping(self, now: float) -> Packet:
        return Packet(
            src_ip=self._external_ip(),
            dst_ip=self._rng.choice([self._web_server, self._rng.choice(self._clients)]),
            protocol=Protocol.ICMP,
            direction=Direction.INBOUND,
            timestamp=now,
            size=64,
        )

    def _inbound_noise(self, now: float) -> Packet:
        return Packet(
            src_ip=self._external_ip(),
            dst_ip=self._rng.choice(self._clients),
            protocol=self._rng.choice([Protocol.TCP, Protocol.UDP]),
            direction=Direction.INBOUND,
            src_port=self._ephemeral(),
            dst_port=self._rng.randint(1025, 65535),
            timestamp=now,
            size=self._size(),
        )
