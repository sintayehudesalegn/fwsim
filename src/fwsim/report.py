"""Human-readable and machine-readable output."""

from __future__ import annotations

import json
from typing import Any

from .models import Action, Decision, Packet
from .stats import Stats


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _pct(part: int, whole: int) -> str:
    return f"{(100 * part / whole) if whole else 0:.1f}%"


def format_decision(packet: Packet, decision: Decision) -> str:
    src = f"{packet.src_ip}:{packet.src_port}" if packet.src_port else str(packet.src_ip)
    dst = f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else str(packet.dst_ip)
    tag = "ALLOW" if decision.action is Action.ALLOW else "DENY "
    return (
        f"[{packet.timestamp:8.3f}s] {tag} {packet.direction.value:<8} "
        f"{packet.protocol.value:<4} {src} -> {dst}  ({decision.label})"
    )


def render_text(stats: Stats, info: dict[str, Any], top: int = 5) -> str:
    rate = info["rate_limit"]
    rate_text = f"{rate['max_packets']} pkts/{rate['window_seconds']:g}s" if rate else "off"
    lines = [
        "=" * 64,
        " FIREWALL SIMULATION REPORT",
        "=" * 64,
        f" Rules: {info['rules']}   Default policy: {info['default_policy']}",
        f" Stateful: {'on' if info['stateful'] else 'off'}"
        f" (timeout {info['connection_timeout_seconds']:g}s)   Rate limit: {rate_text}",
        "",
        f" Packets  : {stats.total}",
        f" Allowed  : {stats.allowed:>6}  ({_pct(stats.allowed, stats.total)})"
        f"   {_human_bytes(stats.bytes_allowed)}",
        f" Denied   : {stats.denied:>6}  ({_pct(stats.denied, stats.total)})"
        f"   {_human_bytes(stats.bytes_denied)}",
        "",
        " Decisions",
    ]
    lines += [f"   {n:>6}  {label}" for label, n in stats.by_decision.most_common()]
    lines += ["", " Protocols"]
    lines += [f"   {n:>6}  {proto}" for proto, n in stats.by_protocol.most_common()]
    if stats.denied_sources:
        lines += ["", f" Top denied sources (top {top})"]
        lines += [f"   {n:>6}  {ip}" for ip, n in stats.denied_sources.most_common(top)]
    if stats.denied_ports:
        lines += ["", f" Top denied destination ports (top {top})"]
        lines += [f"   {n:>6}  {port}" for port, n in stats.denied_ports.most_common(top)]
    lines.append("=" * 64)
    return "\n".join(lines)


def render_json(stats: Stats, info: dict[str, Any]) -> str:
    return json.dumps({"firewall": info, "stats": stats.to_dict()}, indent=2)
