"""Command-line interface: simulate, validate, check."""

from __future__ import annotations

import argparse
import sys
from importlib import resources
from ipaddress import IPv4Address
from pathlib import Path

from . import __version__
from .config import load_firewall
from .models import Direction, Packet, Protocol, RuleError
from .report import format_decision, render_json, render_text
from .traffic import TrafficGenerator


def _default_rules_path() -> Path:
    return Path(str(resources.files("fwsim").joinpath("default_rules.json")))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fwsim", description="Packet-filtering firewall simulator.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_rules(p: argparse.ArgumentParser) -> None:
        p.add_argument("-r", "--rules", type=Path, help="ruleset JSON (default: built-in example)")

    sim = sub.add_parser("simulate", help="run synthetic traffic through the firewall")
    add_rules(sim)
    sim.add_argument("-n", "--packets", type=int, default=500, help="packets to generate (default 500)")
    sim.add_argument("-s", "--seed", type=int, help="random seed for reproducible runs")
    sim.add_argument("-f", "--format", choices=("text", "json"), default="text")
    sim.add_argument("-v", "--verbose", action="store_true", help="print every decision")

    val = sub.add_parser("validate", help="check a ruleset for errors")
    add_rules(val)

    chk = sub.add_parser("check", help="evaluate a single packet")
    add_rules(chk)
    chk.add_argument("--src", required=True)
    chk.add_argument("--dst", required=True)
    chk.add_argument("--proto", choices=[p.value for p in Protocol], default="tcp")
    chk.add_argument("--sport", type=int, default=40000)
    chk.add_argument("--dport", type=int, default=0)
    chk.add_argument("--direction", choices=[d.value for d in Direction], default="inbound")
    return parser


def _cmd_simulate(args: argparse.Namespace) -> int:
    if args.packets < 1:
        raise RuleError("--packets must be at least 1")
    firewall = load_firewall(args.rules or _default_rules_path())
    log = sys.stderr if args.format == "json" else sys.stdout
    for packet in TrafficGenerator(args.seed).generate(args.packets):
        decision = firewall.evaluate(packet)
        if args.verbose:
            print(format_decision(packet, decision), file=log)
    info = firewall.describe()
    if args.format == "json":
        print(render_json(firewall.stats, info))
    else:
        print(render_text(firewall.stats, info))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    path = args.rules or _default_rules_path()
    firewall = load_firewall(path)
    print(f"OK: {path} ({len(firewall.rules)} active rules, default {firewall.default_policy.value})")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    firewall = load_firewall(args.rules or _default_rules_path())
    packet = Packet(
        src_ip=IPv4Address(args.src),
        dst_ip=IPv4Address(args.dst),
        protocol=Protocol(args.proto),
        direction=Direction(args.direction),
        src_port=args.sport,
        dst_port=args.dport,
    )
    decision = firewall.evaluate(packet)
    print(format_decision(packet, decision))
    return 0 if decision.action.value == "allow" else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"simulate": _cmd_simulate, "validate": _cmd_validate, "check": _cmd_check}
    try:
        return handlers[args.command](args)
    except BrokenPipeError:  # e.g. `fwsim simulate -v | head`
        return 0
    except (RuleError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
