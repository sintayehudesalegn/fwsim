"""Load and validate firewall configuration from JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .engine import Firewall
from .models import Action, Rule, RuleError


def firewall_from_dict(data: Any) -> Firewall:
    if not isinstance(data, dict):
        raise RuleError("ruleset must be a JSON object")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuleError("'rules' must be a list")

    try:
        default_policy = Action(str(data.get("default_policy", "deny")).lower())
    except ValueError as exc:
        raise RuleError(f"invalid default_policy: {data.get('default_policy')!r}") from exc

    try:
        timeout = float(data.get("connection_timeout_seconds", 60))
    except (TypeError, ValueError) as exc:
        raise RuleError("connection_timeout_seconds must be a number") from exc
    if timeout <= 0:
        raise RuleError("connection_timeout_seconds must be positive")

    rate_limit = None
    if data.get("rate_limit") is not None:
        raw = data["rate_limit"]
        try:
            rate_limit = (int(raw["max_packets"]), float(raw["window_seconds"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise RuleError("rate_limit needs numeric 'max_packets' and 'window_seconds'") from exc
        if rate_limit[0] <= 0 or rate_limit[1] <= 0:
            raise RuleError("rate_limit values must be positive")

    return Firewall(
        [Rule.from_dict(r) for r in raw_rules],
        default_policy,
        stateful=bool(data.get("stateful", True)),
        connection_timeout=timeout,
        rate_limit=rate_limit,
    )


def load_firewall(path: str | Path) -> Firewall:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleError(f"{path}: invalid JSON ({exc})") from exc
    return firewall_from_dict(data)
