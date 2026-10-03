"""fwsim - a packet-filtering firewall simulator."""

from .config import firewall_from_dict, load_firewall
from .engine import Firewall
from .models import Action, Decision, Direction, Packet, Protocol, Rule, RuleError
from .traffic import TrafficGenerator

__version__ = "1.0.0"

__all__ = [
    "Action",
    "Decision",
    "Direction",
    "Firewall",
    "Packet",
    "Protocol",
    "Rule",
    "RuleError",
    "TrafficGenerator",
    "firewall_from_dict",
    "load_firewall",
]
