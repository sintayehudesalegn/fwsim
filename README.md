# fwsim

[![CI](https://github.com/sintayehudesalegn/fwsim/actions/workflows/ci.yml/badge.svg)](https://github.com/sintayehudesalegn/fwsim/actions)

A packet-filtering **firewall simulator** written in pure Python (no dependencies).
It models how a real firewall makes decisions, using synthetic traffic only.
**It never touches your network or your system's firewall.**

## Features

- **Ordered rule engine**: priorities, CIDR networks, protocols (TCP/UDP/ICMP), port ranges, and traffic direction
- **Stateful inspection**: replies to allowed outbound connections are admitted, with timeout and eviction
- **Rate limiting**: sliding-window, per-source limits to model flood and scan protection
- **Default policy**: deny-by-default (or allow) when no rule matches
- **Traffic generator**: seedable mix of web browsing, replies, VPN logins, pings, port scans, and noise
- **Reports**: text summary or JSON, with per-packet decision logs
- **JSON rulesets** with strict validation and clear error messages
- Typed code, unit tests, and CI across Python 3.10 to 3.13

## Install

```bash
git clone https://github.com/sintayehudesalegn/fwsim.git
cd fwsim
python3 -m venv venv && source venv/bin/activate`
pip install -e ".[dev]"
```

## Usage

```bash
# Run 1,000 synthetic packets through the built-in example ruleset
fwsim simulate -n 1000 --seed 42

# See every decision, or get machine-readable output
fwsim simulate -n 50 --seed 42 --verbose
fwsim simulate -n 1000 --seed 42 --format json > report.json

# Use your own ruleset
fwsim validate --rules my_rules.json
fwsim simulate --rules my_rules.json

# Ask what the firewall would do with one packet (exit code 0 = allow, 1 = deny)
fwsim check --src 203.0.113.9 --dst 192.168.1.10 --proto tcp --dport 443
```

You can also run it without installing: `PYTHONPATH=src python3 -m fwsim simulate`.

## How a packet is evaluated

```
packet
  |
  v
[1] rate limit (inbound)      -> DENY if the source exceeds its budget
  |
  v
[2] connection table          -> ALLOW if it is a reply to an allowed outbound flow
  |
  v
[3] rules, by priority        -> first match wins (ALLOW or DENY)
  |
  v
[4] default policy
```

## Ruleset format

The built-in example is in `src/fwsim/default_rules.json`. Copy it and edit.

```json
{
  "default_policy": "deny",
  "stateful": true,
  "connection_timeout_seconds": 60,
  "rate_limit": { "max_packets": 30, "window_seconds": 10 },
  "rules": [
    {
      "id": "allow-ssh-from-vpn",
      "priority": 40,
      "action": "allow",
      "direction": "inbound",
      "protocol": "tcp",
      "src": "10.8.0.0/24",
      "dst": "192.168.1.20",
      "dst_ports": 22
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Unique name (required) |
| `action` | `allow` or `deny` (required) |
| `priority` | Lower runs first; ties keep file order (default 100) |
| `protocol` | `tcp`, `udp`, or `icmp`; omit for any |
| `direction` | `inbound` or `outbound`; omit for any |
| `src`, `dst` | IP or CIDR, such as `10.0.0.0/8`; omit for any |
| `src_ports`, `dst_ports` | `443`, `"8000-8100"`, `"80,443"`, or a list; omit for any |
| `enabled` | Set `false` to switch a rule off |

## Use as a library

```python
from fwsim import load_firewall, TrafficGenerator

fw = load_firewall("my_rules.json")
for packet in TrafficGenerator(seed=1).generate(100):
    decision = fw.evaluate(packet)
print(fw.stats.to_dict())
```

## Project layout

```
src/fwsim/
  models.py    packets, rules, decisions
  engine.py    firewall, connection tracker, rate limiter
  config.py    JSON loading and validation
  traffic.py   synthetic traffic generator
  stats.py     counters
  report.py    text and JSON output
  cli.py       command line interface
tests/         pytest suite
```

## Development

```bash
pytest -q
```

## Limitations

This is an educational simulator. It handles IPv4 only, with no fragmentation, TCP state machine, NAT, or deep packet inspection, and it should not be used as a security control.

## License

MIT
