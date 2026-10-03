import json

from fwsim.cli import main


def test_simulate_json_output(capsys):
    assert main(["simulate", "-n", "100", "-s", "1", "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["stats"]["total"] == 100
    assert data["stats"]["allowed"] + data["stats"]["denied"] == 100


def test_validate_default_rules(capsys):
    assert main(["validate"]) == 0
    assert capsys.readouterr().out.startswith("OK")


def test_check_exit_codes(capsys):
    allowed = ["check", "--src", "198.51.100.5", "--dst", "192.168.1.10", "--dport", "443"]
    denied = ["check", "--src", "203.0.113.9", "--dst", "192.168.1.10", "--dport", "443"]
    assert main(allowed) == 0
    assert main(denied) == 1


def test_missing_rules_file_returns_error(capsys, tmp_path):
    assert main(["validate", "-r", str(tmp_path / "missing.json")]) == 2
    assert "error:" in capsys.readouterr().err
