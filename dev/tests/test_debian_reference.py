import csv
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[2] / "dev/scripts/debian_reference.py"
FIELDS = ["id", "outcome", "exit_code", "stdout", "stderr"]


def _script(monkeypatch, exits):
    """The script with docker exec replaced by fixed exit codes per command name, recording each call."""
    spec = importlib.util.spec_from_file_location("debian_reference", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []

    def run(cmd, input, capture_output):
        calls.append((cmd, input))
        return SimpleNamespace(returncode=exits[cmd[cmd.index("25") + 1]], stdout=b"real out\n", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", run)
    return module, calls


def _files(tmp_path, rows):
    """A two-command golden set and a results CSV with the given honeypot rows."""
    golden = tmp_path / "golden.yml"
    golden.write_text("- {id: a, cat: system, cmd: [lsblk]}\n- {id: b, cat: trap, cmd: [vmstat, -Z], pipe_stdin: x}\n", encoding="utf-8")
    results = tmp_path / "results.csv"
    with results.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return golden, results


def test_each_command_runs_in_the_container_and_is_paired_with_the_honeypot(tmp_path, monkeypatch, capsys):
    """Every golden command runs once in the container with its stdin, and success or failure is compared for model answers."""
    module, calls = _script(monkeypatch, {"lsblk": 0, "vmstat": 1})
    golden, results = _files(tmp_path, [
        {"id": "a", "outcome": "generated", "exit_code": "0", "stdout": "NAME\n", "stderr": ""},
        {"id": "b", "outcome": "generated", "exit_code": "0", "stdout": "0s\n", "stderr": ""},
    ])
    out = tmp_path / "pairs.json"
    assert module.main([str(results), "--golden", str(golden), "--container", "ref", "--out", str(out)]) == 0
    assert [c[0][8:] for c in calls] == [["lsblk"], ["vmstat", "-Z"]] and [c[1] for c in calls] == [b"", b"x"]
    assert all(c[0][:8] == ["docker", "exec", "-i", "-w", "/root", "ref", "timeout", "25"] for c in calls)
    pairs = json.loads(out.read_text(encoding="utf-8"))
    assert [(p["id"], p["real"]["exit_code"], p["honeypot"]["exit_code"]) for p in pairs] == [("a", 0, 0), ("b", 1, 0)]
    assert "1 of 2 model answers succeed or fail like the real server" in capsys.readouterr().out


@pytest.mark.parametrize("ids", [["a"], []])
def test_results_missing_a_golden_command_stop_before_running_anything(tmp_path, monkeypatch, ids):
    """A results file without an answer for every golden command is refused, naming what is missing, and nothing runs."""
    module, calls = _script(monkeypatch, {"lsblk": 0, "vmstat": 1})
    golden, results = _files(tmp_path, [{"id": i, "outcome": "generated", "exit_code": "0", "stdout": "", "stderr": ""} for i in ids])
    with pytest.raises(SystemExit, match="no answer for .*b"):
        module.main([str(results), "--golden", str(golden), "--out", str(tmp_path / "pairs.json")])
    assert calls == []
