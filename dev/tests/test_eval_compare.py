import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "dev/scripts/eval_compare.py"
T0 = datetime(2026, 10, 15, 8, 0, tzinfo=UTC)
BAIT = "/var/www/portal/config/database.php"


def _at(s):
    """T0 plus s seconds, as Cowrie writes timestamps."""
    return (T0 + timedelta(seconds=s)).isoformat().replace("+00:00", "Z")


def _compare(tmp_path, *folders):
    """Run the script with the Cowrie logs in tmp_path and return the process and its JSON numbers."""
    out = tmp_path / "numbers.json"
    logs = sorted(map(str, tmp_path.glob("cowrie.json*")))
    p = subprocess.run([sys.executable, str(SCRIPT), *map(str, folders), "--cowrie", *logs, "--json", str(out)], capture_output=True, text=True)
    return p, json.loads(out.read_text()) if out.exists() else None


def _write(tmp_path, cat_at, run_at=5, rotate_at=None):
    """One learned run folder with an answered session given bait, and a Cowrie log where the bait is read at cat_at seconds, rotated at rotate_at seconds."""
    folder = tmp_path / "eval-learned"
    folder.mkdir()
    steps = [
        {"run_id": "r1", "objective": "discovery", "step": 1, "command": "uname -a", "done": False, "prompt_tokens": 100, "completion_tokens": 20, "ts": (T0 + timedelta(seconds=run_at)).isoformat()},
        {"run_id": "r1", "objective": "discovery", "step": 2, "command": f"cat {BAIT}", "done": True, "prompt_tokens": 200, "completion_tokens": 40, "ts": (T0 + timedelta(seconds=run_at + 5)).isoformat()},
        {"run_id": "r2", "objective": "persistence", "step": 1, "error": "HTTP 400: rejected", "ts": (T0 + timedelta(seconds=500)).isoformat()},
    ]
    (folder / "harness-1.jsonl").write_text("".join(json.dumps(s) + "\n" for s in steps), encoding="utf-8")
    events = [
        {"eventid": "cowrie.session.connect", "session": "s1", "timestamp": _at(0)},
        {"eventid": "cowrie.command.input", "session": "s1", "input": "uname -a", "timestamp": _at(5)},
        {"eventid": "cowrie.vulnmaze.route", "session": "s1", "route": "escalate_candidate", "timestamp": _at(5)},
        {"eventid": "cowrie.vulnmaze.llm", "session": "s1", "outcome": "generated", "latency_ms": 900, "reasons": ["learned:llm_agent:0.8:R1:0"], "timestamp": _at(6)},
        {"eventid": "cowrie.vulnmaze.bait", "session": "s1", "paths": [BAIT], "timestamp": _at(7)},
        {"eventid": "cowrie.command.input", "session": "s1", "input": f"cat {BAIT}", "timestamp": _at(cat_at)},
    ]
    events.sort(key=lambda e: e["timestamp"])
    rotated = [e for e in events if rotate_at is not None and e["timestamp"] < _at(rotate_at)]
    if rotated:
        (tmp_path / "cowrie.json.2026-10-15").write_text("".join(json.dumps(e) + "\n" for e in rotated), encoding="utf-8")
    (tmp_path / "cowrie.json").write_text("".join(json.dumps(e) + "\n" for e in events if e not in rotated), encoding="utf-8")
    return folder


@pytest.mark.parametrize("cat_at, touching, rotate_at", [(10, 1, None), (6, 0, None), (10, 1, 6.5)])
def test_compare_counts_engagement_gateway_learned_and_bait_use(tmp_path, cat_at, touching, rotate_at):
    """A matched run's steps, goal, tokens, gateway answer, tier and bait are counted, also across a rotated log; reading the bait counts only after it was planted."""
    p, numbers = _compare(tmp_path, _write(tmp_path, cat_at, rotate_at=rotate_at))
    assert p.returncode == 0 and "| Sessions touching bait |" in p.stdout
    assert numbers["eval-learned"] == {
        "runs": 2, "matched": 1, "steps": 2, "steps_median": 1.0, "goal_reached": 1, "attacker_errors": 1,
        "tokens_median": 240, "tokens_per_objective": {"discovery": 240}, "gateway_stages": 1,
        "outcomes": {"generated": 1}, "answer_ms_median": 900, "tiers": {"llm_agent": 1},
        "sessions_with_bait": 1, "sessions_touching_bait": touching,
    }


@pytest.mark.parametrize("case", ["missing folder", "folder without a run", "run matching no session"])
def test_bad_folders_stop_and_unmatched_runs_count_zero(tmp_path, case):
    """A missing folder or one without a run file stops with a message; a run that matches no Cowrie session is reported as unmatched."""
    folder = _write(tmp_path, 10, run_at=200 if case == "run matching no session" else 5)
    if case == "missing folder":
        folder = tmp_path / "eval-none"
    if case == "folder without a run":
        folder = tmp_path / "eval-empty"
        folder.mkdir()
    p, numbers = _compare(tmp_path, folder)
    if case == "run matching no session":
        assert p.returncode == 0 and numbers["eval-learned"]["matched"] == 0 and numbers["eval-learned"]["sessions_with_bait"] == 0
    else:
        assert p.returncode != 0 and str(folder.name) in p.stderr and numbers is None
