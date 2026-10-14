import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


def _connect(session, ts):
    """A Cowrie session.connect line."""
    return json.dumps({"eventid": "cowrie.session.connect", "session": session, "timestamp": ts})


def _tag(tmp_path, lines, *extra):
    """Run the script on a gzipped log and return the sessions it tagged."""
    log = tmp_path / "cowrie.json.gz"
    with gzip.open(log, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    out = tmp_path / "tiers.jsonl"
    script = ROOT / "dev/scripts/tag_human_sessions.py"
    subprocess.run([sys.executable, str(script), str(log), "--out", str(out), *extra], check=True)
    return [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize(
    "extra, expected",
    [
        ((), ["a1", "b2"]),
        (("--since", "2026-10-14T10:30:00+00:00"), ["b2"]),
        (("--until", "2026-10-14T10:30:00+00:00"), ["a1"]),
    ],
)
def test_sessions_in_the_window_are_tagged_human(tmp_path, extra, expected):
    """Every session that connected in the window is written once, as human."""
    lines = [_connect("a1", "2026-10-14T10:00:00.000000Z"), _connect("b2", "2026-10-14T11:00:00Z"), _connect("a1", "2026-10-14T10:00:01Z")]
    assert _tag(tmp_path, lines, *extra) == [{"session": s, "tier": "human"} for s in expected]


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        json.dumps({"eventid": "cowrie.command.input", "session": "c3", "timestamp": "2026-10-14T10:00:00Z"}),
        json.dumps({"eventid": "cowrie.session.connect", "timestamp": "2026-10-14T10:00:00Z"}),
        json.dumps({"eventid": "cowrie.session.connect", "session": "d4", "timestamp": "yesterday"}),
    ],
)
def test_other_lines_are_ignored(tmp_path, line):
    """Malformed lines, non-connect events and events without a session or time tag nothing."""
    assert _tag(tmp_path, [line]) == []


def _step(run_id, ts):
    """An attacker-harness step record."""
    return json.dumps({"run_id": run_id, "ts": ts, "objective": "discovery", "step": 1})


def _tag_harness(tmp_path, connects, steps, *extra):
    """Run the script in --harness mode and return (session, run_id, tier) for each tagged run."""
    runs = tmp_path / "runs.jsonl"
    runs.write_text("\n".join(steps) + "\n", encoding="utf-8")
    return [(r["session"], r["run_id"], r["tier"]) for r in _tag(tmp_path, connects, "--harness", str(runs), *extra)]


@pytest.mark.parametrize(
    "connects, steps, expected",
    [
        (
            [_connect("s1", "2026-10-14T14:47:20Z"), _connect("s2", "2026-10-14T14:48:00Z")],
            [_step("r1", "2026-10-14T14:47:22+00:00"), _step("r1", "2026-10-14T14:47:40+00:00"),
             _step("r2", "2026-10-14T14:48:12.600000+00:00")],
            [("s1", "r1"), ("s2", "r2")],
        ),
        (
            [_connect("s0", "2026-10-14T15:07:30Z"), _connect("s1", "2026-10-14T15:07:49Z")],
            [_step("r1", "2026-10-14T15:08:01+00:00")],
            [("s1", "r1")],
        ),
    ],
)
def test_harness_runs_get_the_session_that_connected_last_before_them(tmp_path, connects, steps, expected):
    """Each run is matched once, to the latest unused session that connected shortly before its first step."""
    assert _tag_harness(tmp_path, connects, steps) == [(s, r, "llm_agent") for s, r in expected]


@pytest.mark.parametrize(
    "connect, extra",
    [("2026-10-14T14:47:30Z", ()), ("2026-10-14T14:46:00Z", ()), ("2026-10-14T14:47:10Z", ("--max-gap", "5"))],
)
def test_runs_without_a_session_just_before_them_are_left_out(tmp_path, connect, extra):
    """A session that connected after the run started, or longer than --max-gap before it, is not matched."""
    steps = [_step("r1", "2026-10-14T14:47:22+00:00"), "not json"]
    assert _tag_harness(tmp_path, [_connect("s1", connect)], steps, *extra) == []
