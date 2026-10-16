import argparse
import json
import posixpath
import statistics
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from vulnmaze.harness.matching import connected_sessions, harness_sessions

ROOT = Path(__file__).parents[2]


def compare(folder: Path, events: dict[str, list[dict]], sessions: dict) -> dict:
    """Engagement, gateway, learned and bait numbers for the harness runs in one run folder."""
    runs = sorted(folder.glob("*.jsonl"))
    if not runs:
        raise SystemExit(f"{folder}: no run file")
    steps, done, errors, tokens = Counter(), set(), 0, {}
    objective = {}
    tagged = []
    for run in runs:
        for line in run.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            objective[r["run_id"]] = r.get("objective")
            if r.get("error"):
                errors += 1
                continue
            steps[r["run_id"]] += 1
            if r.get("done"):
                done.add(r["run_id"])
            if r.get("prompt_tokens") is not None:
                tokens[r["run_id"]] = r["prompt_tokens"] + r.get("completion_tokens", 0)
        tagged += harness_sessions(sessions, str(run))
    gaps, outcomes, tiers, latency, touched = 0, Counter(), Counter(), [], set()
    plants = [
        (e["timestamp"], name, t["session"])
        for t in tagged
        for e in events.get(t["session"], [])
        if e["eventid"] == "cowrie.vulnmaze.bait"
        for path in e.get("paths") or []
        for name in (path, posixpath.basename(path))
    ]
    for t in tagged:
        for e in events.get(t["session"], []):
            eid = e["eventid"]
            gaps += eid == "cowrie.vulnmaze.route" and e.get("route") == "escalate_candidate"
            if eid == "cowrie.vulnmaze.llm":
                outcomes[e.get("outcome")] += 1
                tiers.update(r.split(":")[1] for r in e.get("reasons") or [] if r.startswith("learned:"))
                if e.get("outcome") == "generated":
                    latency.append(e.get("latency_ms") or 0)
            if eid == "cowrie.command.input" and any(
                at <= e["timestamp"] and name in (e.get("input") or "") for at, name, _ in plants
            ):
                touched.add(t["session"])
    per_objective = defaultdict(list)
    for run_id, n in tokens.items():
        per_objective[objective[run_id]].append(n)
    n = [steps[r] for r in objective]
    return {
        "runs": len(objective),
        "matched": len(tagged),
        "steps": sum(n),
        "steps_median": statistics.median(n) if n else 0,
        "goal_reached": len(done),
        "attacker_errors": errors,
        "tokens_median": statistics.median(tokens.values()) if tokens else None,
        "tokens_per_objective": {k: statistics.median(v) for k, v in sorted(per_objective.items())},
        "gateway_stages": gaps,
        "outcomes": dict(sorted(outcomes.items())),
        "answer_ms_median": statistics.median(latency) if latency else None,
        "tiers": dict(sorted(tiers.items())),
        "sessions_with_bait": len({s for _, _, s in plants}),
        "sessions_reading_bait": len(touched),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare evaluation runs (one folder per mode) in one table.")
    ap.add_argument("folders", nargs="+", type=Path, help="run folders written by eval_mode.py")
    ap.add_argument("--cowrie", nargs="+", type=Path, help="cowrie.json and its rotated cowrie.json.<date> files; default: all of them, copied from the running cowrie container")
    ap.add_argument("--json", type=Path, help="also write the numbers as JSON")
    args = ap.parse_args()
    for folder in args.folders:
        if not folder.is_dir():
            sys.exit(f"{folder}: not a folder")
    logs = args.cowrie
    if logs is None:
        copy = Path(tempfile.mkdtemp()) / "cowrie"
        cp = ["docker", "compose", "-f", "infra/docker-compose.yml", "cp", "cowrie:/cowrie/var/log/cowrie", str(copy)]
        subprocess.run(cp, cwd=ROOT, check=True, capture_output=True)
        logs = sorted(copy.glob("cowrie.json*"))
    events = defaultdict(list)
    for log in logs:
        for line in log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                e = json.loads(line)
                events[e.get("session")].append(e)
    for session_events in events.values():
        session_events.sort(key=lambda e: e.get("timestamp", ""))
    sessions = connected_sessions([str(log) for log in logs])
    results = {f.name: compare(f, events, sessions) for f in args.folders}
    rows = [
        ("Sessions (matched to Cowrie)", lambda r: f"{r['runs']} ({r['matched']})"),
        ("Attacker steps (median per session)", lambda r: f"{r['steps']} ({r['steps_median']})"),
        ("Sessions reaching their goal", lambda r: r["goal_reached"]),
        ("Attacker errors", lambda r: r["attacker_errors"]),
        ("Attacker tokens per session (median)", lambda r: r["tokens_median"] if r["tokens_median"] is not None else "n/a"),
        ("Stages sent to the gateway", lambda r: r["gateway_stages"]),
        ("Gateway outcomes", lambda r: ", ".join(f"{k} {v}" for k, v in r["outcomes"].items()) or "none"),
        ("Model answer time, median (ms)", lambda r: r["answer_ms_median"] if r["answer_ms_median"] is not None else "n/a"),
        ("learned tiers", lambda r: ", ".join(f"{k} {v}" for k, v in r["tiers"].items()) or "none"),
        ("Sessions given bait", lambda r: r["sessions_with_bait"]),
        ("Sessions reading bait (after it was planted)", lambda r: r["sessions_reading_bait"]),
    ]
    print("| | " + " | ".join(results) + " |")
    print("|---|" + "---|" * len(results))
    for name, cell in rows:
        print(f"| {name} | " + " | ".join(str(cell(r)) for r in results.values()) + " |")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
