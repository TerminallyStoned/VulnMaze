import argparse
import json
from datetime import datetime, timedelta

from vulnmaze.ingest.public import iter_events


def human_sessions(
    paths: list[str], since: datetime | None = None, until: datetime | None = None
) -> dict[str, datetime]:
    """Session ids, with their connect time, of the sessions that connected within [since, until] in Cowrie JSON logs (plain or .gz)."""
    found: dict[str, datetime] = {}
    for path in paths:
        for line in iter_events(path):
            try:
                event = json.loads(line)
                ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
            if event.get("eventid") != "cowrie.session.connect" or not event.get("session"):
                continue
            if (since and ts < since) or (until and ts > until):
                continue
            found.setdefault(event["session"], ts)
    return found


def harness_sessions(sessions: dict[str, datetime], runs_path: str, max_gap: float = 30.0) -> list[dict]:
    """Match each attacker-harness run to the Cowrie session that connected last before its first step.

    Behind Docker Desktop's port forwarder Cowrie logs a different source
    port from the one the harness records, so runs are matched by time: runs
    go one at a time, and a run's session is the latest unused one that
    connected at most max_gap seconds before the run's first step. Runs with
    no such session are left out.
    """
    runs: dict[str, dict] = {}
    with open(runs_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                step = json.loads(line)
                ts = datetime.fromisoformat(step["ts"])
                run = runs.setdefault(step["run_id"], {"first": ts, "objective": step.get("objective")})
            except (ValueError, KeyError, TypeError):
                continue
            run["first"] = min(run["first"], ts)
    tagged, used = [], set()
    for run_id, run in sorted(runs.items(), key=lambda kv: kv[1]["first"]):
        earlier = [
            (ts, s)
            for s, ts in sessions.items()
            if s not in used and run["first"] - timedelta(seconds=max_gap) <= ts <= run["first"]
        ]
        if earlier:
            session = max(earlier)[1]
            used.add(session)
            tagged.append({"session": session, "tier": "llm_agent", "run_id": run_id, "objective": run["objective"]})
    return tagged


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Write a vulnmaze-label --tiers file marking sessions as human, or as llm_agent with --harness."
    )
    ap.add_argument("paths", nargs="+", help="cowrie.json files from volunteers or this honeypot")
    ap.add_argument("--since", type=datetime.fromisoformat, help="ISO time with offset, e.g. 2026-10-14T10:00+08:00")
    ap.add_argument("--until", type=datetime.fromisoformat)
    ap.add_argument("--harness", help="attacker-harness run file (dev/harness_runs/*.jsonl): tag its sessions llm_agent")
    ap.add_argument("--max-gap", type=float, default=30.0, help="seconds a run's session may connect before its first step")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    sessions = human_sessions(args.paths, args.since, args.until)
    rows = (
        harness_sessions(sessions, args.harness, args.max_gap)
        if args.harness
        else [{"session": s, "tier": "human"} for s in sessions]
    )
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    print(f"{len(rows)} {'llm_agent' if args.harness else 'human'} sessions written to {args.out}")


if __name__ == "__main__":
    main()
