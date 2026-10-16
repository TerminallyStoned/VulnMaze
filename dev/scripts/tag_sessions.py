import argparse
import json
from datetime import datetime

from vulnmaze.harness.matching import connected_sessions, harness_sessions


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
    sessions = connected_sessions(args.paths, args.since, args.until)
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
