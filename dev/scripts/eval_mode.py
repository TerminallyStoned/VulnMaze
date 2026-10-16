import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from vulnmaze.harness.objectives import OBJECTIVES
from vulnmaze.harness.runner import load_env_file

ROOT = Path(__file__).parents[2]


def main(argv: list[str] | None = None) -> int:
    """Run one escalation mode end to end: restart, check, clear stored answers, run the harness, summarise."""
    ap = argparse.ArgumentParser(description="Run one evaluation mode of the attacker harness against the local stack.")
    ap.add_argument("mode", choices=["off", "all", "learned"])
    ap.add_argument("--model", help="OpenRouter attacker model; default OPENROUTER_MODEL in infra/.env")
    ap.add_argument("--reasoning", action=argparse.BooleanOptionalAction, default=True, help="keep the attacker's reasoning on")
    ap.add_argument("--sessions", type=int, default=6, help="sessions per objective")
    ap.add_argument("--max-steps", type=int, default=30, help="commands per session")
    ap.add_argument("--gpu", action=argparse.BooleanOptionalAction, default=True, help="add infra/docker-compose.gpu.yml")
    ap.add_argument("--runs", type=Path, default=ROOT / "dev/harness_runs", help="parent folder of the run folders")
    ap.add_argument("--fresh-attacker", action="store_true", help="run one session at a time and clear stored answers before each, so every session is a new attacker")
    ap.add_argument("--bait-prepare", action=argparse.BooleanOptionalAction, default=True, help="let the gateway prepare bait in advance (learned)")
    ap.add_argument("--dry-run", action="store_true", help="print the commands and stop")
    args = ap.parse_args(argv)

    load_env_file(ROOT / "infra/.env")
    model = args.model or os.environ.get("OPENROUTER_MODEL", "").strip()
    if not model:
        sys.exit("no attacker model: set OPENROUTER_MODEL in infra/.env or pass --model")
    out = args.runs / f"eval-{model.replace('/', '-')}-{args.mode}"
    if any(out.glob("*.jsonl")):
        sys.exit(f"{out} already has a run file; move or delete it to run {args.mode} again")
    dc = ["docker", "compose", "-f", "infra/docker-compose.yml", *(["-f", "infra/docker-compose.gpu.yml"] if args.gpu else [])]
    up = [*dc, "up", "-d", "--build", "--wait"]
    harness = [sys.executable, "-m", "vulnmaze.harness.runner", "--env-file", "infra/.env", "--model", model]
    harness += ["--max-steps", str(args.max_steps), "--out", str(out), *(["--reasoning"] if args.reasoning else [])]
    runs = (
        [[*harness, "--objective", o, "--sessions", "1"] for o in OBJECTIVES for _ in range(args.sessions)]
        if args.fresh_attacker
        else [[*harness, "--sessions", str(args.sessions)]]
    )
    env = {"VULNMAZE_ESCALATION": args.mode, "VULNMAZE_BAIT_PREPARE": "on" if args.bait_prepare else "off"}
    if args.dry_run:
        print(" ".join(f"{k}={v}" for k, v in env.items()), " ".join(up))
        print("\n".join(" ".join(r) for r in runs))
        return 0
    if args.mode == "learned" and not (ROOT / "infra/classifiers/session_models.joblib").is_file():
        sys.exit("learned needs infra/classifiers/session_models.joblib (see docs/harness.md)")

    print(f"== 1/5 restarting the stack in {args.mode} mode", flush=True)
    subprocess.run(up, cwd=ROOT, env={**os.environ, **env}, check=True)

    print("== 2/5 checking the mode in both containers", flush=True)
    for service in ("cowrie", "llm-gateway"):
        got = subprocess.run([*dc, "exec", "-T", service, "printenv", "VULNMAZE_ESCALATION"], cwd=ROOT, capture_output=True, text=True, check=True)
        if got.stdout.strip() != args.mode:
            sys.exit(f"{service} runs {got.stdout.strip()!r}, not {args.mode!r}")

    if args.mode != "off":
        print("== 3/5 waiting for the honeypot's model to load", flush=True)
        probe = "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=5).read().decode())"
        for _ in range(60):
            got = subprocess.run([*dc, "exec", "-T", "llm-gateway", "python", "-c", probe], cwd=ROOT, capture_output=True, text=True)
            health = json.loads(got.stdout or "{}")
            if health.get("model_failed"):
                sys.exit(f"the gateway could not load {health.get('backend')}; check VULNMAZE_LLM_MODEL in infra/.env and your shell")
            if health.get("model_ready"):
                print(f"   {health['backend']} ready", flush=True)
                break
            time.sleep(10)
        else:
            sys.exit("the model did not load within 10 minutes")

    print("== 4/5 clearing stored answers (attacker_facts); logs are kept", flush=True)
    psql = [*dc, "exec", "-T", "postgres", "psql", "-U", "vulnmaze", "-d", "vulnmaze", "-At", "-c"]
    subprocess.run([*psql, "TRUNCATE attacker_facts"], cwd=ROOT, check=True, capture_output=True)

    start = datetime.now(UTC).isoformat()
    print(f"== 5/5 running the harness into {out}", flush=True)
    for run in runs:
        if args.fresh_attacker:
            subprocess.run([*psql, "TRUNCATE attacker_facts"], cwd=ROOT, check=True, capture_output=True)
        subprocess.run(run, cwd=ROOT, check=True)
        time.sleep(1.1 if args.fresh_attacker else 0)

    files = sorted(out.glob("*.jsonl"))
    rows = [json.loads(line) for f in files for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]
    sessions = {r["run_id"] for r in rows}
    steps = [r for r in rows if not r.get("error")]
    errors = Counter(r["error"][:100] for r in rows if r.get("error"))
    done = {r["run_id"] for r in rows if r.get("done")}
    calls = subprocess.run([*psql, f"SELECT outcome, count(*) FROM llm_calls WHERE ts > '{start}' GROUP BY 1 ORDER BY 1"], cwd=ROOT, capture_output=True, text=True, check=True)
    outcomes = dict(line.split("|") for line in calls.stdout.split())
    print(f"\n{args.mode}: {out} ({len(files)} run files)\n  sessions {len(sessions)}, steps {len(steps)}, goal reached {len(done)}, models {sorted({r.get('model') for r in rows})}")
    print(f"  gateway outcomes {outcomes or 'none'}")
    for error, n in errors.most_common(3):
        print(f"  attacker error x{n}: {error}")
    if len(steps) < len(sessions):
        print("  WARNING: some sessions have no steps; the attacker model failed (see the errors above)")
    if args.mode == "off" and outcomes:
        print("  WARNING: the gateway answered in off mode")
    if args.mode != "off" and "fallback" in outcomes:
        print("  NOTE: some commands got the fallback answer; check llm_calls reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
