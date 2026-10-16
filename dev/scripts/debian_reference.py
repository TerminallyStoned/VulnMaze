import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

import yaml


def main(argv: list[str] | None = None) -> int:
    """Run the golden set on a real Debian 12 container and pair each result with the honeypot's answer."""
    ap = argparse.ArgumentParser(description="Compare the honeypot's golden-set answers with a real Debian 12 server.")
    ap.add_argument("results", type=Path, help="CSV written by llm_eval.py run")
    ap.add_argument("--golden", type=Path, default=Path(__file__).parents[1] / "eval/golden_commands.yml")
    ap.add_argument("--container", default="vulnmaze-refvm", help="running container built from dev/eval/reference/Dockerfile")
    ap.add_argument("--out", required=True, type=Path, help="JSON file with both answers per command (real output cut at 4,000 characters)")
    args = ap.parse_args(argv)

    golden = yaml.safe_load(args.golden.read_text(encoding="utf-8"))
    with args.results.open(encoding="utf-8", newline="") as fh:
        honeypot = {r["id"]: r for r in csv.DictReader(fh)}
    missing = [g["id"] for g in golden if g["id"] not in honeypot]
    if missing:
        sys.exit(f"{args.results}: no answer for {', '.join(missing)}")

    pairs = []
    for g in golden:
        argv_ = [str(a) for a in g["cmd"]]
        p = subprocess.run(
            ["docker", "exec", "-i", "-w", "/root", args.container, "timeout", "25", *argv_],
            input=(g.get("pipe_stdin") or "").encode(),
            capture_output=True,
        )
        h = honeypot[g["id"]]
        pairs.append(
            {
                "id": g["id"],
                "category": g["cat"],
                "command": argv_,
                "stdin": g.get("pipe_stdin"),
                "real": {
                    "exit_code": p.returncode,
                    "stdout": p.stdout.decode(errors="replace")[:4000],
                    "stderr": p.stderr.decode(errors="replace")[:4000],
                },
                "honeypot": {"outcome": h["outcome"], "exit_code": int(h["exit_code"]), "stdout": h["stdout"], "stderr": h["stderr"]},
            }
        )
    args.out.write_text(json.dumps(pairs, indent=1, ensure_ascii=False), encoding="utf-8")
    model = [p for p in pairs if p["honeypot"]["outcome"] == "generated"]
    same = sum((p["real"]["exit_code"] == 0) == (p["honeypot"]["exit_code"] == 0) for p in model)
    print(f"{len(pairs)} commands -> {args.out}; {same} of {len(model)} model answers succeed or fail like the real server")
    return 0


if __name__ == "__main__":
    sys.exit(main())
