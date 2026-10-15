from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime
from pathlib import Path

import joblib

from vulnmaze.classify.baselines import MODELS, TASKS
from vulnmaze.classify.tier import session_features

CHOSEN = {"tactic": "random_forest", "severity": "random_forest_chars"}
HIGH = ("R3", "R4")


def fit(commands: list[dict]) -> dict:
    """Fit the chosen tactic and severity models on all distinct labelled lines."""
    models = {}
    for task in TASKS:
        rows = sorted({(c["input"], c[task]) for c in commands if c[task] is not None})
        if not rows:
            raise ValueError(f"no labelled {task} lines")
        models[task] = MODELS[CHOSEN[task]]().fit([x for x, _ in rows], [y for _, y in rows])
        models[task][-1].set_params(n_jobs=1)
    return models


def predict(models: dict, commands: list[dict]) -> dict:
    """Per-command tactic and severity, running session severity and attacker tier for a digest's commands."""
    rows = [c for c in commands if not c.get("realm") and (c.get("input") or "").strip()]
    if not rows:
        raise ValueError("the session has no commands")
    lines = [c["input"] for c in rows]
    labels = {}
    for task in TASKS:
        x = models[task][:-1].transform(lines)
        labels[task] = [
            y for i in range(0, x.shape[0], 32) for y in models[task][-1].predict(x[i : i + 32].toarray())
        ]
    out, top, high = [], "R0", 0
    for line, tactic, level in zip(lines, labels["tactic"], labels["severity"], strict=True):
        top, high = max(top, level), high + (level in HIGH)
        out.append(
            {"input": line, "tactic": tactic, "severity": level, "session_max": top, "session_high": high}
        )
    typed = [(datetime.fromisoformat(c["ts"]), c["input"]) for c in rows if not c.get("nested")]
    tier = None
    if models.get("tier") and len(typed) >= 2:
        features = session_features(sorted(typed))
        tier = models["tier"]["model"].predict([[features[f] for f in models["tier"]["features"]]])[0]
    return {"commands": out, "session_max": top, "session_high": high, "tier": tier}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Fit the chosen tactic and severity models on all labels and save them with the tier model."
    )
    ap.add_argument("--commands", required=True, type=Path, help="commands.jsonl written by vulnmaze-label")
    ap.add_argument("--tier", type=Path, help="tier.joblib written by vulnmaze-train-tier")
    ap.add_argument(
        "--out", required=True, type=Path, help="session_models.joblib to write, in infra/classifiers/"
    )
    args = ap.parse_args()
    commands = [json.loads(x) for x in args.commands.read_text(encoding="utf-8").split("\n") if x.strip()]
    models = fit(commands)
    if args.tier:
        models["tier"] = joblib.load(args.tier)
        models["tier"]["model"].set_params(n_jobs=1)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({**models, "chosen": CHOSEN}, args.out)
    sample = sorted({c["input"] for c in commands})[:200]
    timings = []
    for line in sample:
        t = time.perf_counter()
        predict(models, [{"ts": "2025-07-01T00:00:00+00:00", "input": line}])
        timings.append((time.perf_counter() - t) * 1000)
    print(
        json.dumps(
            {
                "chosen": CHOSEN,
                "tier": bool(args.tier),
                "saved": str(args.out),
                "ms_per_command": {
                    "median": round(statistics.median(timings), 2),
                    "p95": round(sorted(timings)[int(len(timings) * 0.95) - 1], 2),
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
