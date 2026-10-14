from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold

from vulnmaze.classify.baselines import scores

TIERS = ("bot", "human", "llm_agent")
FEATURES = (
    "n_commands",
    "gap_mean",
    "gap_median",
    "gap_std",
    "gap_cv",
    "gap_min",
    "gap_max",
    "fast_gaps",
    "slow_gaps",
    "len_mean",
    "len_max",
    "pipes",
    "chains",
    "words_mean",
    "distinct_programs",
    "transition_entropy",
)
VARIANTS = {
    "all_features": FEATURES,
    "without_count": tuple(f for f in FEATURES if f != "n_commands"),
    "count_only": ("n_commands",),
}


def session_features(commands: list[tuple[datetime, str]]) -> dict[str, float]:
    """Timing, structure and behaviour features of one session from its typed commands (time, text) in time order.

    Only what every Cowrie logs is used, so sessions from plain Cowrie and
    from VulnMaze are described the same way. Raises ValueError for fewer
    than two commands, which have no gaps.
    """
    if len(commands) < 2:
        raise ValueError("a session needs at least two commands")
    texts = [x for _, x in commands]
    gaps = [(b - a).total_seconds() for (a, _), (b, _) in zip(commands, commands[1:], strict=False)]
    programs = [x.split()[0] if x.split() else "" for x in texts]
    pairs = Counter(zip(programs, programs[1:], strict=False))
    mean, std = statistics.fmean(gaps), statistics.pstdev(gaps)
    return {
        "n_commands": len(texts),
        "gap_mean": mean,
        "gap_median": statistics.median(gaps),
        "gap_std": std,
        "gap_cv": std / mean if mean else 0.0,
        "gap_min": min(gaps),
        "gap_max": max(gaps),
        "fast_gaps": sum(g < 0.5 for g in gaps) / len(gaps),
        "slow_gaps": sum(g > 10 for g in gaps) / len(gaps),
        "len_mean": statistics.fmean(len(x) for x in texts),
        "len_max": max(len(x) for x in texts),
        "pipes": sum("|" in x for x in texts) / len(texts),
        "chains": sum(";" in x or "&&" in x for x in texts) / len(texts),
        "words_mean": statistics.fmean(len(x.split()) for x in texts),
        "distinct_programs": len(set(programs)) / len(programs),
        "transition_entropy": -sum(n / len(gaps) * math.log2(n / len(gaps)) for n in pairs.values()),
    }


def load_sessions(
    paths: list[Path], tiers: dict[str, str], min_commands: int = 2, bot_sample: int = 3000, seed: int = 29
) -> list[tuple[str, str, dict[str, float]]]:
    """(session, tier, features) for every labelled session with at least min_commands commands.

    paths are JSONL exports of the events table (source, session, eventid,
    ts, input, data). A session's tier comes from tiers, else bot for public
    data; anything else is skipped. Bots are a fixed-seed random sample of
    bot_sample sessions; every human and LLM-agent session is kept.
    """
    commands: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    sources: dict[str, str] = {}
    for path in paths:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                e = json.loads(line)
                if e.get("eventid") != "cowrie.command.input" or not e.get("input"):
                    continue
                sources[e["session"]] = e["source"]
                commands[e["session"]].append((datetime.fromisoformat(e["ts"]), e["input"]))
    found: dict[str, list[tuple[str, dict[str, float]]]] = {t: [] for t in TIERS}
    for session, cmds in commands.items():
        tier = tiers.get(session) or ("bot" if sources[session].startswith("public:") else None)
        if tier in found and len(cmds) >= min_commands:
            found[tier].append((session, session_features(sorted(cmds))))
    bots = sorted(found["bot"], key=lambda r: r[0])
    found["bot"] = random.Random(seed).sample(bots, min(bot_sample, len(bots)))
    return [(s, t, f) for t in TIERS for s, f in found[t]]


def evaluate(
    rows: list[tuple[str, str, dict[str, float]]], folds: int = 5, seeds: tuple[int, ...] = (29, 1, 2, 3, 4)
) -> dict:
    """Repeated stratified cross-validation of the tier model per feature set, against always answering bot.

    Each variant reports the mean and range over the seeds of the overall
    scores, per-tier recall and precision on the predictions pooled over the
    seeds, and the pooled confusion matrix (rows true, columns predicted, in
    TIERS order). Raises ValueError when a tier has fewer sessions than folds.
    """
    y = [t for _, t, _ in rows]
    small = {t: n for t, n in Counter(y).items() if n < folds}
    if small or set(y) != set(TIERS):
        raise ValueError(f"every tier needs at least {folds} sessions, got {dict(Counter(y))}")
    results = {"sessions": dict(Counter(y)), "folds": folds, "seeds": list(seeds)}
    for name, cols in {**VARIANTS, "always_bot": ()}.items():
        x = [[f[c] for c in cols] for _, _, f in rows]
        per_seed, pooled_true, pooled_pred = [], [], []
        for seed in seeds:
            pred = ["bot"] * len(y)
            if cols:
                for train, test in StratifiedKFold(folds, shuffle=True, random_state=seed).split(x, y):
                    model = RandomForestClassifier(
                        n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1
                    )
                    model.fit([x[i] for i in train], [y[i] for i in train])
                    for i, p in zip(test, model.predict([x[i] for i in test]), strict=True):
                        pred[i] = p
            per_seed.append(scores(y, pred, "tier"))
            pooled_true += y
            pooled_pred += pred
        matrix = confusion_matrix(pooled_true, pooled_pred, labels=list(TIERS))
        results[name] = {
            "features": list(cols),
            **{
                k: {
                    "mean": round(statistics.fmean(s[k] for s in per_seed), 4),
                    "min": min(s[k] for s in per_seed),
                    "max": max(s[k] for s in per_seed),
                }
                for k in ("accuracy", "f1", "mcc")
            },
            "recall": {t: round(float(matrix[i][i] / matrix[i].sum()), 4) for i, t in enumerate(TIERS)},
            "precision": {
                t: round(float(matrix[i][i] / matrix[:, i].sum()), 4) if matrix[:, i].sum() else 0.0
                for i, t in enumerate(TIERS)
            },
            "confusion": matrix.tolist(),
        }
    return results


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Train and score the attacker-tier classifier (bot, human, LLM agent)."
    )
    ap.add_argument("--events", required=True, nargs="+", type=Path, help="JSONL exports of the events table")
    ap.add_argument("--tiers", nargs="*", type=Path, default=[], help="JSONL files with session and tier")
    ap.add_argument("--min-commands", type=int, default=2, help="sessions with fewer commands are skipped")
    ap.add_argument("--bot-sample", type=int, default=3000, help="bot sessions sampled, fixed seed")
    ap.add_argument(
        "--model", choices=sorted(VARIANTS), default="without_count", help="feature set of the saved model"
    )
    ap.add_argument(
        "--out", required=True, type=Path, help="directory for metrics.json and tier.joblib, outside the repo"
    )
    args = ap.parse_args()
    tiers = {}
    for path in args.tiers:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                tiers[row["session"]] = row["tier"]
    rows = load_sessions(args.events, tiers, args.min_commands, args.bot_sample)
    results = evaluate(rows)
    cols = VARIANTS[args.model]
    model = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=29, n_jobs=-1)
    model.fit([[f[c] for c in cols] for _, _, f in rows], [t for _, t, _ in rows])
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    joblib.dump({"features": list(cols), "model": model}, args.out / "tier.joblib")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
