from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import Counter
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    matthews_corrcoef,
    mean_absolute_error,
    precision_recall_fscore_support,
)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline

TOKEN = r"[^\s;|&()<>'\"`=]+"
MODELS = {
    "tfidf_similarity": lambda: make_pipeline(
        TfidfVectorizer(token_pattern=TOKEN, sublinear_tf=True),
        KNeighborsClassifier(n_neighbors=1, metric="cosine", algorithm="brute"),
    ),
    "random_forest": lambda: make_pipeline(
        TfidfVectorizer(token_pattern=TOKEN, sublinear_tf=True),
        RandomForestClassifier(n_estimators=200, random_state=29, n_jobs=-1),
    ),
    "random_forest_chars": lambda: make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), sublinear_tf=True),
        RandomForestClassifier(n_estimators=200, random_state=29, n_jobs=-1),
    ),
}
TASKS = ("tactic", "severity")
SHAPE = [
    (re.compile(r"Changing password for \S+"), "Changing password for USER"),
    (re.compile(r"(?:ssh-rsa|ssh-ed25519|ecdsa-\S+)\s+\S+(?:\s+\S+)?"), "KEY"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "IP"),
    (re.compile(r"(?=[A-Za-z0-9+/=_.-]*\d)(?=[A-Za-z0-9+/=_.-]*[A-Za-z])[A-Za-z0-9+/=_.-]{6,}"), "TOK"),
    (re.compile(r"\b(?=[A-Za-z]*[a-z])(?=[A-Za-z]*[A-Z])[A-Za-z]{8,}\b"), "TOK"),
    (re.compile(r"\d+"), "N"),
    (re.compile(r"\s+"), " "),
]


def shape(line: str) -> str:
    """The command with keys, IPs, random tokens and numbers replaced, so bot lines that differ only in those match."""
    for rx, token in SHAPE:
        line = rx.sub(token, line)
    return line.strip()


def scores(truth: list[str], pred: list[str], task: str) -> dict:
    """Accuracy, macro precision, recall and F1, and MCC; for severity also the mean absolute error in levels."""
    p, r, f, _ = precision_recall_fscore_support(truth, pred, average="macro", zero_division=0)
    out = {
        "n": len(truth),
        "accuracy": accuracy_score(truth, pred),
        "precision": p,
        "recall": r,
        "f1": f,
        "mcc": matthews_corrcoef(truth, pred),
    }
    levels = [(t, q) for t, q in zip(truth, pred, strict=True) if t[:1] == "R" and q[:1] == "R"]
    if task == "severity" and levels:
        out["mae_levels"] = mean_absolute_error(
            [int(t[1]) for t, _ in levels], [int(q[1]) for _, q in levels]
        )
    return {k: round(float(v), 4) if k != "n" else v for k, v in out.items()}


def evaluate(commands: list[dict], test_day: str, gold: dict[str, dict] | None = None) -> tuple[dict, dict]:
    """Train each baseline on the days before test_day and score it on test_day.

    commands are rows of vulnmaze-label's commands.jsonl. Training uses each
    distinct (line, label) pair once, so a bot line seen 70,000 times weighs
    the same as a rare one. Each model is scored on every test-day line as it
    occurred, on the test-day lines whose shape never appears in training
    (bots repeat the same lines every day and vary only passwords, keys or
    addresses, which flatters the first score) and, when gold maps
    command lines to hand labels, against those labels, where the rules are
    scored too (a rule abstention counts as "unknown"). With gold, every
    training line that has the shape of a gold line is left out, so the
    models are scored on lines they never saw. Returns the metrics and the
    fitted models; raises ValueError when a split has no labelled lines.
    """
    results, fitted = {}, {}
    held_out = {shape(x) for x in gold or {}}
    for task in TASKS:
        rows = [(c["input"], c[task], c["ts"][:10]) for c in commands if c[task] is not None]
        train = sorted({(x, y) for x, y, day in rows if day < test_day and shape(x) not in held_out})
        test = [(x, y) for x, y, day in rows if day == test_day]
        if not train or not test:
            raise ValueError(f"no labelled {task} lines before or on {test_day}")
        seen = {shape(x) for x, _ in train}
        unseen = [(x, y) for x, y in test if shape(x) not in seen]
        judged = [(x, g[task]) for x, g in (gold or {}).items() if g.get(task) and g[task] != "unknown"]
        results[task] = {"train_distinct": len(train), "test_lines": len(test), "test_new_shape": len(unseen)}
        if judged:
            rule = {c["input"]: c[task] or "unknown" for c in commands}
            results[task]["rules"] = {
                "gold": scores([y for _, y in judged], [rule.get(x, "unknown") for x, _ in judged], task)
            }
        for name, make in MODELS.items():
            model = make().fit([x for x, _ in train], [y for _, y in train])
            lines = sorted({x for x, _ in test} | {x for x, _ in judged})
            guess = dict(zip(lines, model.predict(lines), strict=True))
            results[task][name] = {
                "test": scores([y for _, y in test], [guess[x] for x, _ in test], task),
                "test_new_shape": scores([y for _, y in unseen], [guess[x] for x, _ in unseen], task)
                if unseen
                else None,
            }
            if judged:
                results[task][name]["gold"] = scores(
                    [y for _, y in judged], [guess[x] for x, _ in judged], task
                )
            fitted[f"{task}_{name}"] = model
    return results, fitted


def cross_validate(commands: list[dict], folds: int = 5) -> dict:
    """Score each baseline on command shapes it never saw, by cross-validation grouped by shape.

    The labels are made per shape, so a shape is the unit: the shapes are
    split into folds, each model trains on the distinct lines of the other
    folds and is scored on the most frequent line of each held-out shape, so
    every shape counts once however often bots send it. Raises ValueError
    when folds is below 2 or above the number of labelled shapes.
    """
    results = {}
    for task in TASKS:
        by_shape: dict[str, list[tuple[int, str, str]]] = {}
        for (x, y), n in Counter((c["input"], c[task]) for c in commands if c[task] is not None).items():
            by_shape.setdefault(shape(x), []).append((n, x, y))
        shapes = sorted(by_shape)
        if not 2 <= folds <= len(shapes):
            raise ValueError(f"{folds} folds for {len(shapes)} labelled {task} shapes")
        random.Random(29).shuffle(shapes)
        results[task] = {"shapes": len(shapes), "folds": folds}
        for name, make in MODELS.items():
            truth, pred = [], []
            for k in range(folds):
                test = set(shapes[k::folds])
                train = [(x, y) for s in shapes if s not in test for _, x, y in by_shape[s]]
                model = make().fit([x for x, _ in train], [y for _, y in train])
                reps = [max(by_shape[s]) for s in sorted(test)]
                truth += [y for _, _, y in reps]
                pred += list(model.predict([x for _, x, _ in reps]))
            results[task][name] = scores(truth, pred, task)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Train and score the tactic and severity baselines (TF-IDF similarity, random forest)."
    )
    ap.add_argument("--commands", required=True, type=Path, help="commands.jsonl written by vulnmaze-label")
    ap.add_argument(
        "--out", required=True, type=Path, help="directory for metrics.json and the models, outside the repo"
    )
    ap.add_argument("--test-day", default="2025-07-01", help="day held out for testing; earlier days train")
    ap.add_argument("--gold", type=Path, help="hand-labelled CSV with command, tactic and severity columns")
    ap.add_argument(
        "--cv-folds", type=int, default=5, help="folds for cross-validation grouped by shape; 0 skips it"
    )
    args = ap.parse_args()
    commands = [json.loads(x) for x in args.commands.read_text(encoding="utf-8").split("\n") if x.strip()]
    gold = None
    if args.gold:
        with args.gold.open(encoding="utf-8-sig", newline="") as fh:
            gold = {r["command"]: {t: (r[t] or "").strip() for t in TASKS} for r in csv.DictReader(fh)}
    results, fitted = evaluate(commands, args.test_day, gold)
    if args.cv_folds:
        results["shape_cv"] = cross_validate(commands, args.cv_folds)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    for name, model in fitted.items():
        joblib.dump(model, args.out / f"{name}.joblib")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
