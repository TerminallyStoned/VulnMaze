"""Real-model evaluation: logic-trap behaviour, latency and realism.

Runs the golden command set through the *full* gateway pipeline against the
configured model, so what is measured is what an attacker would see. Writes a
CSV with two empty rating columns for the realism review, and prints a
summary. `score()` reads the CSV back after two people have rated it.
"""

from __future__ import annotations

import csv
import statistics
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from vulnmaze.llm import sanitize

CSV_FIELDS = ["id", "category", "command", "outcome", "exit_code", "stdout", "stderr", "latency_ms",
              "reasons", "trap_violation", "visible_leak", "rater_1", "rater_2"]


@dataclass
class GoldenCommand:
    id: str
    category: str
    argv: list[str]
    stdin: str | None = None


def load_golden(path: str | Path) -> list[GoldenCommand]:
    items = yaml.safe_load(Path(path).read_text())
    return [GoldenCommand(i["id"], i["cat"], [str(a) for a in i["cmd"]], i.get("pipe_stdin")) for i in items]


def trap_violation(category: str, outcome: str, exit_code: int) -> bool:
    """A logic trap is violated when the model claims success [3], [13].
    A fallback is not a violation (the attacker saw an error)."""
    return category == "trap" and outcome in ("generated", "pinned") and exit_code == 0


def visible_leak(detector: sanitize.LeakageDetector, stdout: str, stderr: str) -> list[str]:
    """Anything leak-like in what the attacker actually saw. Should always be
    empty: the gateway filters it. Measured anyway, as a regression check."""
    text = stdout + "\n" + stderr
    return detector.check(text) + sanitize.tells(stdout, stderr)


def summarise(rows: Sequence[dict]) -> dict:
    lat = sorted(int(r["latency_ms"]) for r in rows if r["outcome"] in ("generated", "fallback"))
    traps = [r for r in rows if r["category"] == "trap"]
    reasons = Counter(x.split(":")[0] for r in rows for x in (r["reasons"].split("|") if r["reasons"] else []))

    def pct(values, q):
        if not values:
            return None
        k = max(0, min(len(values) - 1, round(q * (len(values) - 1))))
        return values[k]

    return {
        "commands": len(rows),
        "outcomes": dict(Counter(r["outcome"] for r in rows)),
        "latency_ms_p50": pct(lat, 0.50),
        "latency_ms_p95": pct(lat, 0.95),
        "trap_violations": sum(str(r["trap_violation"]) == "True" for r in traps),
        "traps": len(traps),
        "visible_leaks": sum(bool(r["visible_leak"]) for r in rows),
        "rejection_reasons": dict(reasons.most_common()),
    }


def cohen_kappa(a: Sequence[int], b: Sequence[int]) -> float:
    """Cohen's kappa for two raters over the same items (binary or categorical)."""
    if len(a) != len(b) or not a:
        raise ValueError("need two equally long, non-empty rating lists")
    n = len(a)
    observed = sum(x == y for x, y in zip(a, b, strict=True)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)


def score(csv_path: str | Path) -> dict:
    """Realism from a rated CSV: rater_1/rater_2 are 1 (realistic) or
    0 (not). Rows with either rating missing are skipped."""
    with open(csv_path, newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if r["rater_1"].strip() and r["rater_2"].strip()]
    a = [int(r["rater_1"]) for r in rows]
    b = [int(r["rater_2"]) for r in rows]
    both = [x and y for x, y in zip(a, b, strict=True)]
    return {
        "rated": len(rows),
        "realistic_rater_1": round(statistics.fmean(a), 3) if a else None,
        "realistic_rater_2": round(statistics.fmean(b), 3) if b else None,
        "realistic_both": round(statistics.fmean(both), 3) if both else None,
        "cohen_kappa": round(cohen_kappa(a, b), 3) if rows else None,
    }
