import json
from datetime import UTC, datetime, timedelta

import pytest

from vulnmaze.classify.tier import TIERS, evaluate, load_sessions, session_features

T0 = datetime(2026, 10, 14, 10, 0, tzinfo=UTC)


def _commands(gaps, texts):
    """(time, text) pairs that start at T0 and are separated by the given gaps in seconds."""
    times = [T0]
    for g in gaps:
        times.append(times[-1] + timedelta(seconds=g))
    return list(zip(times, texts, strict=True))


@pytest.mark.parametrize(
    "gaps, texts, expected",
    [
        ([0.1, 0.1], ["uname -a", "id", "uname -a"], {"gap_mean": 0.1, "fast_gaps": 1.0, "slow_gaps": 0.0, "distinct_programs": 2 / 3}),
        ([12.0, 30.0], ["ls /etc | grep ssh", "cat a; cat b", "whoami"], {"gap_max": 30.0, "slow_gaps": 1.0, "pipes": 1 / 3, "chains": 1 / 3}),
        ([2.0, 2.0, 2.0], ["ls", "ls", "ls", "ls"], {"gap_cv": 0.0, "transition_entropy": 0.0, "n_commands": 4}),
    ],
)
def test_session_features_describe_timing_and_structure(gaps, texts, expected):
    """Gap statistics, command structure and program transitions come out as computed by hand."""
    features = session_features(_commands(gaps, texts))
    assert {k: features[k] for k in expected} == pytest.approx(expected)


@pytest.mark.parametrize("texts", [[], ["uname -a"]])
def test_sessions_with_fewer_than_two_commands_are_rejected(texts):
    """A session without at least one gap has no timing features."""
    with pytest.raises(ValueError):
        session_features(_commands([0.5] * max(len(texts) - 1, 0), texts))


def _event(source, session, i, text):
    """A command.input row as the events export writes it."""
    ts = (T0 + timedelta(seconds=i)).isoformat()
    return json.dumps({"source": source, "session": session, "eventid": "cowrie.command.input", "ts": ts, "input": text, "data": {}})


@pytest.mark.parametrize("bot_sample, expected_bots", [(1, 1), (5, 2)])
def test_load_sessions_labels_samples_and_skips(tmp_path, bot_sample, expected_bots):
    """Tiers come from the tier files or public data; short or unlabelled sessions are skipped; bots are sampled."""
    lines = [_event("public:cow", "b1", i, "uname -a") for i in range(3)]
    lines += [_event("public:cow", "b2", i, "id") for i in range(2)]
    lines += [_event("public:cow", "b3", 0, "id")]
    lines += [_event("public:human-me", "h1", i, "ls -la") for i in range(4)]
    lines += [_event("live", "a1", i, "cat /etc/passwd") for i in range(3)]
    lines += [_event("live", "x1", i, "whoami") for i in range(3)]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows = load_sessions([path], {"h1": "human", "a1": "llm_agent"}, bot_sample=bot_sample)
    tiers = [t for _, t, _ in rows]
    assert tiers.count("bot") == expected_bots and tiers.count("human") == 1 and tiers.count("llm_agent") == 1
    assert {s for s, _, _ in rows} <= {"b1", "b2", "h1", "a1"}


@pytest.mark.parametrize("counts", [{"bot": 10, "human": 4, "llm_agent": 10}, {"bot": 10, "llm_agent": 10}])
def test_evaluate_needs_enough_sessions_of_every_tier(counts):
    """A tier missing or with fewer sessions than folds raises instead of scoring on too little."""
    rows = [(f"{t}{i}", t, session_features(_commands([1.0], ["ls", "id"]))) for t, n in counts.items() for i in range(n)]
    with pytest.raises(ValueError):
        evaluate(rows, folds=5)


def test_evaluate_scores_separable_tiers():
    """On clearly separated tiers every variant except always-bot finds each tier."""
    styles = {"bot": ([0.0], ["uname -a", "id"]), "human": ([20.0], ["ls -la /var/www", "cat config.php"]),
              "llm_agent": ([4.0], ["find / -name '*.conf' 2>/dev/null | head", "cat /etc/passwd | grep sh"])}
    rows = [(f"{t}{i}", t, session_features(_commands(*styles[t]))) for t in TIERS for i in range(8)]
    results = evaluate(rows, folds=4, seeds=(29,))
    assert results["without_count"]["recall"] == dict.fromkeys(TIERS, 1.0)
    assert results["always_bot"]["recall"] == {"bot": 1.0, "human": 0.0, "llm_agent": 0.0}
