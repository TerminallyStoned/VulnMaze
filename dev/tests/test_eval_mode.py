import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[2] / "dev/scripts/eval_mode.py"


def _run(tmp_path, *args):
    """Run the script with run folders under tmp_path and google/gemini-3.6-flash as the infra/.env model."""
    env = {**os.environ, "OPENROUTER_MODEL": "google/gemini-3.6-flash"}
    return subprocess.run([sys.executable, str(SCRIPT), *args, "--runs", str(tmp_path), "--dry-run"], capture_output=True, text=True, env=env)


@pytest.mark.parametrize(
    "args, expected",
    [
        (["off"], ["VULNMAZE_ESCALATION=off", "docker-compose.gpu.yml", "--model google/gemini-3.6-flash", "--max-steps 30", "eval-google-gemini-3.6-flash-off", "--reasoning"]),
        (["learned", "--model", "z-ai/glm-5.3-flash", "--no-reasoning", "--no-gpu", "--sessions", "1"], ["VULNMAZE_ESCALATION=learned", "--sessions 1", "eval-z-ai-glm-5.3-flash-learned"]),
    ],
)
def test_dry_run_plans_the_mode_and_its_own_run_folder(tmp_path, args, expected):
    """The mode reaches the restart, and the harness gets the model, limits and a run folder named after model and mode."""
    result = _run(tmp_path, *args)
    assert result.returncode == 0
    assert all(e in result.stdout for e in expected)
    assert ("--reasoning" in result.stdout) == ("--no-reasoning" not in args)
    assert ("gpu" in result.stdout) == ("--no-gpu" not in args)


@pytest.mark.parametrize("mode, existing", [("none", False), ("all", True)])
def test_unknown_mode_or_a_used_run_folder_is_refused(tmp_path, mode, existing):
    """An unknown mode, or a run folder that already holds a run, stops before anything runs."""
    if existing:
        (tmp_path / f"eval-google-gemini-3.6-flash-{mode}").mkdir()
        (tmp_path / f"eval-google-gemini-3.6-flash-{mode}" / "harness-1.jsonl").write_text("{}\n", encoding="utf-8")
    result = _run(tmp_path, mode)
    assert result.returncode != 0 and "VULNMAZE_ESCALATION" not in result.stdout
