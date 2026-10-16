# eval/

- `golden_commands.yml`: the golden set of 95 commands Cowrie cannot answer, for checking the LLM's answers (run with `dev/scripts/llm_eval.py`, see `docs/how-it-works.md` section 8).
- `results/`: one CSV and summary per run. Two people rate each answer in the `rater_1` and `rater_2` columns; commit the rated CSVs.

The attacker-harness runs that compare `off`, `all` and `learned` are in `dev/harness_runs/` (not committed); see `docs/harness.md`.
