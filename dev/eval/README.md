# eval/

- `golden_commands.yml`: the golden set of 95 commands Cowrie cannot answer, for checking the LLM's answers (run with `dev/scripts/llm_eval.py`, see `docs/how-it-works.md` section 8).
- `results/`: one CSV and summary per run. Two people rate each answer in the `rater_1` and `rater_2` columns; commit the rated CSVs.
- `reference/`: the same golden set run on a real Debian 12 server, to compare the honeypot's answers with real output:
  - `Dockerfile`: Debian 12 booted with systemd, with nginx, MariaDB, PHP 8.2-FPM and the tools the golden set uses;
  - `debian12-20261016.json`: each command with the real output and the honeypot's answer from the morning run of 16 Oct, before the fixes for #87 to #89 (real output cut at 4,000 characters). That run's CSV was not kept; the answers are in this file. It used the old trap09 and trap12 commands;
  - `review-claude-20261016.csv`: a review of each model answer against the real output by Claude (1 = closely matches the real format, timestamps ignored). It is an AI's judgement, not the two-person rating.

  To redo it (about 5 minutes; the image downloads Debian packages once):
  ```bash
  docker build -t vulnmaze-refvm dev/eval/reference
  docker run -d --name vulnmaze-refvm --hostname web-portal-01 --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw vulnmaze-refvm
  docker exec vulnmaze-refvm mysql -e "CREATE DATABASE portal; CREATE TABLE portal.users (id INT PRIMARY KEY, name VARCHAR(50))"
  uv run python dev/scripts/debian_reference.py dev/eval/results/<run>.csv --out dev/eval/reference/debian12-<date>.json
  docker rm -f vulnmaze-refvm
  ```
  Raters can use the JSON to see the real output next to each answer.

The attacker-harness runs that compare `off`, `all` and `learned` are in `dev/harness_runs/` (not committed); see `docs/harness.md`.
