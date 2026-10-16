# VulnMaze user manual

How to install VulnMaze, choose how it answers attackers, train its classifiers and run the evaluation. What each part does and why is explained in [How VulnMaze works](how-it-works.md).

Commands are run from the repository folder, in Git Bash, PowerShell or a Linux/macOS shell. With an NVIDIA GPU, every `docker compose` command below takes `-f infra/docker-compose.gpu.yml` after `-f infra/docker-compose.yml`; without one, leave it out (the LLM then runs on the CPU and is much slower).

## 1. Requirements

| Needed for | What |
|---|---|
| The honeypot | Docker 24+ with Compose v2 |
| LLM answers (`all`, `learned`) | About 4 GB free disk for the model; an NVIDIA GPU with the NVIDIA Container Toolkit is strongly recommended |
| Classifiers, harness, evaluation | [uv](https://docs.astral.sh/uv/) (installs Python 3.12 and every library) |
| The attacker harness only | An [OpenRouter](https://openrouter.ai) API key |

```bash
uv sync --all-extras
```

## 2. Configure

Copy the example settings and fill in your own secrets:
```bash
cp infra/.env.example infra/.env
```
Generate each secret with `python -c "import secrets; print(secrets.token_hex(32))"`.

| Setting in `infra/.env` | Meaning |
|---|---|
| `POSTGRES_PASSWORD`, `VULNMAZE_STATE_TOKEN`, `VULNMAZE_GATEWAY_TOKEN` | Secrets between the containers |
| `VULNMAZE_DEID_KEY` | Key that replaces IP addresses and passwords with pseudonyms before storage. Keep it secret and the same on every deployment |
| `SSH_PUBLISH` | Where the honeypot listens. Keep `127.0.0.1:2222` (only your own computer) unless you deploy a public sensor |
| `VULNMAZE_ESCALATION` | `off`, `all` or `learned` (section 4) |
| `VULNMAZE_LLM_MODEL` | The honeypot's local model, default `qwen3.5:4b`. Leave it unless you change models |
| `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` | Only for the attacker harness: remove the `#` in front of both lines and fill them in |

`VULNMAZE_LLM_MODEL` is the honeypot's model and `OPENROUTER_MODEL` is the attacker's. Mixing them up stops the honeypot's model from loading.

## 3. Start, stop and log in

Download the honeypot's model once:
```bash
docker compose -f infra/docker-compose.yml --profile models run --rm ollama-pull
```
Start everything (the first build takes a few minutes):
```bash
docker compose -f infra/docker-compose.yml up -d --build --wait
```
Log in as an attacker would, with any password except `root`, `123456` or one containing `honeypot` (Cowrie rejects those):
```bash
ssh -p 2222 root@127.0.0.1
```
Stop:
```bash
docker compose -f infra/docker-compose.yml down
```
After pulling new code, run `git pull`, `uv sync --all-extras`, and start again with `--build`.

## 4. Choose the escalation mode

| Mode | What a command Cowrie cannot answer gets |
|---|---|
| `off` | `command not found`, as plain Cowrie |
| `all` | An answer from the local LLM, always |
| `learned` | The classifiers decide per session; sessions worth deceiving also get bait files. Needs the classifier file (section 5) |

**Set it** in `infra/.env` (`VULNMAZE_ESCALATION=learned`) and restart with `up -d --wait`. A value set in your shell overrides the file. If the mode does not change, clear it: PowerShell `Remove-Item Env:VULNMAZE_ESCALATION -ErrorAction SilentlyContinue`, Git Bash `unset VULNMAZE_ESCALATION`.

**Check it** in the running containers. Both must print the same mode:
```bash
docker compose -f infra/docker-compose.yml exec -T cowrie printenv VULNMAZE_ESCALATION
```
```bash
docker compose -f infra/docker-compose.yml exec -T llm-gateway printenv VULNMAZE_ESCALATION
```
And check that the model has loaded (`all` and `learned`): `docker compose -f infra/docker-compose.yml ps` must show `llm-gateway` as **healthy**.

## 5. Build the classifier file

`learned` mode needs `infra/classifiers/session_models.joblib`. It is not in git (28 MB); build it once per computer. The input files are not in the repository either: the COW160x4 dataset export, its labelled commands, and the human and harness session files. Get them from the team's shared folder.

1. Train the attacker-tier model (bot / human / LLM agent):
   ```bash
   uv run vulnmaze-train-tier --events <cow_events_public_cow160x4.jsonl> <events_human_agent.jsonl> <events_harness_2026-10-15.jsonl> --tiers <tiers-human.jsonl> <tiers-harness.jsonl> <tiers-harness-2026-10-15.jsonl> --out <models folder>/tier
   ```
   It prints the cross-validation scores and writes `metrics.json` and `tier.joblib`.
2. Train the tactic and severity models and save all three together:
   ```bash
   uv run vulnmaze-session-models --commands <commands_llm.jsonl> --tier <models folder>/tier/tier.joblib --out infra/classifiers/session_models.joblib
   ```
   It prints the prediction time per command (about 12 ms).

To compare the tactic and severity baselines (the tables in [How VulnMaze works](how-it-works.md#6-the-classifiers)): `uv run vulnmaze-train-baselines --commands <commands_llm.jsonl> --out <folder>`.

## 6. Read what happened

| Where | What |
|---|---|
| `docker compose -f infra/docker-compose.yml cp cowrie:/cowrie/var/log/cowrie/cowrie.json cowrie.json` | Cowrie's full log: every command, routing decision (`cowrie.vulnmaze.route`), LLM answer (`cowrie.vulnmaze.llm`) and planted bait (`cowrie.vulnmaze.bait`) |
| Table `llm_calls` | One row per gateway call: command, outcome (`generated`, `pinned`, `declined`, `fallback`, `not_installed`, `bait`, ...), reasons and latency |
| Table `attacker_facts` | What was invented for each attacker (answers, files, facts, bait); `created_by = 'honeytoken'` marks bait |
| Table `session_digests` | A summary per session: logins, commands, timing |

Example query:
```bash
docker compose -f infra/docker-compose.yml exec -T postgres psql -U vulnmaze -d vulnmaze -c "SELECT ts, command, outcome, reasons, latency_ms FROM llm_calls ORDER BY ts DESC LIMIT 20"
```

## 7. Run the evaluation

The evaluation runs the same attacker against `off`, `all` and `learned` and compares them. Details and options: [harness guide](harness.md).

1. Put the attacker model in `infra/.env`, for example `OPENROUTER_MODEL=google/gemini-3.6-flash`, and pull the latest code (`git pull`).
2. Run each mode. Each takes 10 to 30 minutes and does everything: restarts the stack in that mode, checks it, waits for the model, clears stored answers, runs 30 attacker sessions into `dev/harness_runs/eval-<model>-<mode>/` and prints a summary with warnings.
   ```bash
   uv run python dev/scripts/eval_mode.py off
   ```
   ```bash
   uv run python dev/scripts/eval_mode.py all
   ```
   ```bash
   uv run python dev/scripts/eval_mode.py learned
   ```
   Gemini needs its reasoning on, which is the default; for a model that does not, add `--no-reasoning`.
3. Compare the three runs in one table:
   ```bash
   uv run python dev/scripts/eval_compare.py dev/harness_runs/eval-google-gemini-3.6-flash-off dev/harness_runs/eval-google-gemini-3.6-flash-all dev/harness_runs/eval-google-gemini-3.6-flash-learned
   ```
   The table (sessions, attacker steps, goals reached, errors, tokens, gateway outcomes, answer time, tiers, bait given and bait read) can be pasted into the report.

## 8. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Every LLM answer is a fallback, `llm_calls` shows `model_failed` | The honeypot's model could not load. Check `VULNMAZE_LLM_MODEL=qwen3.5:4b` in `infra/.env` and in your shell, run the model download (section 3), restart |
| The mode does not change after editing `infra/.env` | A value set in the shell wins. Clear it (section 4) and restart |
| `llm-gateway` does not start in `learned` mode | The classifier file is missing: build it (section 5) |
| No `learned:` reason on a command | The answer was served from memory (`pinned`) or the command was not installed; only fresh decisions are logged |
| Answers from an earlier run come back | Stored answers are kept per attacker. `eval_mode.py` clears them; by hand: `docker compose -f infra/docker-compose.yml exec -T postgres psql -U vulnmaze -d vulnmaze -c "TRUNCATE attacker_facts"` (test stacks only) |
| Harness sessions stop at step 1 with `HTTP 400: Reasoning is mandatory` | The attacker model needs reasoning on: drop `--no-reasoning` |
| Harness errors `reply cut off at the 2048-token limit` | The attacker's reasoning is too long for the reply limit; note it, or try another attacker model |
| `eval_mode.py` refuses to run | The run folder already holds a run. Rename or move it |
| Results do not match the latest code | The local checkout was not updated: `git pull`, then run again (the script rebuilds the stack) |

## 9. Safety

- Keep `SSH_PUBLISH=127.0.0.1:2222` unless you deploy a public sensor on purpose, and then only after moving the host's real SSH off port 22.
- The honeypot container cannot reach the database or the internet; the model server has no route out. Only the one-off model download and the attacker harness use the internet.
- IP addresses and passwords are replaced with pseudonyms before storage. Raw Cowrie logs (`cowrie.json`) still contain real addresses: do not share them, and delete old ones.
- The attacker harness only attacks `127.0.0.1:2222` and refuses any other target.
