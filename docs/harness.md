# Attacker harness

The harness (`vulnmaze.harness`, #28) is a fake attacker: an LLM on OpenRouter logs in to the honeypot over SSH and types commands to reach a goal. We use it to:
1. **Train the tier classifier:** its sessions are the `llm_agent` examples (#29).
2. **Check `learned` mode:** the classifier should see the harness as an LLM agent and let it through to the model, not turn it away as a bot (#30).
3. **Compare the modes:** run the same harness against `off`, `all` and `learned` and compare how long the attacker stays, what it reaches, how many model calls are made and how fast the answers are.

It only attacks `127.0.0.1:2222`, the honeypot on your own computer, and refuses any other target.

All commands below run from the repository root (`Documents\GitHub\VulnMaze`), in Git Bash or PowerShell.

## The escalation mode: off, all, learned

The mode decides what the honeypot does with a command that Cowrie cannot answer by itself:

| Mode | What the attacker gets |
|---|---|
| `off` | Plain Cowrie: `-bash: <command>: command not found`. No LLM. |
| `all` | Every such command is answered by the local LLM. |
| `learned` | The classifiers look at the session first. A bot doing nothing risky gets `command not found` (like `off`); everyone else gets the LLM (like `all`). |

### Where the mode is set

It is the setting `VULNMAZE_ESCALATION`. It can come from two places:
- **The file `infra/.env`**, the line `VULNMAZE_ESCALATION=...`. This is the normal place.
- **The shell you start Docker from.** If `VULNMAZE_ESCALATION` is set there, it wins over the file. In PowerShell it stays set until you close that window.

The stack reads the setting only when it starts. So the file can say one thing while the running stack uses another.

### See which mode is running

Ask the running containers. Both lines must print the same mode:
```bash
docker compose -f infra/docker-compose.yml exec -T cowrie printenv VULNMAZE_ESCALATION
docker compose -f infra/docker-compose.yml exec -T llm-gateway printenv VULNMAZE_ESCALATION
```
If they print an error, the stack is not running.

To see what the file says:
```bash
grep VULNMAZE_ESCALATION infra/.env
```

### Change the mode

1. Open `infra/.env` and change the line to `VULNMAZE_ESCALATION=off`, `all` or `learned`.
2. Make sure the shell does not override it. In PowerShell run `Remove-Item Env:VULNMAZE_ESCALATION -ErrorAction SilentlyContinue`; in Git Bash run `unset VULNMAZE_ESCALATION`.
3. Restart the stack with the new setting (leave out `-f infra/docker-compose.gpu.yml` on a computer without an NVIDIA GPU):
   ```bash
   docker compose -f infra/docker-compose.yml -f infra/docker-compose.gpu.yml up -d --wait
   ```
4. Check with the two `printenv` lines above.

## Setup (once per computer)

1. Follow **Quick start** in the [README](../README.md): Docker, and `infra/.env` copied from `infra/.env.example` with your own secrets.
2. Install the Python tools: `uv sync --all-extras`.
3. For `all` or `learned`, download the local model once (see **Enabling LLM answers** in the README).
4. In `infra/.env`, find the two OpenRouter lines, remove the `#` in front of them and fill them in:
   ```
   OPENROUTER_API_KEY=sk-or-v1-...
   OPENROUTER_MODEL=qwen/qwen3.5-9b
   ```
   These are only for the harness (the attacker). The honeypot keeps using its local model.
5. For `learned`, the classifier file `infra/classifiers/session_models.joblib` must exist. If it does not, build it:
   ```bash
   uv run vulnmaze-session-models --commands <commands.jsonl> --tier <tier.joblib> --out infra/classifiers/session_models.joblib
   ```

## Run the harness

### 1. Pick the mode and check it

See **Change the mode** and **See which mode is running** above.

### 2. When comparing modes: clear the stored answers

The honeypot remembers its answers for each attacker, so the same question gets the same answer next time, and a remembered answer skips the mode's decision. All harness sessions from your computer count as one attacker, so answers from the last mode would leak into the next one. Before each mode's runs, clear them. This deletes only the remembered answers, so only do it on your own test stack. The logs are kept: `cowrie.json`, the `events` table, the session digests and `llm_calls`.
```bash
docker compose -f infra/docker-compose.yml exec -T postgres psql -U vulnmaze -d vulnmaze -c "TRUNCATE attacker_facts"
```

### 3. Note the time, then start

Write down the current time; you need it to check the results. Then:
```bash
uv run python -m vulnmaze.harness.runner --env-file infra/.env
```
This runs **5 sessions**, one for each objective, up to 12 commands each. A session takes about half a minute to a minute; 30 sessions took 12 to 27 minutes on 14 and 15 October. It prints one line per finished session, and at the end the total and the run file's path, for example:
```
5 sessions -> dev/harness_runs/harness-20261015T060000Z.jsonl | tokens ...
```

### How many sessions: the options

`--objective` takes an objective **name**, not a number. The names are:

| Name | Goal |
|---|---|
| `discovery` | Find out what the server is |
| `credential-access` | Find passwords and keys |
| `persistence` | Keep a way back in |
| `collection` | Gather valuable files into one archive |
| `command-and-control` | Download a payload and make it call back |

Sessions per run = number of objectives × `--sessions`.

| You want | Command | Sessions |
|---|---|---|
| One per objective (the normal run) | `uv run python -m vulnmaze.harness.runner --env-file infra/.env` | 5 |
| Six per objective (the 14 Oct training data) | `... --sessions 6` | 30 |
| Only discovery | `... --objective discovery` | 1 |
| Discovery and persistence, 2 each | `... --objective discovery --objective persistence --sessions 2` | 4 |

Other options: `--max-steps N` (commands per session, default 12), `--model <id>` (an OpenRouter attacker model instead of `OPENROUTER_MODEL`; repeat it to run each model in turn) `--out <folder>` (where the run file goes, default `dev/harness_runs`) and `--reasoning` (keep the attacker's reasoning on at low effort, for models that refuse to turn it off; the run fails at step 1 with `HTTP 400: Reasoning is mandatory` without it).

### Attacker models

| Model | Used | Notes |
|---|---|---|
| `qwen/qwen3.5-9b` | 14 Oct, 30 sessions, `all` | In the tier model's training data |
| `qwen/qwen3-coder` | 15 Oct, 30 sessions, `learned` | In the tier model's training data |
| `google/gemini-3.6-flash` | not yet | Unseen by the tier model, so the fair test of `learned`. Needs `--reasoning`: it rejects reasoning turned off |

When a run uses a new model, add it to this table.

To count the sessions in an existing run file:
```bash
uv run python -c "import json,sys,collections as c; r=c.defaultdict(set); [r[(d:=json.loads(l))['objective']].add(d['run_id']) for l in open(sys.argv[1])]; print({k:len(v) for k,v in r.items()})" dev/harness_runs/<run>.jsonl
```
It prints the sessions per objective, for example `{'discovery': 6, 'credential-access': 6, ...}`.

### 4. Check the results

Match each harness session to the honeypot's session for it:
```bash
docker compose -f infra/docker-compose.yml cp cowrie:/cowrie/var/log/cowrie/cowrie.json cowrie.json
uv run python dev/scripts/tag_human_sessions.py cowrie.json --harness dev/harness_runs/<run>.jsonl --out tiers-harness.jsonl
```

See what the honeypot did with each command since your start time (replace the time with yours):
```bash
docker compose -f infra/docker-compose.yml exec -T postgres psql -U vulnmaze -d vulnmaze -c "SELECT session, command, outcome, reasons, latency_ms FROM llm_calls WHERE ts > '2026-10-15T14:00+08:00' ORDER BY ts"
docker compose -f infra/docker-compose.yml exec -T postgres psql -U vulnmaze -d vulnmaze -c "SELECT outcome, count(*) FROM llm_calls WHERE ts > '2026-10-15T14:00+08:00' GROUP BY outcome"
```

How to read `outcome`: `generated` means the LLM answered; `declined` means `learned` mode turned the session away as a bot.

In `learned` mode, `reasons` also holds `learned:<tier>:<tier probability>:<highest severity>:<number of R3/R4 commands>`, for example `learned:llm_agent:0.69:R1:0`. A session is declined only as a bot with probability 0.9 or more and nothing at R3 or R4. For harness sessions the tier should be `llm_agent` (or `human`), and nothing should be `declined`. A command answered from a remembered answer has no `learned:` entry, and the first command of a session has no tier yet (`learned:None:None:...`).

### 5. Stop the stack when done

```bash
docker compose -f infra/docker-compose.yml down
```

## Evaluation: one run per mode

Compare the modes with the same attacker model and the same number of sessions. Do the three modes one after another, each with its own folder for the run file: the run file does not record the mode, the folder does.

For each mode, in this order: `off`, `all`, `learned`.

1. **Set the mode.** In `infra/.env`, set `VULNMAZE_ESCALATION=<mode>`. Clear any shell value (PowerShell: `Remove-Item Env:VULNMAZE_ESCALATION -ErrorAction SilentlyContinue`; Git Bash: `unset VULNMAZE_ESCALATION`).
2. **Restart the stack:**
   ```bash
   docker compose -f infra/docker-compose.yml -f infra/docker-compose.gpu.yml up -d --build --wait
   ```
3. **Check the mode.** Both lines must print the mode you set:
   ```bash
   docker compose -f infra/docker-compose.yml exec -T cowrie printenv VULNMAZE_ESCALATION
   docker compose -f infra/docker-compose.yml exec -T llm-gateway printenv VULNMAZE_ESCALATION
   ```
4. **Clear the remembered answers** (the logs are kept):
   ```bash
   docker compose -f infra/docker-compose.yml exec -T postgres psql -U vulnmaze -d vulnmaze -c "TRUNCATE attacker_facts"
   ```
5. **Run 30 sessions** into the mode's folder:
   ```bash
   uv run python -m vulnmaze.harness.runner --env-file infra/.env --sessions 6 --model google/gemini-3.6-flash --reasoning --out dev/harness_runs/eval-<mode>
   ```
6. **Check before the next mode.** A run that took under a minute failed: look at the `error` field of its first line. Then check that the run file has 30 sessions (see **How many sessions**). In `off` mode `llm_calls` gets no new rows; in `all` there are no `declined` rows; in `learned` harness sessions should not be `declined`.

Then compare the three run files: commands per session, sessions where the attacker declared its goal done (`done` in the last step), what reached the gateway and its outcomes, and answer latency.
