# VulnMaze

A medium-interaction SSH honeypot platform built on Cowrie. Every attacker
session is captured as de-identified telemetry, summarised into a per-session
digest, and tracked in a write-once per-attacker state store. A deterministic
router decides what the honeypot answers: privilege-boundary commands are
always served by fixed, plausible handlers, and everything else falls through
to Cowrie's standard behaviour. Commands Cowrie cannot answer at all may be
answered by a hardened local language model: it sits on its own isolated
network, every answer is checked against the machine persona, and answers,
files and facts are pinned so the machine stays consistent across sessions.

In `learned` mode, trained classifiers (ATT&CK tactic, R0-R4 severity and
attacker tier: bot, human or LLM agent) decide per session who gets the
language model, and plant tactic-matched bait files for sessions worth
deceiving. An LLM-agent attacker harness and two scripts compare this with
plain Cowrie (`off`) and an always-on LLM honeypot (`all`).

## Documentation

| Read | For |
|---|---|
| [How VulnMaze works](docs/how-it-works.md) | What each part does and why, the results so far, the limitations, and what goes in which section of the report |
| [User manual](docs/user-manual.md) | Installing, configuring, choosing the mode, building the classifiers, running the evaluation, troubleshooting |
| [Attacker harness](docs/harness.md) | Running the LLM-agent attacker and each evaluation mode in detail |
| [Human sessions](docs/human-sessions.md) | Collecting sessions typed by people for the attacker-tier classifier |

## Features

- **Isolated deployment.** A Docker Compose stack with `edge` / `dmz` /
  `backend` networks. The honeypot is the only published service, and the
  internal networks have no gateway, so even a fully compromised honeypot
  cannot reach the database or the internet.
- **De-identified telemetry.** Source IPs and passwords are replaced with
  keyed HMACs (plus a coarse /16 prefix for network-level analysis) before
  storage. Raw addresses and plaintext passwords never reach the database.
- **Per-session digests.** A compact JSON summary of each session — logins,
  command timeline, files, timing and client fingerprint — built
  incrementally, so it is available while the session is still running.
- **Write-once attacker state.** Anything the honeypot invents for an
  attacker (users, credentials, files, banners) is stored once per attacker
  and served unchanged thereafter, so the persona stays consistent across
  sessions.
- **Deterministic router.** Every command stage is classified as privilege /
  deterministic / escalate candidate. Privilege commands (`usermod`, `sudo`,
  `/etc/shadow`, ...) are always answered by fixed handlers — a security
  floor that holds regardless of anything else in the stack.
- **Hardened local LLM gap-filler.** Commands Cowrie cannot answer are
  optionally answered by a local language model behind a gateway that
  re-checks the router decision, strips reasoning text, rejects leaks and
  persona contradictions, rate-limits per attacker, and pins every answer,
  file and fact. Escalation is off by default and switches on in
  `infra/.env`; the model runs locally — no attacker data ever leaves the
  deployment.
- **Public dataset loader.** Public Cowrie datasets (for example the
  CyberLab honeynet) load through the same normalise/de-identify path as
  live data.
- **Learned escalation.** `VULNMAZE_ESCALATION=off | all | learned`. In
  `learned`, random-forest classifiers run on each session (about 12 ms per
  command); a session at least 90% likely to be a bot that has done nothing
  risky gets plain Cowrie's `command not found`, everyone else gets the
  language model. Every decision is logged.
- **Honeytokens.** In `learned`, humans, LLM agents and risky sessions get a
  bait file matched to their predicted ATT&CK tactic (for example a database
  config with a password), written by the local model, added to the running
  session and pinned for the attacker.
- **Persona filesystem.** The web server the persona describes (web root,
  nginx, MariaDB and PHP configs) is added to Cowrie's filesystem in every
  mode, so the disk agrees with the model's answers.
- **Attacker harness and evaluation.** An LLM attacker (via OpenRouter) that
  can only target the local honeypot, `eval_mode.py` to run one mode end to
  end and `eval_compare.py` to compare modes in one table.

## Layout

```
src/vulnmaze/
  router/          deterministic command router (the security floor)
  cowrie_ext/      hooks + fixed privilege handlers installed into Cowrie,
                   async LLM command, session files
  ingest/          tails cowrie.json, normalises and stores; public dataset loader
  digest/          per-session digest builder
  state/           write-once per-attacker state store + HTTP API
  llm/             hardened LLM gateway: prompt, backends, output checks, pinning,
                   learned decisions and bait (/v1/assess)
  classify/        tactic, severity and attacker-tier classifiers
  labels/          rule-based ATT&CK and R0-R4 labeller (baseline)
  harness/         LLM-agent attacker harness
  common/          de-identification (keyed HMAC)
  db/schema.sql    PostgreSQL schema
src/twisted/plugins/vulnmaze_plugin.py   `twistd vulnmaze` = Cowrie + VulnMaze hooks
infra/             docker compose stack (edge, cowrie, postgres, ingester,
                   state-api, llm-gateway, ollama); persona/persona.yml;
                   classifiers/ (the trained model file, not in git)
dev/scripts/       evaluation (eval_mode.py, eval_compare.py), session tagging,
                   golden-set evaluation of the gap-filler
docs/              the documentation listed above
```

## Quick start

Requires Docker 24+ with Compose v2. From the repository root:

```bash
# configure secrets (generate each with:
#   python3 -c "import secrets; print(secrets.token_hex(32))")
cp infra/.env.example infra/.env

docker compose -f infra/docker-compose.yml up -d --build --wait

# verify: the honeypot answers SSH on the published port
ssh -p 2222 root@127.0.0.1
```

To run as a public sensor, set `SSH_PUBLISH=0.0.0.0:22` in `infra/.env` —
only after the host's real sshd has been moved off port 22 and restricted.

### Enabling LLM answers (optional)

```bash
# download the model once (the only container that touches the internet)
docker compose -f infra/docker-compose.yml --profile models run --rm ollama-pull
```

With an NVIDIA GPU, add `-f infra/docker-compose.gpu.yml` to the compose
commands (needs the NVIDIA Container Toolkit on the host). Then set
`VULNMAZE_ESCALATION=all` (or `learned`, which also needs the classifier
file, see the [user manual](docs/user-manual.md#5-build-the-classifier-file))
in `infra/.env` and restart the stack. Model choices
(`VULNMAZE_LLM_BACKEND`, `VULNMAZE_LLM_URL`, `VULNMAZE_LLM_MODEL`) are in
`infra/.env.example`.

### OpenRouter for development (optional, off by default)

For testing without a local GPU, the gateway can use a model on OpenRouter.
It is never the default: the normal stack has no route to the internet and
refuses a model URL outside the deployment. To opt in, uncomment the two
OpenRouter lines in `infra/.env` (copied from `infra/.env.example`) and enter
your key and a model id:

```
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=qwen/qwen3.5-9b
```

OpenRouter has no `qwen3.5:4b`; `qwen/qwen3.5-9b` is the smallest Qwen 3.5
there. Then add the override file:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.openrouter.yml up -d --build --wait
```

Without `-f infra/docker-compose.openrouter.yml` these settings are ignored.
Every escalated command, its arguments, piped input and recent history are
then sent to the provider, so use it for development and the harness only,
never on a public sensor.

## Development

Requires [uv](https://docs.astral.sh/uv/). It installs Python 3.12 if needed
and creates `.venv` from the locked dependencies in `uv.lock`.

```bash
uv sync --all-extras
uv run pre-commit install
```

`pre-commit install` is a one-time step per clone. After it, every `git commit`
runs `ruff check --fix`, `ruff format` and the secret and whitespace checks on
the staged files. If a hook changes a file, the commit stops: review the
change, `git add` it and commit again.

### Updating an existing clone

After pulling changes, bring your environment up to date:

```bash
git switch main
git pull
uv sync --all-extras
uv run pre-commit install
```

`uv sync` updates `.venv` to match the pulled `uv.lock` (run it after any pull
that changes `uv.lock`). `pre-commit install` only needs running once per
clone; running it again is harmless. To run the stack with the new code,
rebuild the images with `docker compose -f infra/docker-compose.yml up -d --build --wait`.

If you have a branch in progress from before the code was formatted, run
`uv run ruff format .` on it and commit, then merge `main` into it. Formatting
first keeps layout-only differences from showing up as merge conflicts.

To run the same checks and the tests without committing:

```bash
uv run ruff check --fix .
uv run ruff format .
uv run pytest
```

CI runs `ruff check`, `ruff format --check` and `pytest` on every push to `main`
and every pull request, so anything the hooks did not catch shows up there.

Database tests are skipped unless `VULNMAZE_TEST_DSN` points at a PostgreSQL
database they may write to:

```bash
docker run -d --rm --name vulnmaze-testdb -e POSTGRES_PASSWORD=test -e POSTGRES_DB=vulnmaze_test -p 127.0.0.1:55432:5432 postgres:16-alpine
VULNMAZE_TEST_DSN=postgresql://postgres:test@127.0.0.1:55432/vulnmaze_test uv run pytest
```

After changing dependencies in `pyproject.toml`, run `uv lock` and commit
`uv.lock`; the Docker images install exactly what it pins.

## Privacy and safety

- De-identification happens before storage: nothing downstream can leak what
  it never saw. The de-identification key (`VULNMAZE_DEID_KEY`) must be the
  same across all of your deployments so pseudonyms match, and must never be
  committed to the repository or included in any data release.
- The honeypot container shares no network with the database. It writes JSON
  logs to a volume; the ingester on the internal `backend` network mounts it
  read-only.
- The state API is reachable only from the internal `backend` network and
  requires a bearer token.
- The LLM gateway is the only new neighbour of the honeypot: it sits on an
  internal network of its own, requires a token, re-checks the router
  decision on every request, and never sees privilege-boundary commands.
  The model server has no route to the internet — models are pulled once by
  a one-off job. A hosted model (OpenRouter) is possible only as an explicit
  development opt-in (`infra/docker-compose.openrouter.yml`); without it,
  attacker data never leaves the deployment.
- Raw log retention: rotated `cowrie.json.*` files on the log volume contain
  real IPs; delete them on your chosen schedule (the ingester never needs
  them after ingestion).
