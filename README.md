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

## Layout

```
src/vulnmaze/
  router/          deterministic command router (the security floor)
  cowrie_ext/      hooks + fixed privilege handlers installed into Cowrie,
                   async LLM command, session files
  ingest/          tails cowrie.json, normalises and stores; public dataset loader
  digest/          per-session digest builder
  state/           write-once per-attacker state store + HTTP API
  llm/             hardened LLM gateway: prompt, backends, output checks, pinning
  common/          de-identification (keyed HMAC)
  db/schema.sql    PostgreSQL schema
src/twisted/plugins/vulnmaze_plugin.py   `twistd vulnmaze` = Cowrie + VulnMaze hooks
infra/             docker compose stack (edge, cowrie, postgres, ingester,
                   state-api, llm-gateway, ollama); persona/persona.yml
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
`VULNMAZE_ESCALATION=all` in `infra/.env` and restart the stack. Model
choices (`VULNMAZE_LLM_BACKEND`, `VULNMAZE_LLM_URL`, `VULNMAZE_LLM_MODEL`)
are in `infra/.env.example`.

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
  a one-off job — and no hosted model API is supported, so attacker data
  never leaves the deployment.
- Raw log retention: rotated `cowrie.json.*` files on the log volume contain
  real IPs; delete them on your chosen schedule (the ingester never needs
  them after ingestion).
