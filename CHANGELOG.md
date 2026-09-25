# Changelog

## v0.6: Hardened local LLM gap-filler
- `vulnmaze.llm`: gateway with route re-check, existence and output pinning, prompt builder, Ollama and OpenAI-compatible backends (json and raw modes), reasoning stripping, anchored leakage detector, output and file-path denylist, persona and stored-fact contradiction checks, one retry, deterministic fallbacks, per-attacker rate limit, global concurrency cap, `llm_calls` log.
- Cowrie: escalation switch (`VULNMAZE_ESCALATION`, off by default), async LLM command, unimplemented binaries in standard bin directories now count as "Cowrie can't answer", LLM-created files loaded at login with early input (including EOF) held until loaded, `cowrie.vulnmaze.llm` events.
- State store: global facts (`cmd-exists:*`), prefix escaping in `list`.
- Digest v2: `llm` counts and `commands[].llm`.
- Infra: `llm-gateway`, `ollama`, `ollama-pull` (profile `models`), networks `hpgw`, `llm`, `egress`; `docker-compose.gpu.yml`; `infra/persona/persona.yml`.

## v0.5: Deterministic router
- `vulnmaze.router`: classifies every command stage as privilege / deterministic / escalate candidate.
- `twistd vulnmaze` plugin wraps Cowrie's command execution and logs `cowrie.vulnmaze.route` events.
- Fixed handlers for usermod, userdel, groupadd, groupdel, gpasswd, chage, setcap, pkexec; `sudo -l` and `sudo -V` answered from persona files.

## v0.4: Per-attacker state store
- `attacker_facts` table, write-once (ON CONFLICT DO NOTHING + UPDATE trigger).
- `StateStore` library and FastAPI service on the backend network.

## v0.3: Session digest builder
- Pure incremental digest builder, persisted in `session_digests` in the same transaction as the events.

## v0.2: Cowrie baseline and telemetry ingestion
- Ingester tails `cowrie.json` (rotation-safe, checkpointed, idempotent).
- De-identification: keyed HMAC of IPs and passwords, /16 prefix, password scrubbing in commands.
- Public dataset loader.

## v0.1: Scaffold and isolated infrastructure
- Repository layout and CI.
- Compose stack with `edge` / `dmz` (internal) / `backend` (internal) networks; HAProxy with PROXY protocol.
