# Changelog

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
