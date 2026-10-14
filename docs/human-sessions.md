# Human attacker sessions

VulnMaze's attacker-tier classifier separates bots, LLM agents and humans. Humans are the hardest class to get data for, so we need a few sessions typed by real people. Each session takes about 10 minutes.

## For volunteers

### 1. Run the honeypot on your own computer
Follow **Quick start** in the [README](../README.md) (Docker, `infra/.env` from `infra/.env.example` with your own secrets). Keep `SSH_PUBLISH=127.0.0.1:2222`: your honeypot must only be reachable from your own computer.

The LLM is optional. Without an NVIDIA GPU, leave `VULNMAZE_ESCALATION=off`.

### 2. Do 1 to 3 sessions
```bash
ssh -p 2222 root@127.0.0.1
```
Use any password except `root` and `123456`, and **never a real password of yours**. Everything you type is logged.

In each session pick **one** goal and work on it for about 10 minutes, the way a real attacker would:

| Goal | Ideas |
|---|---|
| Find out what this server is | `uname -a`, `cat /etc/os-release`, `ps aux`, `ss -tlnp`, `systemctl`, `df -h`, `ls /var/www` |
| Find credentials | config files, `.bash_history`, `/etc/passwd`, MySQL (`mysql -u root`), web app configs |
| Keep a way back in | add a user, add an SSH key to `~/.ssh/authorized_keys`, a cron job |
| Bring in a tool | `wget` or `curl` a script, `chmod +x`, run it |

Rules:
- **Type everything by hand.** Do not paste scripts or command lists; your typing rhythm, pauses and typos are what the classifier learns from.
- React to what you see: if a command fails or shows something interesting, follow it.
- Stay inside the honeypot shell. Do not scan or attack anything else.
- The honeypot logs you out after 15 minutes without typing, and every session ends after 1 hour. If that happens, log in again and carry on.
- Use a different goal for each session, and `exit` at the end.

### 3. Send your log
From the repository folder, with the stack still running:
```bash
docker compose -f infra/docker-compose.yml cp cowrie:/cowrie/var/log/cowrie/cowrie.json human-<yourname>.json
```
Send `human-<yourname>.json` to the person collecting them. It contains only your own sessions on your own honeypot. Then stop the stack with `docker compose -f infra/docker-compose.yml down`.

## For the person collecting the logs

1. Load each file into the shared database as its own source. The loader reads plain or gzipped Cowrie JSON:
   ```bash
   vulnmaze-load-public --name human-<name> human-<name>.json
   ```
   Run it where the database is reachable (for the Docker stack: inside the `ingester` container).
2. Write the tier file. Every session in a volunteer's log is theirs:
   ```bash
   uv run python dev/scripts/tag_human_sessions.py human-*.json --out tiers-human.jsonl
   ```
   For your own sessions on a shared honeypot, copy its `cowrie.json` the same way and limit the time window to when you typed:
   ```bash
   uv run python dev/scripts/tag_human_sessions.py cowrie.json --since 2026-10-14T10:00+08:00 --until 2026-10-14T11:30+08:00 --out tiers-me.jsonl
   ```
   For attacker-harness runs, pass the run file with `--harness`; each run is matched to the Cowrie session that connected last before its first step (at most `--max-gap` seconds, default 30) and tagged `llm_agent`. The harness's own source port cannot be used for this behind Docker Desktop, which forwards the connection:
   ```bash
   docker compose -f infra/docker-compose.yml cp cowrie:/cowrie/var/log/cowrie/cowrie.json cowrie.json
   uv run python dev/scripts/tag_human_sessions.py cowrie.json --harness dev/harness_runs/<run>.jsonl --out tiers-harness.jsonl
   ```
3. Pass the tier files to the labeller with `vulnmaze-label --tiers ...` (combine several files into one first). A session in a tier file is labelled with that tier; without one, every `public:*` session would be labelled `bot`.

Aim for at least 10 human sessions. With fewer, train the tier classifier on bot and LLM agent only and report human detection as future work.
