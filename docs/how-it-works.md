# How VulnMaze works

This page explains what VulnMaze does, how each part works, what has been measured so far and what is still missing, in plain words. It is written for the team members who write the report and slides. Each section ends with what to take into the report. To install and run the system, see the [user manual](user-manual.md).

## 1. The idea in one paragraph

A honeypot is a fake server that attackers can log in to, so we can watch what they do. Cowrie, the honeypot we build on, fakes a Linux shell well, but only for the commands it knows. Anything else gets `command not found`, and a capable attacker notices and leaves. VulnMaze adds a **local language model (LLM)** that invents realistic answers for those missing commands. A model call is slow and costs compute, and a scripted bot gains nothing from a clever answer, so VulnMaze uses **trained classifiers** to decide per session who is worth it. Sessions it judges worth deceiving also get **bait files** (honeytokens) matched to what the attacker is after. This is the proposal's main claim: escalation decided by learned attack type, severity and attacker tier, rather than by how complex a command is.

## 2. What happens to one command

An attacker types `systemctl list-timers`. In order:

1. **Cowrie** receives the line and splits it into commands.
2. **The router** (`src/vulnmaze/router/`) classifies every command:
   - *privilege*: touches something sensitive (`/etc/shadow`, `sudo`, `~/.ssh`). Fixed, safe answers, never the LLM. This is the **security floor**.
   - *deterministic*: Cowrie can answer it itself (`ls`, `cat`, `uname`, ...).
   - *escalate candidate*: Cowrie has no such command. Only these can reach the LLM.
3. **The escalation mode** decides what happens to an escalate candidate (section 3).
4. **The gateway** (`src/vulnmaze/llm/gateway.py`) checks the router's decision again, serves a stored answer if this attacker asked before, and otherwise asks the local model (`qwen3.5:4b` in Ollama). The answer is checked for leaks ("as an AI ..."), contradictions with the machine's persona, and forbidden content, and retried once. If it fails again, the attacker gets a plain shell error.
5. **Pinning:** every invented answer, file and fact is stored once per attacker in the `attacker_facts` table and served unchanged afterwards, so the fake machine stays consistent, also in later sessions.

Every command and every gateway decision is logged: Cowrie's JSON log, the `events` table (de-identified), a per-session summary (`session_digests`) and one row per gateway call (`llm_calls`).

**For the report (design):** the router as a deterministic security floor (following Magazov et al.), the gateway's checks, and pinning per attacker (as in HoneyGPT's state register). The LLM only fills gaps; it never decides security.

## 3. The three escalation modes

Set with `VULNMAZE_ESCALATION` (see the [user manual](user-manual.md#4-choose-the-escalation-mode)).

| Mode | What an escalate candidate gets | Role in the evaluation |
|---|---|---|
| `off` | `command not found`, exactly like plain Cowrie | Baseline 1: **unmodified Cowrie** |
| `all` | Always an LLM answer | Baseline 2: **a non-adaptive LLM honeypot** (like shelLM, HoneyLLM) |
| `learned` | The classifiers decide per session, and qualifying sessions also get bait | **VulnMaze** |

In `learned` mode, for each escalate candidate the gateway runs the classifiers on the session so far:
- a session the tier model is **at least 90% sure is a bot**, and that has done **nothing risky** (no command at severity R3 or R4), gets `command not found`, the same answer as `off`. No model call, nothing stored. Because the answer is identical to plain Cowrie, this cannot be used to tell VulnMaze apart from Cowrie.
- everyone else (humans, LLM agents, risky bots, unsure cases) gets the LLM, as in `all`.

The decision is logged in `llm_calls.reasons` as `learned:<tier>:<probability>:<highest severity>:<number of R3/R4 commands>`, for example `learned:llm_agent:0.89:R1:0`.

**Why 90%:** without a cutoff, the tier model judged about half the sessions of an attacker model it had not seen as bots at some point, and would have turned them away. With the 0.9 cutoff, tested on the harness attacker model each tier model had not been trained on (both directions, 60 sessions): **0 of 60 agent sessions and 0 of 14 human sessions declined** (27 and 5 without the cutoff), while **88% of low-severity bot command prefixes** in 1,000 unseen real bot sessions are still declined (93% without). The cutoff was chosen on the same data, so the true numbers may be slightly worse.

## 4. Honeytokens (bait files)

In `learned` mode, after the attacker's 3rd typed command and every 5th after that, Cowrie asks the gateway in the background whether this session should get bait. The attacker never waits for it. The gateway:

1. runs the classifiers on the session;
2. gives bait only to a **human**, an **LLM agent**, or a session that reached **R3/R4**;
3. picks the session's most frequent predicted ATT&CK tactic and the persona's bait for it (`baits:` in `infra/persona/persona.yml`):

| Tactic | Bait file |
|---|---|
| Discovery | `/var/www/portal/config/database.php` (database password) |
| Privilege Escalation | `/root/.my.cnf` (MariaDB root password) |
| Persistence | `/etc/cron.d/portal-backup` (backup job to an internal host) |
| Command and Control | `/usr/local/sbin/portal-update.sh` (internal mirror and access token) |
| Exfiltration | `/var/backups/portal/portal-db.sql` (users table with password hashes) |

4. has the local model write the file's contents, with the same checks as any answer, and pins it once per attacker;
5. Cowrie adds the file to the running session's filesystem and logs a `cowrie.vulnmaze.bait` event.

Live example: after `uname -a`, `id`, `ls /var/www/portal`, the model wrote `database.php` with `define('DB_PASS', '...')` in about 9 s, and a later `cat` showed it.

Note: the tactic classifier has **no Credential Access or Collection class**, because its training labels come from the COW160x4 corpus. Credential-style bait is therefore attached to Discovery, the class `cat /etc/passwd` gets.

**For the report (design and limitations):** honeytokens are the "attack-type-matched honeytokens" of the proposal, and they are the main way `learned` behaves differently from `all`. The proposal's extra deception for LLM agents (verbose output that burns context, plausible partial results, unproductive feedback) was **not built**: list it as future work.

## 5. The persona: one consistent fake machine

`infra/persona/persona.yml` describes the machine: `web-portal-01`, Debian 12, a municipal e-services portal on nginx, PHP 8.2 and MariaDB. Everything has to agree with it:
- the LLM's answers are checked against its facts (hostname, kernel, versions);
- its `filesystem:` section adds the web server's directories and configs to Cowrie's filesystem at start-up, in every mode (before 15 Oct, `ls /var/www/portal` failed, an easy giveaway);
- its `baits:` section defines the honeytokens.

## 6. The classifiers

Three models, all **random forests** from scikit-learn, stored together in `infra/classifiers/session_models.joblib`. Prediction takes about **12 ms per command**, so it does not delay answers.

### Data
- **Bots:** COW160x4, a public dataset of Cowrie honeypot logs (M. Mikuláš, P. Krajčík, P. Helebrandt and I. Kotuliak, Zenodo, Jul. 2026, doi: 10.5281/zenodo.21260400). The part we used, 5 days, has 376,380 command lines; they contain 17,380 distinct lines, which collapse to 311 "shapes" once keys, IP addresses and random strings are masked. Its sessions are treated as bots.
- **Labels for tactic and severity:** each shape's most frequent line was labelled with an ATT&CK tactic and an R0 to R4 severity by an LLM (Claude Opus, cross-checked with Claude Haiku), following the severity scale of Touch et al. The rule-based labeller (`vulnmaze-label`) is kept as the baseline.
- **LLM agents:** 60 sessions from our attacker harness (section 7), two attacker models.
- **Humans:** 14 sessions typed by one team member (`docs/human-sessions.md`).

### Results
Cross-validation **grouped by command shape**, so a shape seen in training is never in the test fold (282 shapes, 5 folds):

| Task | Model | Accuracy | Macro F1 | MCC |
|---|---|---|---|---|
| Tactic | TF-IDF similarity (baseline, after Andrew et al.) | 0.787 | 0.551 | 0.723 |
| Tactic | **Random forest on words (chosen)** | 0.844 | 0.548 | 0.793 |
| Tactic | Random forest on characters | 0.851 | 0.447 | 0.803 |
| Severity | TF-IDF similarity | 0.699 | 0.700 | 0.624 |
| Severity | Random forest on words | 0.752 | 0.757 | 0.692 |
| Severity | **Random forest on characters (chosen)** | 0.805 | 0.808 | 0.758 |

Tactic: the word model was chosen over the character model for its higher macro F1 (rare tactics), at nearly equal accuracy. Severity: the character model is best on every measure and is on average 0.32 levels off.

**Attacker tier** (bot / human / LLM agent) uses only timing and the shape of typed commands (gaps between commands, how regular they are, command length, pipes, variety of programs, transition entropy), never IP addresses. 5 seeds x 5 folds on 3,000 sampled bots, 14 humans and 30 agents: **macro F1 0.954** (human recall 0.93, agent recall 0.92); retrained with 60 agents from two attacker models: 0.948. Training on session prefixes was tried and dropped: it scored higher in cross-validation (0.974) but did worse on an unseen attacker model.

**For the report (method and results):** the tables above, shape-grouped cross-validation as the honest test, and the limitation that the tier model recognises attacker models it has seen better than new ones (section 3).

## 7. The attacker harness

`vulnmaze.harness` is a small attacker loop in the style of SWE-agent: an LLM on OpenRouter logs in to the honeypot over SSH and types commands towards one goal (discovery, credential access, persistence, collection, command and control), stating its intent and ATT&CK tactic at every step. It can only attack `127.0.0.1:2222`. Each step is logged to `dev/harness_runs/`. These sessions are the LLM-agent training data and the attackers in the evaluation. How to run it: [harness guide](harness.md).

## 8. Evaluation

One script runs a whole mode (`dev/scripts/eval_mode.py off|all|learned`: restart in that mode, check it, clear stored answers, 30 sessions), and one compares them (`dev/scripts/eval_compare.py`). Steps in the [user manual](user-manual.md#7-run-the-evaluation).

### First series, 15 Oct (preliminary)
Attacker `qwen/qwen3-coder` (seen by the tier model), 30 sessions per mode, at most 12 commands each, **before** honeytokens and the persona filesystem existed:

| | `off` | `all` | `learned` |
|---|---|---|---|
| Attacker commands (median per session) | 281 (11) | 312 (12) | 320 (12) |
| Sessions reaching their goal | 12 | 14 | 11 |
| Commands that reached the gateway | 8 | 5 | 10 |
| Declined by `learned` | | | 0 |

What it shows:
- Only **2 to 3% of agent commands** need the LLM at all: Cowrie answers about 82% itself, shell builtins 7%, the security floor 9%. This matches HoneyGPT, which routed about 1.3% of commands to its LLM, and it is a result in itself: the LLM is cheap to add.
- No agent session was declined, and three sessions the tier model leaned towards "bot" (0.54 to 0.74) were escalated thanks to the 90% cutoff.
- With so few gaps, the modes barely differ in engagement at 30 sessions. That is why honeytokens were added: they make `learned` act on every qualifying session, not only on the rare missing command.

### Final series (to do, issue #65)
Attacker `google/gemini-3.6-flash` (unseen by the tier model), all three modes, after honeytokens, the persona filesystem and the reply-limit fix. The table from `eval_compare.py` goes into the report. Things to watch: Gemini often packs several commands into one line and declares its goal reached after 1 or 2 steps, which keeps sessions short in every mode.

## 9. What to write where in the report

| Report section | Take from |
|---|---|
| Introduction, problem | Section 1; the proposal's introduction |
| Literature review | The proposal (unchanged); add Mikuláš et al. for COW160x4 |
| Solution design | Sections 2 to 5, with a diagram of Cowrie → router → gateway → model, the classifiers beside the gateway, and the state store |
| Implementation | Section 6 (data, models), section 7 (harness), the repository layout in the README |
| Evaluation method | Section 8: three modes, 30 sessions each, same attacker; shape-grouped cross-validation for the classifiers |
| Results | The classifier tables (section 6), the 90% cutoff numbers (section 3), the evaluation table (section 8) |
| Discussion | Only 2 to 3% of commands need an LLM; tier model and unseen attackers; why honeytokens |
| Limitations | One local model (`qwen3.5:4b`, not fine-tuned); harness attackers only, no wild traffic; 14 human sessions from one person; 30 sessions per mode; LLM labels; no Credential Access class; no agent-specific deception |
| Future work | Agent deception from the proposal; fine-tuned model; RoBERTa and sequence models; wild deployment; more human sessions |

Proposal items **not done**, to state honestly: the fine-tuned honeypot model, RoBERTa and LSTM/FHMM classifiers, UMAP + HDBSCAN clustering, the deception for LLM agents, evaluation on wild traffic and with volunteer red-teamers.
