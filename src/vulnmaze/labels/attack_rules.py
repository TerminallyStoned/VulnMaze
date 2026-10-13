from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from importlib import resources
from pathlib import Path

import psycopg
import yaml
from psycopg.rows import dict_row

from vulnmaze.db import dsn_from_env

TACTICS, SEVERITY_SPEC = (
    yaml.safe_load(resources.files("vulnmaze.labels").joinpath(name).read_text(encoding="utf-8"))
    for name in ("tactics.yml", "severity.yml")
)
RULES = [
    (r["name"], r["tactic"], re.compile(r["pattern"].replace("{cmd}", TACTICS["command_start"]), re.I))
    for r in TACTICS["rules"]
]
SEVERITY = [(w["name"], w["level"], set(w["words"].split())) for w in SEVERITY_SPEC["words"]]
SEVERITY_PATTERNS = [(p["name"], p["level"], re.compile(p["pattern"])) for p in SEVERITY_SPEC["patterns"]]
COMMAND_PREFIXES = set(SEVERITY_SPEC["command_prefixes"].split())
SCANNER_CLIENT = re.compile(r"^SSH-2\.0-(?:Go|libssh|ZGrab|Nmap|masscan|sshlib|JSCH|Ganymed)", re.I)


def label_command(line: str) -> tuple[str | None, int | None, list[str], bool]:
    """Label one command line with an ATT&CK tactic and an R0-R4 severity.

    Tactic: every rule in tactics.yml votes for one MITRE ATT&CK v19.2 tactic
    or abstains, and lists the techniques it encodes. The tactic with most
    votes wins, "none" only counts when nothing else fired, and ties go to
    the earlier rule.

    Severity: severity.yml holds the R0-R4 specification of Touch, Fink and
    Colin (CRiSIS 2024), each entry with its source in the paper or marked
    added. As in the paper, commands are placed by name: the first word of
    each command in the line, after prefixes such as sudo or busybox, with
    ./x counting as ./ (the paper's ./EXEC). The highest level wins, which
    gives R4 the priority the paper asks for; its own 93 labelling functions
    and Snorkel label model are not published. Two rules of the paper
    override the level: a single command with --help, help, -V or --version
    is R0 (not -h, which means human-readable for df, du, free and ls), and
    echo piped into passwd is R2.

    Returns (tactic, severity, rules that fired, whether the tactic voters
    disagreed); tactic and severity are None when nothing fires.
    """
    line = line or ""
    fired = [(name, tactic) for name, tactic, rx in RULES if rx.search(line)]
    voters = [f for f in fired if f[1] != "none"] or fired
    votes = Counter(tactic for _, tactic in voters)
    tactic = next((t for _, t in voters if votes[t] == max(votes.values())), None)
    words = set()
    for segment in re.split(r"\|\||&&|[;|&`(\n]|\$\(", line):
        argv = segment.split()
        while argv and (argv[0] in COMMAND_PREFIXES or argv[0].isdigit()):
            argv = argv[1:]
        if argv:
            words.add("./" if argv[0].startswith("./") else argv[0].rsplit("/", 1)[-1].lower())
    levels = [(name, level) for name, level, keywords in SEVERITY if words & keywords]
    levels += [(name, level) for name, level, rx in SEVERITY_PATTERNS if rx.search(line)]
    severity = max((level for _, level in levels), default=None)
    if not re.search(r"[;&|`]", line) and set(line.split()) & {"--help", "help", "-V", "--version"}:
        levels, severity = levels + [("help_or_version", 0)], 0
    elif not re.search(r"[;&]", line) and re.search(r"\becho\b[^|]*\|\s*(?:passwd|chpasswd)\b", line):
        levels, severity = levels + [("echo_pipe_passwd", 2)], 2
    return tactic, severity, [f[0] for f in fired] + [name for name, _ in levels], len(votes) > 1


def label_events(events, tiers: dict[str, str] | None = None) -> tuple[list[dict], list[dict], dict]:
    """Label command events and aggregate them per session.

    ``events`` are rows of the events table (source, session, eventid, ts,
    input, data) in session order. A session is multi-label: its tactics are
    the distinct tactics of its commands in the order first seen ("none" only
    if nothing else), its severity the highest of its commands. The attacker tier comes from
    ``tiers`` (session id to bot, llm_agent or human, written by the harness
    and for volunteer sessions), else "bot" for public data and scanner SSH
    clients, else None.
    """
    tiers = tiers or {}
    commands, sessions = [], {}
    stats = Counter()
    rules = Counter()
    for e in events:
        s = sessions.setdefault(
            (e["source"], e["session"]),
            {
                "source": e["source"],
                "session": e["session"],
                "client": None,
                "n": 0,
                "tactics": Counter(),
                "sev": [],
            },
        )
        if e["eventid"] == "cowrie.client.version":
            s["client"] = (e.get("data") or {}).get("version")
        if e["eventid"] != "cowrie.command.input" or not (e.get("input") or "").strip():
            continue
        tactic, severity, fired, conflict = label_command(e["input"])
        stats["commands"] += 1
        s["n"] += 1
        stats["labelled"] += tactic is not None
        stats["severity_labelled"] += severity is not None
        stats["conflicts"] += conflict
        rules.update(fired)
        if tactic:
            s["tactics"][tactic] += 1
        if severity is not None:
            s["sev"].append(severity)
        commands.append(
            {
                "source": e["source"],
                "session": e["session"],
                "ts": str(e["ts"]),
                "input": e["input"],
                "tactic": tactic,
                "tactic_id": TACTICS["tactic_ids"].get(tactic),
                "severity": None if severity is None else f"R{severity}",
                "rules": fired,
                "conflict": conflict,
            }
        )
    out = []
    for s in sessions.values():
        tier = tiers.get(s["session"]) or (
            "bot" if s["source"].startswith("public:") or SCANNER_CLIENT.match(s["client"] or "") else None
        )
        tactics = [t for t in s["tactics"] if t != "none"] or list(s["tactics"])
        out.append(
            {
                "source": s["source"],
                "session": s["session"],
                "tier": tier,
                "n_commands": s["n"],
                "tactics": tactics,
                "tactic_ids": [TACTICS["tactic_ids"][t] for t in tactics if t in TACTICS["tactic_ids"]],
                "severity": f"R{max(s['sev'])}" if s["sev"] else None,
                "tactic_counts": dict(s["tactics"]),
            }
        )
    tier_of = {(s["source"], s["session"]): s["tier"] for s in out}
    for c in commands:
        c["tier"] = tier_of[(c["source"], c["session"])]
    n = stats["commands"]
    summary = {
        "commands": n,
        "labelled": stats["labelled"],
        "coverage": round(stats["labelled"] / n, 3) if n else 0.0,
        "severity_labelled": stats["severity_labelled"],
        "severity_coverage": round(stats["severity_labelled"] / n, 3) if n else 0.0,
        "conflicts": stats["conflicts"],
        "conflict_rate": round(stats["conflicts"] / n, 3) if n else 0.0,
        "sessions": len(out),
        "sessions_labelled": sum(1 for s in out if s["tactics"]),
        "tactics": dict(Counter(c["tactic"] for c in commands).most_common()),
        "severities": dict(Counter(c["severity"] for c in commands).most_common()),
        "session_tactics": dict(Counter(t for s in out for t in s["tactics"]).most_common()),
        "rules": dict(rules.most_common()),
        "tiers": dict(Counter(s["tier"] for s in out)),
    }
    return commands, out, summary


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Label commands and sessions with ATT&CK tactic and R0-R4 severity."
    )
    ap.add_argument("--out", required=True, type=Path, help="directory for commands.jsonl and sessions.jsonl")
    ap.add_argument("--events", type=Path, help="JSONL export of events rows instead of the database")
    ap.add_argument("--source", default="%", help="SQL LIKE pattern on events.source, e.g. 'public:%%'")
    ap.add_argument("--tiers", type=Path, help="JSONL with session and tier, e.g. from the harness")
    args = ap.parse_args()
    tiers = {}
    if args.tiers:
        for line in args.tiers.read_text(encoding="utf-8").split("\n"):
            if line.strip():
                row = json.loads(line)
                tiers[row["session"]] = row["tier"]
    if args.events:
        lines = args.events.read_text(encoding="utf-8").split("\n")
        commands, sessions, summary = label_events([json.loads(x) for x in lines if x.strip()], tiers)
    else:
        with psycopg.connect(dsn_from_env(), row_factory=dict_row) as conn:
            rows = conn.execute(
                "SELECT source, session, eventid, ts, input, data FROM events "
                "WHERE eventid IN ('cowrie.command.input', 'cowrie.client.version') AND source LIKE %s "
                "ORDER BY source, session, ts, id",
                (args.source,),
            )
            commands, sessions, summary = label_events(rows, tiers)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("commands", commands), ("sessions", sessions)):
        with (args.out / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
