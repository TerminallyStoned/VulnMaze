"""Per-session digest.

A digest is a compact JSON summary of one session: logins, command timeline,
files, timing and client fingerprint. It is built
incrementally, one normalised event at a time, so it is available while the
session is still running; the ML layer reads it mid-session.

``apply`` is a pure function of (digest, event): the same events in the same
order always produce the same digest. That is what the golden-file test
checks, and it lets us rebuild every digest from the events table after a
schema change.
"""

from __future__ import annotations

import copy
import re
import statistics
from datetime import datetime
from typing import Any

DIGEST_VERSION = 1
MAX_LOGIN_ATTEMPTS_KEPT = 200   # brute-force sessions: keep counting, stop listing
MAX_COMMANDS_KEPT = 2000
SUBSHELL_WINDOW_S = 0.1         # piped-to-shell commands arrive within a few ms
_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>|;]+", re.I)
_SHELLS = {"bash", "sh", "dash", "zsh", "ash"}


def new_digest(source: str, session: str) -> dict[str, Any]:
    return {
        "version": DIGEST_VERSION,
        "source": source,
        "session": session,
        "sensor": None,
        "protocol": None,
        "src_ip_hmac": None,
        "src_prefix": None,
        "dst_port": None,
        "start_ts": None,
        "last_ts": None,
        "end_ts": None,
        "closed": False,
        "duration_s": None,
        "client": {"version": None, "hassh": None, "pubkey_fingerprints": [], "term": None, "arch": None},
        "logins": {"attempts": [], "n_failed": 0, "n_success": 0, "username": None},
        "commands": [],
        "urls": [],
        "files": {"downloads": [], "uploads": []},
        "routes": {"privilege": 0, "deterministic": 0, "escalate_candidate": 0},
        "timing": {"login_to_first_cmd_s": None, "gaps_s": [], "gap_mean_s": None, "gap_std_s": None},
        "counts": {"events": 0, "commands": 0, "failed_commands": 0, "nested_commands": 0},
        "ttylog_shasum": None,
        "_state": {"login_ts": None, "last_cmd_ts": None, "subshell_until": None},
    }


def _ts(e: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(e["ts"])


def _secs(a: str, b: str) -> float:
    return round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds(), 6)


def _update_gap_stats(d: dict[str, Any]) -> None:
    gaps = d["timing"]["gaps_s"]
    if gaps:
        d["timing"]["gap_mean_s"] = round(statistics.fmean(gaps), 6)
        d["timing"]["gap_std_s"] = round(statistics.pstdev(gaps), 6) if len(gaps) > 1 else 0.0


def apply(digest: dict[str, Any], event: dict[str, Any], *, inplace: bool = False) -> dict[str, Any]:
    """Apply one normalised event (Row.as_dict()) and return the digest.

    By default the input is left untouched; the ingester passes
    ``inplace=True`` to avoid copying long sessions on every event."""
    d = digest if inplace else copy.deepcopy(digest)
    eid = event["eventid"]
    ts = event["ts"]
    st = d["_state"]

    d["counts"]["events"] += 1
    if d["start_ts"] is None or ts < d["start_ts"]:
        d["start_ts"] = ts
    if d["last_ts"] is None or ts > d["last_ts"]:
        d["last_ts"] = ts
    for k in ("sensor", "src_ip_hmac", "src_prefix", "protocol", "dst_port"):
        if d[k] is None and event.get(k) is not None:
            d[k] = event[k]

    if eid == "cowrie.client.version":
        d["client"]["version"] = event.get("version")
    elif eid == "cowrie.client.kex":
        d["client"]["hassh"] = event.get("hassh")
    elif eid == "cowrie.client.fingerprint":
        fp = event.get("fingerprint")
        if fp and fp not in d["client"]["pubkey_fingerprints"]:
            d["client"]["pubkey_fingerprints"].append(fp)
    elif eid == "cowrie.client.size":
        d["client"]["term"] = {"width": event.get("width"), "height": event.get("height")}
    elif eid == "cowrie.session.params":
        d["client"]["arch"] = event.get("arch")

    elif eid in ("cowrie.login.success", "cowrie.login.failed"):
        ok = eid.endswith("success")
        logins = d["logins"]
        logins["n_success" if ok else "n_failed"] += 1
        if len(logins["attempts"]) < MAX_LOGIN_ATTEMPTS_KEPT:
            logins["attempts"].append({
                "ts": ts,
                "username": event.get("username"),
                "password_hmac": event.get("password_hmac"),
                "password_len": event.get("password_len"),
                "success": ok,
            })
        if ok:
            logins["username"] = event.get("username")
            st["login_ts"] = ts

    elif eid == "cowrie.command.input":
        text = event.get("input") or ""
        realm = event.get("realm")
        nested = bool(st["subshell_until"] and ts <= st["subshell_until"])
        cmd = {"ts": ts, "input": text, "failed": False, "routes": []}
        if realm:
            cmd["realm"] = realm      # stdin typed into a running command (passwd, cat, ...)
        if nested:
            cmd["nested"] = True      # produced by `... | bash`, not typed
            d["counts"]["nested_commands"] += 1
            # a piped script can hold several lines; keep the window open
            until = _ts(event).timestamp() + SUBSHELL_WINDOW_S
            st["subshell_until"] = datetime.fromtimestamp(until, tz=_ts(event).tzinfo).isoformat()
        if len(d["commands"]) < MAX_COMMANDS_KEPT:
            d["commands"].append(cmd)
        d["counts"]["commands"] += 1
        for url in _URL.findall(text):
            if url not in d["urls"]:
                d["urls"].append(url)
        # Timing only for commands the attacker actually typed.
        if not nested and not realm:
            if st["last_cmd_ts"] is not None:
                d["timing"]["gaps_s"].append(_secs(st["last_cmd_ts"], ts))
                _update_gap_stats(d)
            elif st["login_ts"] is not None:
                d["timing"]["login_to_first_cmd_s"] = _secs(st["login_ts"], ts)
            st["last_cmd_ts"] = ts

    elif eid == "cowrie.command.failed":
        d["counts"]["failed_commands"] += 1
        if d["commands"]:
            d["commands"][-1]["failed"] = True

    elif eid == "cowrie.vulnmaze.route":
        route = event.get("route")
        if route in d["routes"]:
            d["routes"][route] += 1
        if d["commands"]:
            d["commands"][-1]["routes"].append(route)
        if event.get("command") in _SHELLS:
            # Commands piped into this shell will be logged as command.input
            # within milliseconds; mark them as nested, not typed.
            until = _ts(event).timestamp() + SUBSHELL_WINDOW_S
            st["subshell_until"] = datetime.fromtimestamp(until, tz=_ts(event).tzinfo).isoformat()

    elif eid in ("cowrie.session.file_download", "cowrie.session.file_download.failed"):
        d["files"]["downloads"].append({
            "ts": ts,
            "url": event.get("url"),
            "shasum": event.get("shasum"),
            "ok": eid == "cowrie.session.file_download",
        })
    elif eid == "cowrie.session.file_upload":
        d["files"]["uploads"].append({"ts": ts, "filename": event.get("filename"), "shasum": event.get("shasum")})

    elif eid == "cowrie.log.closed":
        d["ttylog_shasum"] = event.get("shasum")

    elif eid == "cowrie.session.closed":
        d["closed"] = True
        d["end_ts"] = ts
        if event.get("duration_ms") is not None:
            d["duration_s"] = round(event["duration_ms"] / 1000, 3)
        elif event.get("duration") is not None:          # older Cowrie versions
            d["duration_s"] = round(float(event["duration"]), 3)

    return d


def public_view(digest: dict[str, Any]) -> dict[str, Any]:
    """The digest without internal bookkeeping, for the ML layer and exports."""
    return {k: v for k, v in digest.items() if not k.startswith("_")}


def build(events: list[dict[str, Any]], source: str, session: str) -> dict[str, Any]:
    d = new_digest(source, session)
    for e in events:
        apply(d, e, inplace=True)
    return d
