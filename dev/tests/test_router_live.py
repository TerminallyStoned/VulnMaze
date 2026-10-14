"""Router behaviour inside a running Cowrie: obfuscation, latency, handlers, parity.

Needs the `honeypot` extra; skipped without it. Marked `cowrie`.
"""

from __future__ import annotations

import statistics
import time

import pytest
from _support import ssh_session

# Every line must end up routing `cat /etc/shadow` to PRIVILEGE once the shell
# has expanded it, which is where the router actually sees the command.
OBFUSCATED = [
    "cat /etc/shadow",
    "/bin/c'a't /etc/sh''adow",
    "$(echo cat) /etc/shadow",
    "`echo cat` /etc/shadow",
    "X=/etc; cat $X/shadow",
    "cd /etc; cat shadow",
    "echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash",   # base64 of 'cat /etc/shadow'
    "bash -c 'cat /etc/shadow'",
    "cat /etc/../etc/shadow",
]

DETERMINISTIC_CMDS = ["uname -a", "whoami", "id", "pwd", "hostname", "cat /etc/passwd",
                      "ls -la /", "ls /tmp", "echo hello world", "cat /proc/cpuinfo",
                      "cat /etc/issue", "which ls", "groups", "cat /etc/hostname"]

pytestmark = pytest.mark.cowrie


def test_obfuscated_shadow_reads_reach_the_privilege_route(cowrie_server):
    """Quotes, substitutions, base64 and cwd tricks all still route to PRIVILEGE."""
    before = len(cowrie_server.events())
    ssh_session(cowrie_server.host, cowrie_server.port, OBFUSCATED + ["exit"])
    time.sleep(1.0)
    events = cowrie_server.events()[before:]
    # Group route events under the typed line that caused them. Lines run by
    # `... | bash` are logged as command.input too, so match typed lines in order.
    per_line: list[tuple[str, list[dict]]] = []
    for e in events:
        nxt = OBFUSCATED[len(per_line)] if len(per_line) < len(OBFUSCATED) else None
        if e["eventid"] == "cowrie.command.input" and e["input"] == nxt:
            per_line.append((e["input"], []))
        elif e["eventid"] == "cowrie.vulnmaze.route" and per_line:
            per_line[-1][1].append(e)
    assert [line for line, _ in per_line] == OBFUSCATED
    for line, routes in per_line:
        shadow = [r for r in routes if r["command"] == "cat" and r["input"].endswith("shadow")]
        assert shadow and all(r["route"] == "privilege" for r in shadow), f"not caught: {line}"


def test_live_router_latency_stays_submillisecond(cowrie_server):
    """Routing inside a real session costs well under a millisecond at the median.

    Scoped to this test's own session: `cowrie_server` is shared for the whole run, so
    reading every event would mix in other tests' privilege and gateway routes. The hard
    p99 < 5 ms bound lives in test_router.py, replaying the table offline; here the same
    `router_us` field is checked end to end, with a p99 ceiling loose enough to survive a
    loaded CI box but tight enough to catch a blocking call entering the hot path.
    """
    before = len(cowrie_server.events())
    ssh_session(cowrie_server.host, cowrie_server.port, ["uname -a", "id", "ls -la /"] * 10 + ["exit"])
    time.sleep(0.6)
    us = [e["router_us"] for e in cowrie_server.events()[before:] if e["eventid"] == "cowrie.vulnmaze.route"]
    assert len(us) >= 20, f"only {len(us)} route samples"
    median_ms = statistics.median(us) / 1000
    p99_ms = statistics.quantiles(us, n=100)[98] / 1000
    assert median_ms < 1.0, f"median {median_ms:.3f} ms"
    assert p99_ms < 25.0, f"p99 {p99_ms:.3f} ms"


def test_added_privilege_handlers_answer_in_cowrie(cowrie_server):
    """usermod, sudo -l and pkexec are implemented rather than falling through to not-found."""
    out = ssh_session(cowrie_server.host, cowrie_server.port,
                      ["usermod -aG sudo bob; echo $?", "sudo -l", "pkexec id", "exit"])
    assert out[0].strip() == "0"
    assert "may run the following commands" in out[1]
    assert "Not authorized" in out[2]


def test_deterministic_output_matches_stock_cowrie(cowrie_server, stock_cowrie_server):
    """Regression floor: every command the router keeps deterministic prints exactly what
    unmodified Cowrie prints, so the honeypot's cover is not blown by the extension."""
    ours = ssh_session(cowrie_server.host, cowrie_server.port, DETERMINISTIC_CMDS + ["exit"])
    stock = ssh_session(stock_cowrie_server.host, stock_cowrie_server.port, DETERMINISTIC_CMDS + ["exit"])
    for cmd, a, b in zip(DETERMINISTIC_CMDS, ours, stock, strict=False):
        assert a == b, f"output differs for {cmd!r}"


@pytest.mark.parametrize("command,expected", [
    ("find / -name no_such_file_zz", []),
    ("find /etc -name hostname", ["/etc/hostname"]),
    ("find /proc/1 -maxdepth 3 -name root", ["/proc/1/root"]),
])
def test_find_lists_symlinks_without_descending_into_them(cowrie_server, command, expected):
    """find answers within the prompt timeout and does not loop through links that point at their own parent."""
    out = ssh_session(cowrie_server.host, cowrie_server.port, [command, "exit"])
    assert out[0].split() == expected


@pytest.mark.parametrize("command", ["find /no/such/dir -name x", "find /tmp/missing"])
def test_find_on_a_missing_path_prints_nothing(cowrie_server, command):
    """A start path that does not exist returns at once with no output, as Cowrie's own find does."""
    out = ssh_session(cowrie_server.host, cowrie_server.port, [command, "exit"])
    assert out[0].strip() == ""
