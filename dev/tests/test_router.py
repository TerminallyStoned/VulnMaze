import csv
import json
import statistics
import time

import pytest
from conftest import FIXTURES

from vulnmaze.cowrie_ext.hooks import may_escalate
from vulnmaze.router import (
    Route,
    classify_argv,
    classify_line,
    is_sensitive_path,
    program_name,
    split_pipeline,
    strictest,
)

with (FIXTURES / "router_labelled.csv").open() as fh:
    TABLE = list(csv.DictReader(fh))


@pytest.mark.parametrize("row", TABLE, ids=[r["line"][:40] for r in TABLE])
def test_labelled_command_table(row):
    """Every hand-labelled line in router_labelled.csv must route exactly as recorded."""
    assert strictest(classify_line(row["line"])).value == row["expected"], row["note"]


def test_table_is_big_enough_and_balanced():
    """The regression table stays large and covers all three routes."""
    counts = {r["expected"] for r in TABLE}
    assert len(TABLE) >= 200 and counts == {"privilege", "deterministic", "escalate_candidate"}


def test_route_events_are_json_serialisable():
    """A Decision exports to JSON, because the Cowrie hook logs it as an event."""
    assert json.loads(json.dumps(classify_line("cat /etc/shadow")[0].as_dict()))["route"] == "privilege"


@pytest.mark.parametrize("argv", [
    ["sudo", "-l"],
    ["usermod", "-aG", "sudo", "bob"],
    ["/usr/sbin/useradd", "eve"],
    ["cat", "/etc/shadow"],
    ["cat", "/root/.ssh/id_rsa"],
    ["cat", "~/.ssh/authorized_keys"],
    ["ls", "/etc/sha*"],
    ["env", "X=1", "nohup", "cat", "/etc/shadow"],
    ["timeout", "5s", "passwd"],
    ["python", "-c", "open('/etc/shadow').read()"],
    ["dd", "if=/dev/mem", "of=/tmp/x"],
    ["chmod", "4755", "/tmp/x"],
    ["chmod", "u+s", "/tmp/x"],
])
def test_privilege_floor(argv):
    """Privilege commands and sensitive paths are always PRIVILEGE, whatever wraps or hides them."""
    assert classify_argv(argv).route is Route.PRIVILEGE


@pytest.mark.parametrize("argv", [["ls", "-la"], ["cd", "/tmp"], ["chmod", "755", "x"],
                                  ["wget", "http://example.test/etc/shadow"], ["X=1"]])
def test_deterministic(argv):
    """Commands Cowrie implements, builtins and URLs that merely look like paths stay deterministic."""
    assert classify_argv(argv).route is Route.DETERMINISTIC


@pytest.mark.parametrize("argv", [["lsblk"], ["systemctl", "status", "nginx"], ["$CMD", "x"]])
def test_escalate_candidates(argv):
    """Unimplemented or dynamically named commands are the only ones offered to the LLM."""
    assert classify_argv(argv).route is Route.ESCALATE_CANDIDATE


def test_relative_path_resolves_against_cwd():
    """A bare or relative argument is judged at its resolved location."""
    assert classify_argv(["cat", "shadow"], cwd="/etc").route is Route.PRIVILEGE
    assert classify_argv(["cat", "shadow"], cwd="/tmp").route is Route.DETERMINISTIC
    assert classify_argv(["cat", "../etc/shadow"], cwd="/tmp").route is Route.PRIVILEGE


def test_root_home_itself_is_not_sensitive():
    """Only credential directories under a home count, not the home directory or host keys."""
    assert not is_sensitive_path("/root/notes.txt")
    assert is_sensitive_path("/home/bob/.gnupg/pubring.kbx")
    assert is_sensitive_path("~/.ssh/authorized_keys", home="/home/bob")
    assert not is_sensitive_path("/etc/ssh/ssh_host_rsa_key.pub")


@pytest.mark.parametrize("line", ["sudo -l", "cat /etc/shadow", "su root", "passwd",
                                  "cat /root/.ssh/id_rsa", "chmod u+s /bin/bash"])
def test_privilege_is_never_offered_to_the_llm(line):
    """The security-floor invariant: may_escalate is False for every PRIVILEGE decision."""
    decisions = classify_line(line)
    assert strictest(decisions) is Route.PRIVILEGE
    assert all(not may_escalate(d) for d in decisions if d.route is Route.PRIVILEGE)


def test_chains_split_into_one_decision_per_command():
    """;, &&, ||, | and & each start a new command, classified in order."""
    assert [d.command for d in classify_line("a; b && c | d || e & f")] == list("abcdef")
    assert [d.route for d in classify_line("uname -a; cat /etc/shadow | head -1")] == [
        Route.DETERMINISTIC, Route.PRIVILEGE, Route.DETERMINISTIC]


def test_offline_latency_p99_under_5ms():
    """Classification runs on every typed command, so its p99 must stay in single-digit ms."""
    samples = []
    for line in [r["line"] for r in TABLE] * 5:
        start = time.perf_counter()
        classify_line(line)
        samples.append((time.perf_counter() - start) * 1000)
    p99 = statistics.quantiles(samples, n=100)[98]
    assert p99 < 5.0, f"p99 {p99:.3f} ms"



@pytest.mark.parametrize("line", [
    "echo $(cat /etc/shadow)",
    "echo `cat /etc/shadow`",
    "bash -c 'usermod -aG sudo bob'",
    "uname -a; cat /etc/sudoers",
    "ls | sudo tee /x",
])
def test_offline_lines_take_the_strictest_route(line):
    """Substitutions, inner shells and every pipeline stage are classified, and PRIVILEGE wins."""
    assert strictest(classify_line(line)) is Route.PRIVILEGE


def test_offline_line_without_privilege():
    """A benign line containing an unimplemented command is an escalate candidate overall."""
    assert strictest(classify_line("uname -a && lsblk")) is Route.ESCALATE_CANDIDATE
    assert strictest(classify_line("")) is Route.DETERMINISTIC


def test_split_pipeline():
    """Pipelines split on | and |& and drop empty stages."""
    assert split_pipeline(["cat", "x", "|", "grep", "y", "|&", "wc"]) == [["cat", "x"], ["grep", "y"], ["wc"]]


@pytest.mark.parametrize("cmd, name", [("uname", "uname"), ("/usr/bin/uname", "uname"), ("/usr/local/sbin/php-fpm8.2", "php-fpm8.2")])
def test_program_name_accepts_bare_names_and_standard_bin_paths(cmd, name):
    """A bare program name, or one in a standard bin directory, may reach the LLM under its plain name."""
    assert program_name(cmd) == name


@pytest.mark.parametrize("cmd", ["./x", "/tmp/x", "/usr/bin/../../tmp/x", "-rf", "a" * 65, ""])
def test_program_name_refuses_the_attackers_own_files_and_odd_names(cmd):
    """Files outside the bin directories and names that are not program names never reach the LLM."""
    assert program_name(cmd) is None
