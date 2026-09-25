"""Hooks VulnMaze installs into Cowrie at start-up.

We do not fork Cowrie. The pinned Cowrie package is installed unchanged and
our twistd plugin (src/twisted/plugins/vulnmaze_plugin.py) calls
``install()`` before Cowrie builds its services. ``install()``:

1. adds the fixed privilege handlers from ``commands.py`` to Cowrie's
   command table;
2. wraps ``HoneyPotShell._run_expanded``, the single point where Cowrie has
   fully expanded one pipeline (quotes removed, variables and $(...) done)
   and is about to look up the command. We classify every stage there and
   log a ``cowrie.vulnmaze.route`` event, then hand over to Cowrie;
3. when escalation is on, wraps ``getCommand`` so that a stage Cowrie
   cannot answer, and that the router marked escalate_candidate, runs the
   LLM command from ``escalation.py`` instead of "command not found";
4. when escalation is on, loads the files the LLM created for this attacker
   in earlier sessions into the new session's filesystem.

If anything in our code raises, the original Cowrie behaviour runs and the
error is logged: the hooks must never break an attacker's session.
"""

from __future__ import annotations

import posixpath
import time

from twisted.logger import Logger

from vulnmaze.router import Decision, Route, classify_argv, split_pipeline
from vulnmaze.router.router import _ASSIGNMENT

log = Logger(namespace="vulnmaze")

ROUTE_EVENT = "cowrie.vulnmaze.route"
BIN_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin")

_installed = False
_original_get_command = None


def may_escalate(decision: Decision) -> bool:
    """The security-floor invariant, in one place: only ESCALATE_CANDIDATE
    stages may ever be offered to the LLM."""
    return decision.route is Route.ESCALATE_CANDIDATE


def _resolve_in_path(protocol, cmd: str, paths: list[str], cwd: str) -> str | None:
    if "/" in cmd:
        path = protocol.fs.resolve_path(cmd, cwd)
        return path if protocol.fs.exists(path) else None
    for d in paths:
        if d:
            candidate = f"{protocol.fs.resolve_path(d, cwd)}/{cmd}"
            if protocol.fs.exists(candidate):
                return candidate
    return None


def cowrie_answers(protocol, cmd: str, paths: list[str], cwd: str):
    """What Cowrie itself would run for `cmd`, or None if it has nothing
    real. A binary that only exists as a file in Cowrie's filesystem (e.g.
    /usr/bin/lsblk) is run as a "script" by Cowrie, which prints "cannot
    execute binary file": that counts as no answer. Scripts elsewhere (a
    file the attacker wrote to /tmp) still count as Cowrie's to run."""
    found = _original_get_command(protocol, cmd, paths, cwd)
    if found is None:
        return None
    if getattr(found, "__name__", "") == "Command_scriptcmd":
        path = _resolve_in_path(protocol, cmd, paths, cwd)
        if path and posixpath.dirname(path) in BIN_DIRS:
            return None
    return found


def _route_pipeline(shell, tokens: list[str]) -> list[tuple[str, Decision]]:
    """(first token Cowrie will look up, decision) for each pipeline stage."""
    cwd = getattr(shell, "cwd", "/root") or "/root"
    environ = getattr(shell, "environ", {}) or {}
    home = environ.get("HOME", "/root")
    paths = environ.get("PATH", "").split(":")
    protocol = shell.protocol

    def is_known(cmd: str) -> bool:
        try:
            return cowrie_answers(protocol, cmd, paths, cwd) is not None
        except Exception:
            return False

    out = []
    for stage in split_pipeline(tokens):
        first = next((t for t in stage if not _ASSIGNMENT.match(t)), "")
        out.append((first, classify_argv(stage, cwd=cwd, home=home, is_known=is_known)))
    return out


def install() -> None:
    global _installed, _original_get_command
    if _installed:
        return

    from cowrie.shell.honeypot import HoneyPotShell
    from cowrie.shell.protocol import HoneyPotBaseProtocol

    from . import escalation
    from .commands import commands as extra_commands

    HoneyPotBaseProtocol.commands.update(extra_commands)
    _original_get_command = HoneyPotBaseProtocol.getCommand
    original_run = HoneyPotShell._run_expanded

    def _run_expanded(self, cmdAndArgs):  # noqa: N803 (Cowrie's name)
        protocol = self.protocol
        previous = getattr(protocol, "_vulnmaze_escalatable", None)
        try:
            started = time.perf_counter()
            routed = _route_pipeline(self, list(cmdAndArgs))
            elapsed_us = int((time.perf_counter() - started) * 1e6)
            allowed: dict[str, bool] = {}
            for first, d in routed:
                protocol.events.dispatch(
                    ROUTE_EVENT,
                    "Route %(route)s for %(command)s (%(reason)s)",
                    route=d.route.value,
                    command=d.command,
                    input=" ".join(d.argv),
                    reason=d.reason,
                    router_us=elapsed_us,
                )
                # A token appearing in two stages may escalate only if every
                # stage using it may.
                allowed[first] = allowed.get(first, True) and may_escalate(d)
            protocol._vulnmaze_escalatable = allowed
            self._vulnmaze_last_routes = [d for _, d in routed]
        except Exception:
            log.failure("VulnMaze router failed; falling back to Cowrie")
            protocol._vulnmaze_escalatable = {}
        try:
            return original_run(self, cmdAndArgs)
        finally:
            protocol._vulnmaze_escalatable = previous

    _run_expanded._vulnmaze = True  # type: ignore[attr-defined]
    HoneyPotShell._run_expanded = _run_expanded

    if escalation.CONFIG.enabled:
        def getCommand(self, cmd, paths, cwd):  # noqa: N802 (Cowrie's name)
            found = cowrie_answers(self, cmd, paths, cwd)
            if found is not None:
                return found
            try:
                if getattr(self, "_vulnmaze_escalatable", None) and self._vulnmaze_escalatable.get(cmd):
                    if escalation.escalatable_name(cmd):
                        return escalation.make_command(cmd)
            except Exception:
                log.failure("VulnMaze escalation lookup failed")
            # Fall back to exactly what Cowrie would have done.
            return _original_get_command(self, cmd, paths, cwd)

        HoneyPotBaseProtocol.getCommand = getCommand
        escalation.install_session_files_hook()

    _installed = True
    log.info("VulnMaze hooks installed ({n} extra commands, escalation={e})",
             n=len(extra_commands), e=escalation.CONFIG.mode)
