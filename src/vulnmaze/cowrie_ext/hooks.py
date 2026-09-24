"""Hooks VulnMaze installs into Cowrie at start-up.

We do not fork Cowrie. The pinned Cowrie package is installed unchanged and
our twistd plugin (src/twisted/plugins/vulnmaze_plugin.py) calls
``install()`` before Cowrie builds its services. ``install()``:

1. adds the fixed privilege handlers from ``commands.py`` to Cowrie's
   command table, and
2. wraps ``HoneyPotShell._run_expanded``, the single point where Cowrie has
   fully expanded one pipeline (quotes removed, variables and $(...) done)
   and is about to look up the command. We classify every stage there and
   log a ``cowrie.vulnmaze.route`` event, then hand over to Cowrie.

If anything in our code raises, the original Cowrie behaviour runs and the
error is logged: the hook must never break an attacker's session.

Extension point: ``ESCALATION_HANDLER``, when set, is called for
ESCALATE_CANDIDATE stages Cowrie cannot answer. PRIVILEGE stages never reach
it, whatever the handler does; that invariant is enforced here.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from twisted.logger import Logger

from vulnmaze.router import Decision, Route, classify_argv, split_pipeline

log = Logger(namespace="vulnmaze")

ROUTE_EVENT = "cowrie.vulnmaze.route"

# Optional escalation hook. Signature: (shell, decision) -> bool (True if it answered).
ESCALATION_HANDLER: Callable[[object, Decision], bool] | None = None

_installed = False


def _route_pipeline(shell, tokens: list[str]) -> list[Decision]:
    cwd = getattr(shell, "cwd", "/root") or "/root"
    environ = getattr(shell, "environ", {}) or {}
    home = environ.get("HOME", "/root")
    paths = environ.get("PATH", "").split(":")
    protocol = shell.protocol

    def is_known(cmd: str) -> bool:
        try:
            return protocol.getCommand(cmd, paths, cwd) is not None
        except Exception:
            return False

    return [classify_argv(stage, cwd=cwd, home=home, is_known=is_known)
            for stage in split_pipeline(tokens)]


def install() -> None:
    global _installed
    if _installed:
        return

    from cowrie.shell.honeypot import HoneyPotShell
    from cowrie.shell.protocol import HoneyPotBaseProtocol

    from .commands import commands as extra_commands

    HoneyPotBaseProtocol.commands.update(extra_commands)

    original = HoneyPotShell._run_expanded

    def _run_expanded(self, cmdAndArgs):  # noqa: N803 (Cowrie's name)
        try:
            started = time.perf_counter()
            decisions = _route_pipeline(self, list(cmdAndArgs))
            elapsed_us = int((time.perf_counter() - started) * 1e6)
            for d in decisions:
                self.protocol.events.dispatch(
                    ROUTE_EVENT,
                    "Route %(route)s for %(command)s (%(reason)s)",
                    route=d.route.value,
                    command=d.command,
                    input=" ".join(d.argv),
                    reason=d.reason,
                    router_us=elapsed_us,
                )
            self._vulnmaze_last_routes = decisions
        except Exception:
            log.failure("VulnMaze router failed; falling back to Cowrie")
        return original(self, cmdAndArgs)

    _run_expanded._vulnmaze = True  # type: ignore[attr-defined]
    HoneyPotShell._run_expanded = _run_expanded
    _installed = True
    log.info("VulnMaze hooks installed ({n} extra commands)", n=len(extra_commands))


def may_escalate(decision: Decision) -> bool:
    """The security-floor invariant, in one place: only ESCALATE_CANDIDATE
    stages may ever be offered to the LLM."""
    return decision.route is Route.ESCALATE_CANDIDATE
