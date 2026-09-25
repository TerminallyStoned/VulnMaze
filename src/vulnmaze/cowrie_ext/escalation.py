"""Cowrie side of the LLM gap-filler.

`make_command(name)` returns a Cowrie command class that sends one pipeline
stage to the LLM gateway and prints the gateway's answer. It is only ever
returned by the getCommand hook in hooks.py, and only for stages that
Cowrie cannot answer and the router marked escalate_candidate.

Configuration (environment variables of the Cowrie container):

    VULNMAZE_ESCALATION       off (default) | all
    VULNMAZE_GATEWAY_URL      http://llm-gateway:8090
    VULNMAZE_GATEWAY_TOKEN    shared secret with the gateway
    VULNMAZE_GATEWAY_TIMEOUT  seconds before the local fallback (default 10)

"all" means every eligible stage is escalated.

The call is asynchronous (Twisted + treq, as Cowrie's own curl does), so a
slow model never blocks other attackers' sessions.
"""

from __future__ import annotations

import os
import posixpath
import re
import time
from dataclasses import dataclass

import treq
from twisted.logger import Logger

log = Logger(namespace="vulnmaze.escalation")

LLM_EVENT = "cowrie.vulnmaze.llm"
BIN_DIRS = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
MAX_STDIN = 16_000
HISTORY = 15
SESSION_FILES_TIMEOUT = float(os.environ.get("VULNMAZE_SESSION_FILES_TIMEOUT", "2"))
# Used when the gateway cannot be reached. A transient error never claims
# the program exists or does not, so it cannot contradict a pinned answer.
EOF = object()   # marker for a held end-of-input
LOCAL_FALLBACK = "-bash: fork: Resource temporarily unavailable\n"


@dataclass(frozen=True)
class Config:
    mode: str
    url: str
    token: str
    timeout: float

    @property
    def enabled(self) -> bool:
        return self.mode == "all"

    @classmethod
    def from_env(cls) -> Config:
        mode = os.environ.get("VULNMAZE_ESCALATION", "off").strip().lower()
        if mode not in ("off", "all"):
            log.error("Unknown VULNMAZE_ESCALATION={m!r}; escalation disabled", m=mode)
            mode = "off"
        token = os.environ.get("VULNMAZE_GATEWAY_TOKEN", "")
        if mode != "off" and not token:
            log.error("VULNMAZE_GATEWAY_TOKEN not set; escalation disabled")
            mode = "off"
        return cls(
            mode=mode,
            url=os.environ.get("VULNMAZE_GATEWAY_URL", "http://llm-gateway:8090").rstrip("/"),
            token=token,
            timeout=float(os.environ.get("VULNMAZE_GATEWAY_TIMEOUT", "10")),
        )


CONFIG = Config.from_env()


def escalatable_name(cmd: str) -> bool:
    """Bare program names, or absolute paths in the standard bin directories.
    `./x` or `/tmp/x` are the attacker's own files: never the model's to invent."""
    if "/" in cmd:
        return posixpath.dirname(posixpath.normpath(cmd)) in BIN_DIRS and bool(
            _NAME.match(posixpath.basename(cmd)))
    return bool(_NAME.match(cmd))


def _identity(protocol) -> tuple[str, str]:
    ident = getattr(getattr(protocol, "events", None), "identity", {}) or {}
    return str(ident.get("session", "")), str(ident.get("src_ip") or getattr(protocol, "realClientIP", ""))


def materialise(fs, path: str, content: str, uid: int = 0, gid: int = 0) -> bool:
    """Put a file into this session's in-memory filesystem (Cowrie keeps
    file bytes in the node, so nothing is written to disk)."""
    from cowrie.shell.fs import A_CONTENTS, A_SIZE

    try:
        parts = [p for p in posixpath.normpath(path).split("/") if p]
        for i in range(1, len(parts)):
            d = "/" + "/".join(parts[:i])
            if not fs.exists(d):
                fs.mkdir(d, uid, gid, 4096, 0o40755)
        data = content.encode("utf-8")
        if not fs.mkfile(path, uid, gid, len(data), 0o100644):
            return False
        node = fs.getfile(path)
        node[A_CONTENTS] = data
        node[A_SIZE] = len(data)
        return True
    except Exception:
        log.failure("could not create {path}", path=path)
        return False


def make_command(name: str):
    from cowrie.shell.command import HoneyPotCommand

    class Command_vulnmaze_llm(HoneyPotCommand):
        program = name

        def start(self) -> None:
            self._t0 = time.monotonic()
            session, src_ip = _identity(self.protocol)
            login = getattr(getattr(self.protocol, "user", None), "username", "root")
            history = [h.decode("utf-8", "replace") if isinstance(h, bytes) else str(h)
                       for h in getattr(self.protocol, "historyLines", [])[-HISTORY - 1:-1]]
            stdin = None
            if self.input_data:
                stdin = self.input_data[:MAX_STDIN].decode("utf-8", "replace")
            payload = {
                "session": session,
                "src_ip": src_ip,
                "username": login,
                "cwd": self.cwd,
                "home": self.user.get("home", "/root"),
                "argv": [self.program, *self.args],
                "stdin": stdin,
                "history": history,
            }
            try:
                d = treq.post(f"{CONFIG.url}/v1/escalate", json=payload, timeout=CONFIG.timeout,
                              headers={"Authorization": f"Bearer {CONFIG.token}"})
            except Exception as exc:  # treq can raise before returning a Deferred
                self._failed(exc)
                return
            d.addCallback(self._response)
            d.addCallbacks(self._done, self._failed)
            self._deferred = d

        def _response(self, response):
            if response.code != 200:
                raise RuntimeError(f"gateway HTTP {response.code}")
            return treq.json_content(response)

        def _done(self, data: dict) -> None:
            if self.exited:
                return
            for f in data.get("files") or []:
                materialise(self.fs, f["path"], f["content"], self.user.get("uid", 0), self.user.get("gid", 0))
            if data.get("stdout"):
                self.write(data["stdout"])
            if data.get("stderr"):
                self.errorWrite(data["stderr"])
            self._event(data.get("outcome", "unknown"), data.get("reasons", []), data.get("latency_ms"))
            self.exit(int(data.get("exit_code", 0)))

        def _failed(self, failure) -> None:
            if self.exited:
                return
            reason = getattr(failure, "value", failure)
            self.errorWrite(LOCAL_FALLBACK)
            self._event("gateway_unreachable", [type(reason).__name__], None)
            self.exit(1)

        def _event(self, outcome: str, reasons: list[str], gateway_ms) -> None:
            try:
                self.protocol.events.dispatch(
                    LLM_EVENT,
                    "LLM %(outcome)s for %(input)s",
                    outcome=outcome,
                    input=" ".join([self.program, *self.args])[:2000],
                    reasons=reasons[:20],
                    latency_ms=int((time.monotonic() - self._t0) * 1000),
                    gateway_ms=gateway_ms,
                )
            except Exception:
                log.failure("could not log LLM event")

        def handle_CTRL_C(self) -> None:  # noqa: N802 (Cowrie's name)
            # Exit first: cancelling fires the errback synchronously, and it
            # must find the command already finished.
            if not self.exited:
                self._event("interrupted", [], None)
                self.write("^C\n")
                self.exit(130)
            d = getattr(self, "_deferred", None)
            if d is not None:
                d.cancel()

    Command_vulnmaze_llm.__name__ = f"Command_vulnmaze_llm_{name}"
    return Command_vulnmaze_llm


def install_session_files_hook() -> None:
    """When a session starts, fetch the files the LLM created for this
    attacker earlier and add them to the session's filesystem, so an
    invented file is still there next time they log in.

    The fetch is asynchronous, so command lines that arrive before it
    finishes (the first line of an exec session always does) are held and
    replayed in order once the files are loaded, or after at most
    SESSION_FILES_TIMEOUT seconds if the gateway is slow or down."""
    from cowrie.shell.honeypot import HoneyPotShell
    from cowrie.shell.protocol import HoneyPotBaseProtocol

    original_connection_made = HoneyPotBaseProtocol.connectionMade
    original_line = HoneyPotShell.lineReceived
    original_eof = HoneyPotShell.eofReceived

    def flush(protocol) -> None:
        if not getattr(protocol, "_vulnmaze_files_pending", False):
            return
        protocol._vulnmaze_files_pending = False
        held, protocol._vulnmaze_held = protocol._vulnmaze_held, []
        for shell, line in held:
            try:
                if line is EOF:
                    # Deliver to whoever reads stdin *now* (a command started
                    # by a replayed line, or the shell), as Cowrie would have.
                    if getattr(protocol, "cmdstack", None):
                        protocol.cmdstack[-1].eofReceived()
                else:
                    original_line(shell, line)
            except Exception:
                log.failure("could not replay held input")

    def connectionMade(self) -> None:  # noqa: N802 (Cowrie's name)
        self._vulnmaze_files_pending = True
        self._vulnmaze_held = []
        original_connection_made(self)
        try:
            _, src_ip = _identity(self)
            username = self.user.username
            uid, gid = getattr(self.user, "uid", 0), getattr(self.user, "gid", 0)
            d = treq.get(f"{CONFIG.url}/v1/session-files", params={"src_ip": src_ip, "username": username},
                         headers={"Authorization": f"Bearer {CONFIG.token}"},
                         timeout=SESSION_FILES_TIMEOUT)
            d.addCallback(lambda r: treq.json_content(r) if r.code == 200 else [])

            def load(files):
                for f in files or []:
                    materialise(self.fs, f["path"], f["content"], uid, gid)

            d.addCallback(load)
            d.addErrback(lambda failure: log.info("session files unavailable: {e}", e=failure.value))
            d.addBoth(lambda _: flush(self))
        except Exception:
            log.failure("could not request session files")
            flush(self)

    def lineReceived(self, line):  # noqa: N802 (Cowrie's name)
        protocol = self.protocol
        if getattr(protocol, "_vulnmaze_files_pending", False):
            protocol._vulnmaze_held.append((self, line))
            return None
        return original_line(self, line)

    def eofReceived(self):  # noqa: N802 (Cowrie's name)
        # A client that closes stdin straight after an exec request (common
        # for bots, and `ssh host cmd < /dev/null`) must not end the session
        # before the held command has run.
        protocol = self.protocol
        if getattr(protocol, "_vulnmaze_files_pending", False):
            protocol._vulnmaze_held.append((self, EOF))
            return None
        return original_eof(self)

    HoneyPotBaseProtocol.connectionMade = connectionMade
    HoneyPotShell.lineReceived = lineReceived
    HoneyPotShell.eofReceived = eofReceived
