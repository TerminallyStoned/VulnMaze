"""Shared helpers for the test suite: a local Cowrie runner and SSH clients."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import paramiko

PROMPT = re.compile(rb"[#$] $")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")

COWRIE_CFG = """\
[honeypot]
hostname = {hostname}
log_path = var/log/cowrie
state_path = var/lib/cowrie
logtype = plain
sensor_name = test-sensor
[ssh]
enabled = true
listen_endpoints = tcp:{port}:interface=127.0.0.1
[telnet]
enabled = false
[output_jsonlog]
enabled = true
logfile = ${{honeypot:log_path}}/cowrie.json
"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class CowrieServer:
    host: str
    port: int
    workdir: Path

    @property
    def json_log(self) -> Path:
        return self.workdir / "var/log/cowrie/cowrie.json"

    def events(self) -> list[dict]:
        if not self.json_log.exists():
            return []
        return [json.loads(line) for line in self.json_log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def lines(self) -> list[str]:
        return [ln for ln in self.json_log.read_text(encoding="utf-8").splitlines() if ln.strip()]


@contextmanager
def run_cowrie(tap: str = "vulnmaze", hostname: str = "web-portal-01", startup_timeout: float = 30,
               env: dict[str, str] | None = None):
    """Start Cowrie (`tap` = 'vulnmaze' for our plugin, 'cowrie' for stock)
    in a temporary directory and stop it afterwards. `env` adds environment
    variables (e.g. VULNMAZE_ESCALATION=all).

    Cowrie refuses to run as root. When the tests run as root (e.g. inside a
    container) set VULNMAZE_TEST_COWRIE_USER to an unprivileged user."""
    twistd = shutil.which("twistd", path=os.path.dirname(sys.executable)) or "twistd"
    port = free_port()
    workdir = Path(tempfile.mkdtemp(prefix="cowrie-"))
    for d in ("etc", "var/log/cowrie", "var/lib/cowrie/downloads", "var/lib/cowrie/tty"):
        (workdir / d).mkdir(parents=True)
    (workdir / "etc/cowrie.cfg").write_text(COWRIE_CFG.format(port=port, hostname=hostname))
    posix = os.name == "posix"
    unix_only = ["--umask=0022", "--pidfile="] if posix else []
    cmd = [twistd, *unix_only, "-n", "-l", str(workdir / "twistd.log"), tap]
    extra = dict(env or {})
    run_as = os.environ.get("VULNMAZE_TEST_COWRIE_USER")
    if posix and os.geteuid() == 0:
        if not run_as:
            raise RuntimeError("running as root: set VULNMAZE_TEST_COWRIE_USER to an unprivileged user")
        shutil.chown(workdir, run_as)
        for p in workdir.rglob("*"):
            shutil.chown(p, run_as)
        inner = ["env", *(f"{k}={v}" for k, v in extra.items()), *cmd]
        cmd = ["su", run_as, "-s", "/bin/sh", "-c", " ".join(shlex.quote(c) for c in inner)]
    proc = subprocess.Popen(cmd, cwd=workdir, start_new_session=posix, env={**os.environ, **extra},
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    def stop(force: bool = False) -> None:
        """Stop Cowrie and anything it started: the process group on POSIX, the process on Windows."""
        if posix:
            os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
        else:
            proc.kill()

    deadline = time.time() + startup_timeout
    log = workdir / "twistd.log"
    while time.time() < deadline:
        if log.exists() and b"Ready to accept SSH connections" in log.read_bytes():
            break
        if proc.poll() is not None:
            raise RuntimeError(f"Cowrie exited early:\n{log.read_text() if log.exists() else ''}")
        time.sleep(0.2)
    else:
        stop()
        raise RuntimeError("Cowrie did not start in time")
    try:
        yield CowrieServer("127.0.0.1", port, workdir)
    finally:
        stop()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            stop(force=True)
        shutil.rmtree(workdir, ignore_errors=True)


def _read_until_prompt(chan, timeout: float = 10) -> bytes:
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if chan.recv_ready():
            buf += chan.recv(65535)
            if PROMPT.search(ANSI.sub(b"", buf)):
                return buf
        else:
            time.sleep(0.02)
    raise TimeoutError(f"no prompt; got {buf[-300:]!r}")


def clean(output: bytes, command: str) -> str:
    """Strip terminal control codes, the echoed command and the next prompt."""
    text = ANSI.sub(b"", output).decode("utf-8", "replace").replace("\r", "")
    lines = text.split("\n")
    if lines and lines[0].strip() == command.strip():
        lines = lines[1:]
    if lines and PROMPT.search(lines[-1].encode()):
        lines = lines[:-1]
    return "\n".join(lines)


def ssh_session(host: str, port: int, commands: list[str], username: str = "root",
                password: str = "S3cretPass!", pause: float = 0.0) -> list[str]:
    """Log in with paramiko, run commands in an interactive shell, return the
    cleaned output of each."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port, username=username, password=password,
                   look_for_keys=False, allow_agent=False, timeout=15)
    outputs = []
    try:
        chan = client.invoke_shell(width=80, height=24)
        _read_until_prompt(chan)
        for c in commands:
            chan.send((c + "\n").encode())
            if c.strip() in ("exit", "logout"):
                deadline = time.time() + 5
                while not chan.exit_status_ready() and time.time() < deadline:
                    time.sleep(0.05)
                outputs.append("")
                break
            outputs.append(clean(_read_until_prompt(chan), c))
            if pause:
                time.sleep(pause)
    finally:
        client.close()
    return outputs


def failed_login(host: str, port: int, username: str = "root", password: str = "root") -> None:
    """Cowrie's default userdb rejects root/root."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port, username=username, password=password,
                       look_for_keys=False, allow_agent=False, timeout=15)
    except paramiko.AuthenticationException:
        pass
    finally:
        client.close()


def wait_for(predicate, timeout: float = 10, interval: float = 0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise TimeoutError("condition not met")
