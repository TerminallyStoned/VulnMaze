from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

import paramiko

from .agent import AgentError, Attacker
from .objectives import OBJECTIVES, Objective, load_objectives

ALLOWED_TARGETS = frozenset({("127.0.0.1", 2222), ("::1", 2222), ("localhost", 2222)})
TIER = "llm_agent"


class ContainmentError(Exception):
    """The requested target is not our honeypot; the harness refuses to connect."""


def check_target(host: str, port: int) -> None:
    """Refuse any target other than the honeypot's localhost SSH port."""
    if (host, port) not in ALLOWED_TARGETS:
        raise ContainmentError(
            f"refusing target {host}:{port}; the harness may only reach the honeypot "
            f"at one of {sorted(ALLOWED_TARGETS)}"
        )


def load_env_file(path: Path) -> None:
    """Set OPENROUTER_* vars from a KEY=VALUE env file without logging their values."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("OPENROUTER_") and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


def _read_until_idle(chan: paramiko.Channel, read_timeout: float, idle: float = 0.6) -> str:
    chunks: list[bytes] = []
    deadline = time.monotonic() + read_timeout
    last = time.monotonic()
    while time.monotonic() < deadline:
        if chan.recv_ready():
            chunks.append(chan.recv(65536))
            last = time.monotonic()
        elif chunks and time.monotonic() - last > idle:
            break
        else:
            time.sleep(0.05)
    return b"".join(chunks).decode("utf-8", "replace")


def _emit(sink: TextIO, record: dict) -> None:
    sink.write(json.dumps(record) + "\n")
    sink.flush()


def _open_shell(
    host: str, port: int, username: str, password: str, read_timeout: float
) -> tuple[paramiko.SSHClient, paramiko.Channel, str, int]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    src_ip, src_port = client.get_transport().sock.getsockname()[:2]
    chan = client.invoke_shell(width=120, height=40)
    chan.settimeout(read_timeout)
    _read_until_idle(chan, read_timeout)
    return client, chan, src_ip, src_port


def run_session(
    objective: Objective,
    attacker: Attacker,
    sink: TextIO,
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    max_steps: int,
    read_timeout: float,
) -> dict:
    """Drive one attacker session against the honeypot and log a record per step."""
    check_target(host, port)
    run_id = uuid.uuid4().hex[:12]
    client, chan, src_ip, src_port = _open_shell(host, port, username, password, read_timeout)
    last_output: str | None = None
    steps = 0
    try:
        for step_no in range(1, max_steps + 1):
            try:
                step = attacker.next_step(last_output)
            except AgentError as exc:
                _emit(
                    sink,
                    {
                        "run_id": run_id,
                        "objective": objective.id,
                        "model": attacker.model,
                        "step": step_no,
                        "tier": TIER,
                        "error": str(exc),
                        "ts": datetime.now(UTC).isoformat(),
                    },
                )
                break
            started = time.perf_counter()
            chan.sendall(step.command + "\n")
            output = _read_until_idle(chan, read_timeout)
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            steps = step_no
            _emit(
                sink,
                {
                    "run_id": run_id,
                    "session_id": None,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "objective": objective.id,
                    "objective_tactic": objective.tactic,
                    "model": attacker.model,
                    "step": step_no,
                    "command": step.command,
                    "intent": step.intent,
                    "tactic": step.tactic,
                    "technique": step.technique,
                    "output_len": len(output),
                    "duration_ms": elapsed_ms,
                    "done": step.done,
                    "tier": TIER,
                    "ts": datetime.now(UTC).isoformat(),
                },
            )
            last_output = output
            if step.done:
                break
    finally:
        client.close()
    return {
        "run_id": run_id,
        "objective": objective.id,
        "steps": steps,
        "prompt_tokens": attacker.prompt_tokens,
        "completion_tokens": attacker.completion_tokens,
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: run N sessions per objective against the honeypot."""
    parser = argparse.ArgumentParser(description="Contained LLM-agent attacker harness (#28)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", default="root")
    parser.add_argument("--password", default="hunter2x")
    parser.add_argument("--objective", action="append", dest="objectives")
    parser.add_argument("--objectives-file", type=Path, dest="objectives_file")
    parser.add_argument("--model", action="append", dest="models")
    parser.add_argument("--sessions", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--read-timeout", type=float, default=8.0)
    parser.add_argument("--model-timeout", type=float, default=60.0)
    parser.add_argument(
        "--reasoning",
        action="store_true",
        help="keep reasoning on at low effort, for models that cannot turn it off",
    )
    parser.add_argument("--api-url", default="https://openrouter.ai/api/v1")
    parser.add_argument("--env-file", type=Path, default=Path("infra/.env"))
    parser.add_argument("--out", type=Path, default=Path("dev/harness_runs"))
    args = parser.parse_args(argv)

    check_target(args.host, args.port)
    load_env_file(args.env_file)

    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is not set (see infra/.env)")
    catalog = load_objectives(args.objectives_file) if args.objectives_file else OBJECTIVES
    objectives = args.objectives or list(catalog)
    unknown = [o for o in objectives if o not in catalog]
    if unknown:
        raise SystemExit(f"unknown objective(s) {unknown}; available: {sorted(catalog)}")
    models = args.models or [os.environ.get("OPENROUTER_MODEL", "").strip()]
    if not all(models):
        raise SystemExit("no attacker model; set OPENROUTER_MODEL or pass --model")
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_path = args.out / f"harness-{stamp}.jsonl"

    totals = {"prompt_tokens": 0, "completion_tokens": 0, "sessions": 0}
    with out_path.open("w", encoding="utf-8") as sink:
        for model in models:
            for obj_id in objectives:
                objective = catalog[obj_id]
                for _ in range(args.sessions):
                    attacker = Attacker(
                        url=args.api_url,
                        api_key=key,
                        model=model,
                        objective=objective,
                        timeout=args.model_timeout,
                        reasoning=args.reasoning,
                    )
                    summary = run_session(
                        objective,
                        attacker,
                        sink,
                        host=args.host,
                        port=args.port,
                        username=args.username,
                        password=args.password,
                        max_steps=args.max_steps,
                        read_timeout=args.read_timeout,
                    )
                    totals["prompt_tokens"] += summary["prompt_tokens"]
                    totals["completion_tokens"] += summary["completion_tokens"]
                    totals["sessions"] += 1
                    print(
                        f"{objective.id} [{attacker.model}] run {summary['run_id']}: "
                        f"{summary['steps']} steps, "
                        f"{summary['prompt_tokens']}+{summary['completion_tokens']} tokens"
                    )
    print(
        f"\n{totals['sessions']} sessions -> {out_path} | tokens "
        f"{totals['prompt_tokens']} prompt + {totals['completion_tokens']} completion"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
