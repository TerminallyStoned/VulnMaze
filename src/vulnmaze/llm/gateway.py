"""LLM gap-filler gateway.

Cowrie calls POST /v1/escalate for a pipeline stage it cannot answer and the
router marked `escalate_candidate`. The gateway decides what the attacker
sees, in this order, stopping at the first step that produces an answer:

  1. Route re-check. The gateway classifies the command again with the same
     router. Anything that is not escalate_candidate is refused, so a bug on
     the Cowrie side cannot put the model in front of a privilege boundary.
  2. Existence. Commands the persona lists as absent, or that were already
     pinned as absent, get bash's "command not found" with no model call.
  3. Output pin. If this attacker already ran this exact command (same cwd,
     arguments and stdin), they get the stored answer again.
  4. Limits. Per-attacker rate and global concurrency caps.
  5. Generation. Prompt -> model -> strip reasoning -> parse -> leakage,
     tells, denylist, file paths -> persona and fact contradictions. A
     rejected answer is regenerated once with a correction; a second
     rejection, a model error or a timeout gives a deterministic fallback.
  6. Pinning. Accepted answers, the files they create and the facts they
     declare are written once to the state store and served from there.

Every request is logged to `llm_calls`.

    uvicorn vulnmaze.llm.gateway:app --host 0.0.0.0 --port 8090
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import posixpath
import re
import secrets
import shlex
import time
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

import joblib
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from psycopg_pool import ConnectionPool

from vulnmaze.classify.session import HIGH, predict
from vulnmaze.common.deid import Deidentifier
from vulnmaze.db import apply_schema, dsn_from_env
from vulnmaze.llm import sanitize
from vulnmaze.llm.backends import Backend, ModelError, backend_from_env
from vulnmaze.llm.persona import Persona
from vulnmaze.llm.pinning import FACT_KEY, PersonaChecker, fact_contradictions
from vulnmaze.llm.prompt import PromptBuilder
from vulnmaze.llm.ratelimit import Concurrency, TokenBuckets
from vulnmaze.llm.schema import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_STDOUT,
    MODEL_OUTPUT_SCHEMA,
    AssessRequest,
    CreatedFile,
    EscalationRequest,
    ShellResult,
)
from vulnmaze.router import classify_argv, program_name
from vulnmaze.router.router import Route
from vulnmaze.state.store import StateStore

log = logging.getLogger("vulnmaze.llm")

CORRECTION = "Your previous answer was not accepted. Answer again, following every rule above exactly."
HINTS = {
    "invalid_output:not_json": "Answer with one JSON object that has the listed fields and nothing else.",
    "invalid_output:not_object": "Answer with one JSON object that has the listed fields and nothing else.",
    "invalid_output:bad_fields": "Answer with one JSON object that has the listed fields and nothing else.",
    "invalid_output:exit_code": "exit_code is a whole number from 0 to 255.",
    "reasoning_unclosed": "Give only the answer, without any reasoning.",
    "invalid_output:too_many_files": f"List at most {MAX_FILES} created files.",
    "invalid_output:file_too_large": f"Keep each created file under {MAX_FILE_BYTES // 1000} KB.",
    "tell_s1c_": "stdout and stderr start directly with the program's own text, with no greeting, notes or markdown.",
    "empty_output": "This command always prints output, so stdout must not be empty.",
    "exists_mismatch": "This program is installed on this server.",
}
MAX_FILES_AT_LOGIN = 50
NO_STATS = {
    "attempts": 0,
    "model_ms": 0,
    "prompt_tokens": None,
    "completion_tokens": None,
    "rejected_output": None,
}
MAX_FACT_VALUE = 200

# Deterministic answers, used when the model is not asked or not trusted.
# Kept in one place so the team can tune them against a real Debian host.


def not_found(argv0: str) -> tuple[str, str, int]:
    return "", f"-bash: {argv0}: command not found\n", 127


def transient_failure() -> tuple[str, str, int]:
    """For a command already pinned as installed: we must not say "not
    found", so answer with a plausible transient error and do NOT pin it,
    so a later attempt can succeed."""
    return "", "-bash: fork: Resource temporarily unavailable\n", 1


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class GatewayConfig:
    token: str
    deadline_s: float = 15.0
    max_attempts: int = 2
    min_attempt_s: float = 1.0
    per_attacker_per_min: float = 20
    burst: int = 10
    concurrency: int = 2
    busy_wait_s: float = 1.0
    warmup_timeout_s: float = 300.0
    warmup_attempts: int = 5
    escalation: bool = True
    classifiers: str | None = None
    prepare_baits: bool = True
    canary: str = field(default_factory=lambda: "ref-" + secrets.token_hex(6))

    @classmethod
    def from_env(cls) -> GatewayConfig:
        token = os.environ.get("VULNMAZE_GATEWAY_TOKEN", "")
        if len(token) < 16:
            raise RuntimeError("VULNMAZE_GATEWAY_TOKEN must be set (>= 16 chars)")
        env = os.environ.get
        mode = env("VULNMAZE_ESCALATION", "off").strip().lower()
        return cls(
            token=token,
            deadline_s=float(env("VULNMAZE_LLM_DEADLINE_S", "15")),
            max_attempts=int(env("VULNMAZE_LLM_MAX_ATTEMPTS", "2")),
            per_attacker_per_min=float(env("VULNMAZE_LLM_PER_ATTACKER_PER_MIN", "20")),
            burst=int(env("VULNMAZE_LLM_BURST", "10")),
            concurrency=int(env("VULNMAZE_LLM_CONCURRENCY", "2")),
            busy_wait_s=float(env("VULNMAZE_LLM_BUSY_WAIT_S", "1")),
            warmup_timeout_s=float(env("VULNMAZE_LLM_WARMUP_TIMEOUT_S", "300")),
            warmup_attempts=int(env("VULNMAZE_LLM_WARMUP_ATTEMPTS", "5")),
            escalation=mode != "off",
            classifiers=env("VULNMAZE_CLASSIFIERS") if mode == "learned" else None,
            prepare_baits=env("VULNMAZE_BAIT_PREPARE", "on").strip().lower() != "off",
            canary=env("VULNMAZE_LLM_CANARY") or "ref-" + secrets.token_hex(6),
        )


# ---------------------------------------------------------------------------
# Parsing and validation of one model answer
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    exists: bool
    stdout: str
    stderr: str
    exit_code: int
    files: list[tuple[str, str]]
    facts: dict[str, str]


_ERROR_HINT = re.compile(
    r"(?im)^(?:.*: )?(?:error|usage|invalid option|unrecognized option|"
    r"no such file|permission denied|cannot|failed|unknown)"
)


def _extract_json(text: str) -> dict:
    text = sanitize.unwrap_fence(text).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise sanitize.Rejected("invalid_output:not_json") from None
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            raise sanitize.Rejected("invalid_output:not_json") from None
    if not isinstance(data, dict):
        raise sanitize.Rejected("invalid_output:not_object")
    return data


def parse_reply(text: str, mode: str) -> tuple[Candidate, bool]:
    """Returns (candidate, reasoning_was_stripped); an answer that says "command not found" or exits 127 counts as not installed. Raises Rejected."""
    text, stripped = sanitize.strip_reasoning(text)
    if mode == "raw":
        out = sanitize.unwrap_fence(text)
        missing = bool(re.search(r"command not found\s*$", out.strip()))
        code = 0 if not _ERROR_HINT.search(out) else (2 if re.search(r"(?i)usage|invalid option", out) else 1)
        return Candidate(not missing, "" if code else out, out if code else "", code, [], {}), stripped
    data = _extract_json(text)
    try:
        files = [(str(f["path"]), str(f["content"])) for f in (data.get("files_created") or [])]
        facts = {str(f["key"]).strip().lower(): str(f["value"]) for f in (data.get("facts") or [])}
        exit_code = int(data.get("exit_code", 0))
    except (TypeError, KeyError, ValueError):
        raise sanitize.Rejected("invalid_output:bad_fields") from None
    if not 0 <= exit_code <= 255:
        raise sanitize.Rejected("invalid_output:exit_code")
    stdout, stderr = str(data.get("stdout") or ""), str(data.get("stderr") or "")
    written_missing = exit_code == 127 or bool(
        re.search(r"command not found\s*$", (stdout + "\n" + stderr).strip())
    )
    return Candidate(
        exists=bool(data.get("command_exists", True)) and not written_missing,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        files=files,
        facts=facts,
    ), stripped


SECRET_VALUE = re.compile(
    r"""(?i)(\w*(?:pass(?:word|wd)?|pwd|secret|token|authorization|api_?key|access_?key)\w*['"]?\s*(?:=>|=|:|,)\s*['"]?(?:Bearer\s+|Basic\s+)?)([^\s'";,)]{4,})"""
)


def personalise(c: Candidate) -> tuple[Candidate, int]:
    """A copy of prepared bait with each secret value, in its text and facts, swapped for a random one of the same shape; and how many."""
    fresh: dict[str, str] = {}

    def swap(m: re.Match) -> str:
        old = m.group(2)
        if old not in fresh:
            fresh[old] = "".join(
                secrets.choice("abcdefghijklmnopqrstuvwxyz")
                if ch.islower()
                else secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                if ch.isupper()
                else secrets.choice("0123456789")
                if ch.isdigit()
                else ch
                for ch in old
            )
        return m.group(1) + fresh[old]

    stdout = SECRET_VALUE.sub(swap, c.stdout)
    facts = dict(c.facts)
    for old, new in fresh.items():
        facts = {k: v.replace(old, new) for k, v in facts.items()}
    return replace(c, stdout=stdout, facts=facts), len(fresh)


class Validator:
    """All the deterministic checks on one parsed answer."""

    def __init__(self, persona: Persona, prompts: PromptBuilder):
        self.persona_checker = PersonaChecker(persona)
        self.leaks = sanitize.LeakageDetector(
            prompts.leakage_corpus() + [CORRECTION, *HINTS.values()], prompts.canary
        )

    def clean(
        self, c: Candidate, req: EscalationRequest, reasons_nonfatal: list[str] | None = None
    ) -> list[str]:
        """Normalise `c` in place and return rejection reasons (empty = accept).
        Notes that do not reject the answer go to `reasons_nonfatal`."""
        reasons: list[str] = []
        reasons_nonfatal = reasons_nonfatal if reasons_nonfatal is not None else []
        c.stdout = sanitize.normalise(c.stdout, MAX_STDOUT)
        c.stderr = sanitize.normalise(c.stderr, MAX_STDOUT)
        if len(c.files) > MAX_FILES:
            reasons.append("invalid_output:too_many_files")
        files: list[tuple[str, str]] = []
        for path, content in c.files[:MAX_FILES]:
            full = posixpath.normpath(posixpath.join(req.cwd or "/", path))
            full = "/" + full.lstrip("/")
            if sanitize.denylisted_path(full, req.cwd, req.home):
                reasons.append(f"denylist_path:{full}")
            if len(content.encode()) > MAX_FILE_BYTES:
                reasons.append(f"invalid_output:file_too_large:{full}")
            files.append((full, sanitize.normalise(content, MAX_FILE_BYTES)))
        c.files = files
        # Declared facts are shown to the model in later prompts, so they are
        # a channel an attacker could try to plant instructions in: keep them
        # short, single-line and free of leak/instruction patterns.
        for k in list(c.facts):
            v = c.facts[k]
            if not FACT_KEY.match(k) or len(v) > MAX_FACT_VALUE or "\n" in v or self.leaks.check(v):
                c.facts.pop(k)
                reasons_nonfatal.append(f"fact_dropped:{k[:40]}")

        visible = "\n".join([c.stdout, c.stderr, *(f[1] for f in c.files), *c.facts.values()])
        reasons += self.leaks.check(
            visible, [" ".join(req.argv[1:]), *req.argv[1:], *(req.stdin or "").splitlines(), *req.history]
        )
        reasons += sanitize.tells(c.stdout, c.stderr)
        if c.exists:
            reasons += sanitize.empty_output(req.argv, c.stdout, c.stderr, c.exit_code)
        reasons += sanitize.denylisted_content(visible)
        reasons += self.persona_checker.check(visible)
        reasons += self.persona_checker.check_declared(c.facts)
        return reasons


# ---------------------------------------------------------------------------
# Database access (psycopg is synchronous; run in a worker thread)
# ---------------------------------------------------------------------------


def output_key(req: EscalationRequest) -> str:
    stdin_digest = hashlib.sha256((req.stdin or "").encode()).hexdigest()
    raw = json.dumps([req.cwd, req.argv, stdin_digest])
    return "out:" + hashlib.sha256(raw.encode()).hexdigest()[:32]


@dataclass
class Context:
    pinned_output: dict | None
    exists_global: bool | None
    exists_attacker: bool | None
    facts: dict[str, str]


class Db:
    def __init__(self, pool: ConnectionPool, deid: Deidentifier):
        self.pool = pool
        self.deid = deid

    def load(self, req: EscalationRequest, name: str, out_key: str) -> Context:
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            pinned = store.get(req.src_ip, req.username, out_key)
            g = store.get_global(f"cmd-exists:{name}")
            a = store.get(req.src_ip, req.username, f"cmd-exists:{name}")
            facts = {f.fact[4:]: str(f.value) for f in store.list(req.src_ip, req.username, "llm:")}
            files = [f.fact[5:] for f in store.list(req.src_ip, req.username, "file:")]
        if files:
            facts["files created earlier"] = ", ".join(files[:20])
        return Context(
            pinned.value if pinned else None, g.value if g else None, a.value if a else None, facts
        )

    def session_commands(self, session: str) -> list[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT digest->'commands' FROM session_digests WHERE source = 'live' AND session = %s",
                (session,),
            ).fetchone()
        return row[0] if row and row[0] else []

    def file_contents(self, req: EscalationRequest, paths: list[str]) -> list[CreatedFile]:
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            out = []
            for p in paths:
                f = store.get(req.src_ip, req.username, f"file:{p}")
                if f is not None:
                    out.append(CreatedFile(path=p, content=f.value["content"]))
        return out

    def pin_exists(
        self, req: EscalationRequest, name: str, value: bool, created_by: str, attacker_only: bool = False
    ) -> bool:
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            if attacker_only:
                return bool(
                    store.create_if_absent(
                        req.src_ip, req.username, f"cmd-exists:{name}", value, created_by
                    ).value
                )
            return bool(store.create_global_if_absent(f"cmd-exists:{name}", value, created_by).value)

    def facts_contradictions(self, req: EscalationRequest, declared: dict[str, str]) -> list[str]:
        if not declared:
            return []
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            stored = {}
            for k in declared:
                f = store.get(req.src_ip, req.username, f"llm:{k}")
                if f is not None:
                    stored[k] = str(f.value)
        return fact_contradictions(declared, stored)

    def commit(self, req: EscalationRequest, out_key: str, c: Candidate, created_by: str) -> dict:
        """Write files, facts and the output, each create-if-absent. Returns
        the stored output, which may be another request's if it won a race."""
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            for path, content in c.files:
                store.create_if_absent(
                    req.src_ip, req.username, f"file:{path}", {"content": content}, created_by
                )
            for k, v in c.facts.items():
                store.create_if_absent(req.src_ip, req.username, f"llm:{k}", v, created_by)
            value = {
                "stdout": c.stdout,
                "stderr": c.stderr,
                "exit_code": c.exit_code,
                "files": [p for p, _ in c.files],
            }
            return store.create_if_absent(req.src_ip, req.username, out_key, value, created_by).value

    def baited(self, req: EscalationRequest, tactic: str) -> bool:
        with self.pool.connection() as conn:
            return StateStore(conn, self.deid).get(req.src_ip, req.username, f"bait:{tactic}") is not None

    def mark_bait(self, req: EscalationRequest, tactic: str, path: str) -> None:
        with self.pool.connection() as conn:
            StateStore(conn, self.deid).create_if_absent(
                req.src_ip, req.username, f"bait:{tactic}", path, "honeytoken"
            )

    def session_files(self, src_ip: str, username: str) -> list[CreatedFile]:
        with self.pool.connection() as conn:
            facts = StateStore(conn, self.deid).list(src_ip, username, "file:")
        return [CreatedFile(path=f.fact[5:], content=f.value["content"]) for f in facts[:MAX_FILES_AT_LOGIN]]

    def log_call(self, row: dict) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                """INSERT INTO llm_calls (session, attacker_key, username, command, outcome, reasons,
                       attempts, model, latency_ms, model_ms, prompt_tokens, completion_tokens, rejected_output)
                   VALUES (%(session)s, %(attacker_key)s, %(username)s, %(command)s, %(outcome)s, %(reasons)s,
                       %(attempts)s, %(model)s, %(latency_ms)s, %(model_ms)s, %(prompt_tokens)s,
                       %(completion_tokens)s, %(rejected_output)s)""",
                row,
            )


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------


class Gateway:
    def __init__(self, cfg: GatewayConfig, db: Db, backend: Backend, persona: Persona):
        self.cfg = cfg
        self.db = db
        self.backend = backend
        self.persona = persona
        self.prompts = PromptBuilder(persona, cfg.canary, backend.mode)
        self.validator = Validator(persona, self.prompts)
        self.buckets = TokenBuckets(cfg.per_attacker_per_min, cfg.burst)
        self.concurrency = Concurrency(cfg.concurrency)
        self.model_ready = not backend.needs_warmup
        self.warm_task: asyncio.Task | None = None
        self.warm_failed = False
        self.classifiers = joblib.load(cfg.classifiers) if cfg.classifiers else None
        self.baits: dict[str, tuple[str, Candidate]] = {}
        self.bait_task: asyncio.Task | None = None

    def ensure_warming(self) -> None:
        """Load the model in the background, with no deadline, unless it is loaded, loading or failed."""
        if not self.cfg.escalation or self.model_ready or self.warm_failed:
            return
        if self.warm_task is not None and not self.warm_task.done():
            return
        self.warm_task = asyncio.create_task(self._warm())

    async def _warm(self) -> None:
        delay = 5.0
        for attempt in range(1, self.cfg.warmup_attempts + 1):
            t0 = time.perf_counter()
            try:
                timeout = self.cfg.warmup_timeout_s
                await asyncio.wait_for(self.backend.generate([], None, timeout), timeout)
                self.model_ready = True
                log.info("model loaded: %s in %.1f s", self.backend.name, time.perf_counter() - t0)
                self.ensure_baits()
                return
            except (ModelError, TimeoutError) as exc:
                log.warning(
                    "could not load model %s (attempt %d/%d): %r",
                    self.backend.name,
                    attempt,
                    self.cfg.warmup_attempts,
                    exc,
                )
            if attempt < self.cfg.warmup_attempts:
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)
        self.warm_failed = True
        log.error(
            "model %s failed to load after %d attempts; escalated commands get the fallback "
            "until the gateway is restarted",
            self.backend.name,
            self.cfg.warmup_attempts,
        )

    # -- helpers --------------------------------------------------------------

    async def _db(self, fn, *args, **kwargs):
        return await asyncio.to_thread(fn, *args, **kwargs)

    # -- main entry point ------------------------------------------------------

    async def escalate(self, req: EscalationRequest) -> ShellResult:
        t0 = time.perf_counter()
        deadline = t0 + self.cfg.deadline_s
        stats = dict(NO_STATS)
        reasons: list[str] = []
        argv0 = req.argv[0]

        def finish(
            outcome: str, stdout: str, stderr: str, code: int, files: list[CreatedFile] | None = None
        ) -> ShellResult:
            return ShellResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=code,
                files=files or [],
                outcome=outcome,
                reasons=reasons,
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )

        result = await self._escalate(req, argv0, deadline, reasons, stats, finish)
        await self._log(req, result, stats)
        return result

    async def _escalate(self, req, argv0, deadline, reasons, stats, finish) -> ShellResult:
        # 1. route re-check (defence in depth; Cowrie already checked)
        decision = classify_argv(req.argv, cwd=req.cwd, home=req.home)
        if decision.route is not Route.ESCALATE_CANDIDATE:
            reasons.append(f"route:{decision.route.value}:{decision.reason}")
            return finish("refused", *not_found(argv0))
        name = program_name(argv0)
        if name is None:
            reasons.append("bad_command_name")
            return finish("refused", *not_found(argv0))

        # 2. existence
        if name in self.persona.absent:
            reasons.append("persona_absent")
            return finish("not_installed", *not_found(argv0))
        out_key = output_key(req)
        ctx: Context = await self._db(self.db.load, req, name, out_key)
        if ctx.exists_global is False or ctx.exists_attacker is False:
            reasons.append("pinned_absent")
            return finish("not_installed", *not_found(argv0))
        installed = name in self.persona.installed or ctx.exists_global is True

        # 3. output pin
        if ctx.pinned_output is not None:
            p = ctx.pinned_output
            files = await self._db(self.db.file_contents, req, p.get("files", []))
            return finish("pinned", p["stdout"], p["stderr"], p["exit_code"], files)

        if self.classifiers is not None:
            p = await self._predict(req.session, req.history, [shlex.join(req.argv)])
            reasons.append(p["reason"])
            if p["tier"] == "bot" and p["tier_p"] >= 0.9 and p["session_max"] not in HIGH:
                return finish("declined", *not_found(argv0))

        # 4. limits
        if not self.model_ready:
            reasons.append("model_failed" if self.warm_failed else "model_loading")
            self.ensure_warming()
            return await self._fallback(req, name, installed, finish)
        if not self.buckets.allow(self.db.deid.ip(req.src_ip) or req.src_ip):
            reasons.append("rate_limited")
            return await self._fallback(req, name, installed, finish)
        if not await self.concurrency.acquire(
            min(self.cfg.busy_wait_s, max(0.0, deadline - time.perf_counter()))
        ):
            reasons.append("busy")
            return await self._fallback(req, name, installed, finish)

        # 5. generation
        try:
            accepted = await self._generate(req, ctx, installed, deadline, reasons, stats)
        finally:
            self.concurrency.release()
        if accepted is None:
            return await self._fallback(req, name, installed, finish)

        # 6. pinning
        if not installed and not accepted.exists:
            stored = await self._db(self.db.pin_exists, req, name, False, self.backend.name)
            if stored is False:
                return finish("not_installed", *not_found(argv0))
        elif not installed:
            stored = await self._db(self.db.pin_exists, req, name, True, self.backend.name)
            if stored is False:  # another request pinned "absent" first
                return finish("not_installed", *not_found(argv0))
        value = await self._db(self.db.commit, req, out_key, accepted, self.backend.name)
        files = await self._db(self.db.file_contents, req, value.get("files", []))
        return finish("generated", value["stdout"], value["stderr"], value["exit_code"], files)

    async def _predict(self, session: str, history: list[str], current: list[str]) -> dict:
        """Classifier predictions, with their learned:<tier>:<probability>:<max>:<high> reason, on the session's digest commands, the history lines it has not caught up with, and current."""
        commands = await self._db(self.db.session_commands, session)
        ts = datetime.now(UTC).isoformat()
        seen = [i for i, h in enumerate(history) if commands and h == commands[-1].get("input")]
        lagging = history[seen[-1] + 1 :] if seen else history if not commands else []
        commands = [*commands, *({"ts": ts, "input": h} for h in [*lagging, *current])]
        p = await asyncio.to_thread(predict, self.classifiers, commands[-50:])
        return {**p, "reason": f"learned:{p['tier']}:{p['tier_p']}:{p['session_max']}:{p['session_high']}"}

    async def assess(self, req: AssessRequest) -> list[CreatedFile]:
        """Plant the persona's bait for the session's main tactic, once per attacker, when learned mode judges the session worth deceiving."""
        t0 = time.perf_counter()
        if self.classifiers is None or not self.model_ready:
            return []
        try:
            p = await self._predict(req.session, req.history, [])
        except ValueError:
            return []
        tactics = Counter(c["tactic"] for c in p["commands"] if c["tactic"] in self.persona.baits)
        if (p["tier"] not in ("human", "llm_agent") and p["session_max"] not in HIGH) or not tactics:
            return []
        tactic = tactics.most_common(1)[0][0]
        bait = self.persona.baits[tactic]
        bait_req = EscalationRequest(
            session=req.session,
            src_ip=req.src_ip,
            username=req.username,
            argv=["cat", bait["path"]],
            history=req.history,
        )
        if await self._db(self.db.baited, bait_req, tactic):
            return []
        reasons = [p["reason"], f"bait:{tactic}"]
        stats = dict(NO_STATS)
        prepared = self.baits.get(tactic)
        self.ensure_baits()
        if prepared is not None:
            accepted, swapped = personalise(prepared[1])
            reasons += [f"bait_prepared:{prepared[0]}", f"secrets:{swapped}"]
        elif not await self.concurrency.acquire(self.cfg.busy_wait_s):
            return []
        else:
            try:
                accepted = await self._write_bait(bait_req, bait, t0 + self.cfg.deadline_s, reasons, stats)
            finally:
                self.concurrency.release()
        files = []
        if accepted is not None and accepted.stdout.strip():
            accepted.files = [(bait["path"], accepted.stdout)]
            await self._db(self.db.commit, bait_req, output_key(bait_req), accepted, "honeytoken")
            await self._db(self.db.mark_bait, bait_req, tactic, bait["path"])
            files = [CreatedFile(path=bait["path"], content=accepted.stdout)]
        outcome = "bait" if files else "bait_failed"
        await self._log(
            bait_req,
            ShellResult(outcome=outcome, reasons=reasons, latency_ms=int((time.perf_counter() - t0) * 1000)),
            stats,
        )
        return files

    def ensure_baits(self) -> None:
        """In learned mode with preparation on, prepare today's bait files in the background unless they are ready or being prepared."""
        today = datetime.now(UTC).date().isoformat()
        ready = all(self.baits.get(t, ("",))[0] == today for t in self.persona.baits)
        if self.classifiers is None or not self.cfg.prepare_baits or not self.model_ready or ready:
            return
        if self.bait_task is not None and not self.bait_task.done():
            return
        self.bait_task = asyncio.create_task(self._prepare_baits(today))

    async def _prepare_baits(self, day: str) -> None:
        """Have the model write each tactic's bait file for day with fresh random values, keeping the ones that pass every check."""
        for tactic, bait in self.persona.baits.items():
            if self.baits.get(tactic, ("",))[0] == day:
                continue
            t0 = time.perf_counter()
            req = EscalationRequest(
                session=f"bait-{day}", src_ip="192.0.2.1", username="root", argv=["cat", bait["path"]]
            )
            reasons, stats = [f"bait:{tactic}"], dict(NO_STATS)
            await self.concurrency.acquire(3600)
            try:
                accepted = await self._write_bait(
                    req, bait, time.perf_counter() + self.cfg.deadline_s, reasons, stats
                )
            finally:
                self.concurrency.release()
            ok = accepted is not None and bool(accepted.stdout.strip())
            if ok:
                self.baits[tactic] = (day, accepted)
            result = ShellResult(
                outcome="bait_prepared" if ok else "bait_failed",
                reasons=reasons,
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
            await self._log(req, result, stats)

    async def _write_bait(self, req, bait: dict[str, str], deadline: float, reasons: list[str], stats: dict):
        """The model's contents for one bait file, asked as `cat <path>` with the persona's description and a random seed for invented values."""
        ctx = await self._db(self.db.load, req, "cat", output_key(req))
        ctx.facts[f"contents of {bait['path']}"] = bait["contents"]
        ctx.facts["random seed for invented passwords, tokens and hosts"] = secrets.token_hex(4)
        return await self._generate(req, ctx, True, deadline, reasons, stats)

    async def _generate(
        self, req, ctx: Context, installed: bool, deadline: float, reasons: list[str], stats: dict
    ) -> Candidate | None:
        correction: str | None = None
        while stats["attempts"] < self.cfg.max_attempts:
            remaining = deadline - time.perf_counter()
            if remaining < self.cfg.min_attempt_s:
                reasons.append("deadline")
                return None
            stats["attempts"] += 1
            messages = self.prompts.messages(req, ctx.facts, installed, correction)
            schema = MODEL_OUTPUT_SCHEMA if self.backend.mode == "json" else None
            try:
                reply = await asyncio.wait_for(self.backend.generate(messages, schema, remaining), remaining)
            except (ModelError, TimeoutError) as exc:
                reasons.append(f"model_error:{type(exc).__name__}")
                if self.backend.needs_warmup and not await self.backend.healthy():
                    self.model_ready = False
                    self.ensure_warming()
                return None  # a down or slow model will not get better within the deadline
            stats["model_ms"] += reply.model_ms
            stats["prompt_tokens"] = (stats["prompt_tokens"] or 0) + (reply.prompt_tokens or 0)
            stats["completion_tokens"] = (stats["completion_tokens"] or 0) + (reply.completion_tokens or 0)

            try:
                cand, stripped = parse_reply(reply.text, self.backend.mode)
            except sanitize.Rejected as rej:
                reasons.append(rej.reason)
                stats["rejected_output"] = stats["rejected_output"] or reply.text[:4000]
                correction = CORRECTION + self._reminder([rej.reason], ctx)
                continue
            if stripped:
                reasons.append("reasoning_stripped")
            problems = self.validator.clean(cand, req, reasons)
            if installed and not cand.exists:
                problems.append("exists_mismatch")  # persona says it is installed
            if not problems and cand.exists:
                problems = await self._db(self.db.facts_contradictions, req, cand.facts)
            if not problems:
                return cand
            reasons.extend(problems)
            stats["rejected_output"] = stats["rejected_output"] or reply.text[:4000]
            correction = CORRECTION + self._reminder(problems, ctx)
        reasons.append("rejected_all_attempts")
        return None

    def _reminder(self, problems: list[str], ctx: Context) -> str:
        """One hint per rejection group, and the fixed values for contradictions; leaks and the denylist get none."""
        hints = dict.fromkeys(
            hint for problem in problems for key, hint in HINTS.items() if problem.startswith(key)
        )
        reminder = "".join(" " + hint for hint in hints)
        if not any(p.startswith(("contradicts_persona", "contradicts_fact")) for p in problems):
            return reminder
        p = self.persona
        fixed = [f"hostname is {p.hostname}", f"the system is {p.os_pretty}", f"the kernel is {p.kernel}"]
        fixed += [f"{k} is {v}" for k, v in p.facts.items()]
        fixed += [
            f"{k} is {ctx.facts[k]}"
            for k in (x.split(":", 1)[1] for x in problems if x.startswith("contradicts_fact:"))
            if k in ctx.facts
        ]
        return reminder + " These are fixed: " + "; ".join(fixed) + "."

    async def _fallback(self, req, name: str, installed: bool, finish) -> ShellResult:
        if installed:
            return finish("fallback", *transient_failure())
        # Not known to exist: say "not found" and pin that for this attacker
        # only, so they stay consistent without an outage deciding it for
        # everyone.
        await self._db(self.db.pin_exists, req, name, False, "fallback", attacker_only=True)
        return finish("fallback", *not_found(req.argv[0]))

    async def _log(self, req: EscalationRequest, result: ShellResult, stats: dict) -> None:
        redact = lambda s: Deidentifier.redact_text(s, (), req.src_ip)  # noqa: E731
        row = {
            "session": req.session,
            "attacker_key": self.db.deid.ip(req.src_ip),
            "username": self.db.deid.username(req.username),
            "command": redact(" ".join(req.argv))[:2000],
            "outcome": result.outcome,
            "reasons": result.reasons,
            "attempts": stats["attempts"],
            "model": self.backend.name if stats["attempts"] else None,
            "latency_ms": result.latency_ms,
            "model_ms": stats["model_ms"] or None,
            "prompt_tokens": stats["prompt_tokens"],
            "completion_tokens": stats["completion_tokens"],
            "rejected_output": redact(stats["rejected_output"]) if stats["rejected_output"] else None,
        }
        try:
            await self._db(self.db.log_call, row)
        except Exception:
            log.exception("could not log llm call")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

_gateway: Gateway | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _gateway
    cfg = GatewayConfig.from_env()
    deid = Deidentifier.from_env()
    pool = ConnectionPool(
        dsn_from_env(),
        open=True,
        min_size=1,
        max_size=int(os.environ.get("POOL_MAX", "10")),
        kwargs={"autocommit": True},
    )
    with pool.connection() as conn:
        apply_schema(conn)
    _gateway = Gateway(cfg, Db(pool, deid), backend_from_env(), Persona.from_env())
    log.info("gateway ready: backend=%s mode=%s", _gateway.backend.name, _gateway.backend.mode)
    _gateway.ensure_warming()
    yield
    if _gateway.warm_task is not None:
        _gateway.warm_task.cancel()
    pool.close()


app = FastAPI(title="VulnMaze LLM gateway", lifespan=lifespan)


def require_token(authorization: str = Header(default="")) -> None:
    assert _gateway is not None
    if not secrets.compare_digest(authorization, f"Bearer {_gateway.cfg.token}"):
        raise HTTPException(status_code=401, detail="unauthorised")


@app.get("/healthz")
async def healthz(response: Response) -> dict:
    assert _gateway is not None
    if _gateway.warm_failed:
        response.status_code = 503
    return {
        "ok": not _gateway.warm_failed,
        "backend": _gateway.backend.name,
        "model_ready": _gateway.model_ready and await _gateway.backend.healthy(),
        "model_failed": _gateway.warm_failed,
    }


@app.post("/v1/escalate", dependencies=[Depends(require_token)], response_model=ShellResult)
async def escalate(req: EscalationRequest) -> ShellResult:
    assert _gateway is not None
    return await _gateway.escalate(req)


@app.post("/v1/assess", dependencies=[Depends(require_token)], response_model=list[CreatedFile])
async def assess(req: AssessRequest) -> list[CreatedFile]:
    assert _gateway is not None
    return await _gateway.assess(req)


@app.get("/v1/session-files", dependencies=[Depends(require_token)], response_model=list[CreatedFile])
async def session_files(src_ip: str = Query(max_length=64), username: str = Query(max_length=128)):
    assert _gateway is not None
    return await asyncio.to_thread(_gateway.db.session_files, src_ip, username)
