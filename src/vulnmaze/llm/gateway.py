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
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from psycopg_pool import ConnectionPool

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
    CreatedFile,
    EscalationRequest,
    ShellResult,
)
from vulnmaze.router import classify_argv
from vulnmaze.router.router import Route
from vulnmaze.state.store import StateStore

log = logging.getLogger("vulnmaze.llm")

BIN_DIRS = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}
COMMAND_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
CORRECTION = "Your previous answer was not accepted. Answer again, following every rule above exactly."
MAX_FILES_AT_LOGIN = 50
MAX_FACT_VALUE = 200

# Deterministic answers, used when the model is not asked or not trusted.
# Kept in one place so the team can tune them against a real Debian host.


def not_found(argv0: str) -> tuple[str, str, int]:
    return "", f"-bash: {argv0}: command not found\n", 127


def transient_failure(argv0: str) -> tuple[str, str, int]:
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
    deadline_s: float = 8.0
    max_attempts: int = 2
    min_attempt_s: float = 1.0
    per_attacker_per_min: float = 20
    burst: int = 10
    concurrency: int = 2
    busy_wait_s: float = 1.0
    canary: str = field(default_factory=lambda: "ref-" + secrets.token_hex(6))

    @classmethod
    def from_env(cls) -> GatewayConfig:
        token = os.environ.get("VULNMAZE_GATEWAY_TOKEN", "")
        if len(token) < 16:
            raise RuntimeError("VULNMAZE_GATEWAY_TOKEN must be set (>= 16 chars)")
        env = os.environ.get
        return cls(
            token=token,
            deadline_s=float(env("VULNMAZE_LLM_DEADLINE_S", "8")),
            max_attempts=int(env("VULNMAZE_LLM_MAX_ATTEMPTS", "2")),
            per_attacker_per_min=float(env("VULNMAZE_LLM_PER_ATTACKER_PER_MIN", "20")),
            burst=int(env("VULNMAZE_LLM_BURST", "10")),
            concurrency=int(env("VULNMAZE_LLM_CONCURRENCY", "2")),
            busy_wait_s=float(env("VULNMAZE_LLM_BUSY_WAIT_S", "1")),
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


_ERROR_HINT = re.compile(r"(?im)^(?:.*: )?(?:error|usage|invalid option|unrecognized option|"
                         r"no such file|permission denied|cannot|failed|unknown)")


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
    """Returns (candidate, reasoning_was_stripped). Raises Rejected."""
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
    return Candidate(
        exists=bool(data.get("command_exists", True)),
        stdout=str(data.get("stdout") or ""),
        stderr=str(data.get("stderr") or ""),
        exit_code=exit_code,
        files=files,
        facts=facts,
    ), stripped


class Validator:
    """All the deterministic checks on one parsed answer."""

    def __init__(self, persona: Persona, prompts: PromptBuilder):
        self.persona_checker = PersonaChecker(persona)
        self.leaks = sanitize.LeakageDetector(prompts.leakage_corpus() + [CORRECTION], prompts.canary)

    def clean(self, c: Candidate, req: EscalationRequest, reasons_nonfatal: list[str] | None = None) -> list[str]:
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
        reasons += self.leaks.check(visible)
        reasons += sanitize.tells(c.stdout, c.stderr)
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
        return Context(pinned.value if pinned else None, g.value if g else None, a.value if a else None, facts)

    def file_contents(self, req: EscalationRequest, paths: list[str]) -> list[CreatedFile]:
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            out = []
            for p in paths:
                f = store.get(req.src_ip, req.username, f"file:{p}")
                if f is not None:
                    out.append(CreatedFile(path=p, content=f.value["content"]))
        return out

    def pin_exists(self, req: EscalationRequest, name: str, value: bool, created_by: str,
                   attacker_only: bool = False) -> bool:
        with self.pool.connection() as conn:
            store = StateStore(conn, self.deid)
            if attacker_only:
                return bool(store.create_if_absent(req.src_ip, req.username, f"cmd-exists:{name}",
                                                   value, created_by).value)
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
                store.create_if_absent(req.src_ip, req.username, f"file:{path}", {"content": content}, created_by)
            for k, v in c.facts.items():
                store.create_if_absent(req.src_ip, req.username, f"llm:{k}", v, created_by)
            value = {"stdout": c.stdout, "stderr": c.stderr, "exit_code": c.exit_code,
                     "files": [p for p, _ in c.files]}
            return store.create_if_absent(req.src_ip, req.username, out_key, value, created_by).value

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

    # -- helpers --------------------------------------------------------------

    def _command_name(self, argv0: str) -> str | None:
        if "/" in argv0:
            if posixpath.dirname(posixpath.normpath(argv0)) not in BIN_DIRS:
                return None
            argv0 = posixpath.basename(argv0)
        return argv0 if COMMAND_NAME.match(argv0) else None

    async def _db(self, fn, *args, **kwargs):
        return await asyncio.to_thread(fn, *args, **kwargs)

    # -- main entry point ------------------------------------------------------

    async def escalate(self, req: EscalationRequest) -> ShellResult:
        t0 = time.perf_counter()
        deadline = t0 + self.cfg.deadline_s
        stats = {"attempts": 0, "model_ms": 0, "prompt_tokens": None, "completion_tokens": None,
                 "rejected_output": None}
        reasons: list[str] = []
        argv0 = req.argv[0]

        def finish(outcome: str, stdout: str, stderr: str, code: int,
                   files: list[CreatedFile] | None = None) -> ShellResult:
            return ShellResult(stdout=stdout, stderr=stderr, exit_code=code, files=files or [],
                               outcome=outcome, reasons=reasons,
                               latency_ms=int((time.perf_counter() - t0) * 1000))

        result = await self._escalate(req, argv0, deadline, reasons, stats, finish)
        await self._log(req, result, stats)
        return result

    async def _escalate(self, req, argv0, deadline, reasons, stats, finish) -> ShellResult:
        # 1. route re-check (defence in depth; Cowrie already checked)
        decision = classify_argv(req.argv, cwd=req.cwd, home=req.home)
        if decision.route is not Route.ESCALATE_CANDIDATE:
            reasons.append(f"route:{decision.route.value}:{decision.reason}")
            return finish("refused", *not_found(argv0))
        name = self._command_name(argv0)
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

        # 4. limits
        if not self.buckets.allow(self.db.deid.ip(req.src_ip) or req.src_ip):
            reasons.append("rate_limited")
            return await self._fallback(req, name, installed, finish)
        if not await self.concurrency.acquire(min(self.cfg.busy_wait_s, max(0.0, deadline - time.perf_counter()))):
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
            if stored is False:   # another request pinned "absent" first
                return finish("not_installed", *not_found(argv0))
        value = await self._db(self.db.commit, req, out_key, accepted, self.backend.name)
        files = await self._db(self.db.file_contents, req, value.get("files", []))
        return finish("generated", value["stdout"], value["stderr"], value["exit_code"], files)

    async def _generate(self, req, ctx: Context, installed: bool, deadline: float,
                        reasons: list[str], stats: dict) -> Candidate | None:
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
                return None      # a down or slow model will not get better within the deadline
            stats["model_ms"] += reply.model_ms
            stats["prompt_tokens"] = (stats["prompt_tokens"] or 0) + (reply.prompt_tokens or 0)
            stats["completion_tokens"] = (stats["completion_tokens"] or 0) + (reply.completion_tokens or 0)

            try:
                cand, stripped = parse_reply(reply.text, self.backend.mode)
            except sanitize.Rejected as rej:
                reasons.append(rej.reason)
                stats["rejected_output"] = stats["rejected_output"] or reply.text[:4000]
                correction = CORRECTION
                continue
            if stripped:
                reasons.append("reasoning_stripped")
            problems = self.validator.clean(cand, req, reasons)
            if installed and not cand.exists:
                problems.append("exists_mismatch")   # persona says it is installed
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
        """For contradictions, restate the fixed values (never which detector fired)."""
        if not any(p.startswith(("contradicts_persona", "contradicts_fact")) for p in problems):
            return ""
        p = self.persona
        fixed = [f"hostname is {p.hostname}", f"the system is {p.os_pretty}", f"the kernel is {p.kernel}"]
        fixed += [f"{k} is {v}" for k, v in p.facts.items()]
        fixed += [f"{k} is {ctx.facts[k]}" for k in (x.split(":", 1)[1] for x in problems
                                                     if x.startswith("contradicts_fact:")) if k in ctx.facts]
        return " These are fixed: " + "; ".join(fixed) + "."

    async def _fallback(self, req, name: str, installed: bool, finish) -> ShellResult:
        if installed:
            return finish("fallback", *transient_failure(req.argv[0]))
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
            "username": req.username,
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
    pool = ConnectionPool(dsn_from_env(), open=True, min_size=1,
                          max_size=int(os.environ.get("POOL_MAX", "10")), kwargs={"autocommit": True})
    with pool.connection() as conn:
        apply_schema(conn)
    _gateway = Gateway(cfg, Db(pool, deid), backend_from_env(), Persona.from_env())
    log.info("gateway ready: backend=%s mode=%s", _gateway.backend.name, _gateway.backend.mode)
    yield
    pool.close()


app = FastAPI(title="VulnMaze LLM gateway", lifespan=lifespan)


def require_token(authorization: str = Header(default="")) -> None:
    assert _gateway is not None
    if not secrets.compare_digest(authorization, f"Bearer {_gateway.cfg.token}"):
        raise HTTPException(status_code=401, detail="unauthorised")


@app.get("/healthz")
async def healthz() -> dict:
    assert _gateway is not None
    return {"ok": True, "backend": _gateway.backend.name, "model_ready": await _gateway.backend.healthy()}


@app.post("/v1/escalate", dependencies=[Depends(require_token)], response_model=ShellResult)
async def escalate(req: EscalationRequest) -> ShellResult:
    assert _gateway is not None
    return await _gateway.escalate(req)


@app.get("/v1/session-files", dependencies=[Depends(require_token)], response_model=list[CreatedFile])
async def session_files(src_ip: str = Query(max_length=64), username: str = Query(max_length=128)):
    assert _gateway is not None
    return await asyncio.to_thread(_gateway.db.session_files, src_ip, username)
