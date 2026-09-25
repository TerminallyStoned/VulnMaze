"""Model backends for the gap-filler.

* ``ollama``  Ollama's native /api/chat. In json mode the output schema is
              passed as `format`, so decoding is constrained to valid JSON.
* ``openai``  Any OpenAI-compatible server (vLLM, llama.cpp server, LM Studio).
              In json mode the schema is passed as `response_format`.

Both are local-only by design: the gateway's network has no route to the
internet, so a hosted API URL would simply fail.

Mode ``raw`` is for models fine-tuned to print terminal output directly (the
approach of Otal and Canbaz [11]); the gateway then parses the text itself.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx


class ModelError(Exception):
    """The model server could not produce an answer (down, timeout, HTTP error)."""


@dataclass
class ModelReply:
    text: str
    model_ms: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class Backend:
    name: str
    mode: str

    async def generate(self, messages: list[dict], schema: dict | None, timeout: float) -> ModelReply:
        raise NotImplementedError

    async def healthy(self) -> bool:
        raise NotImplementedError


@dataclass
class OllamaBackend(Backend):
    url: str
    model: str
    mode: str = "json"
    temperature: float = 0.2
    max_tokens: int = 768
    keep_alive: str = "30m"
    think: bool | None = None   # only sent if set; older Ollama/models reject it

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    async def generate(self, messages, schema, timeout) -> ModelReply:
        body: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if schema is not None:
            body["format"] = schema
        if self.think is not None:
            body["think"] = self.think
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(f"{self.url.rstrip('/')}/api/chat", json=body)
                r.raise_for_status()
                data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ModelError(f"{type(exc).__name__}: {exc}") from exc
        return ModelReply(
            text=(data.get("message") or {}).get("content", ""),
            model_ms=int((time.perf_counter() - started) * 1000),
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
        )

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self.url.rstrip('/')}/api/tags")
                return r.status_code == 200 and any(
                    m.get("name", "").split(":")[0] == self.model.split(":")[0]
                    for m in r.json().get("models", [])
                )
        except (httpx.HTTPError, ValueError):
            return False


@dataclass
class OpenAIBackend(Backend):
    url: str
    model: str
    mode: str = "json"
    temperature: float = 0.2
    max_tokens: int = 768
    api_key: str = "unused"

    @property
    def name(self) -> str:
        return f"openai:{self.model}"

    async def generate(self, messages, schema, timeout) -> ModelReply:
        body: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "shell_result", "schema": schema},
            }
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    f"{self.url.rstrip('/')}/v1/chat/completions",
                    json=body,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                r.raise_for_status()
                data = r.json()
            text = data["choices"][0]["message"]["content"] or ""
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            raise ModelError(f"{type(exc).__name__}: {exc}") from exc
        usage = data.get("usage") or {}
        return ModelReply(
            text=text,
            model_ms=int((time.perf_counter() - started) * 1000),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self.url.rstrip('/')}/v1/models",
                                     headers={"Authorization": f"Bearer {self.api_key}"})
                return r.status_code == 200
        except httpx.HTTPError:
            return False


def backend_from_env() -> Backend:
    kind = os.environ.get("VULNMAZE_LLM_BACKEND", "ollama")
    url = os.environ.get("VULNMAZE_LLM_URL", "http://ollama:11434")
    model = os.environ.get("VULNMAZE_LLM_MODEL", "llama3.1:8b")
    mode = os.environ.get("VULNMAZE_LLM_MODE", "json")
    if mode not in ("json", "raw"):
        raise ValueError("VULNMAZE_LLM_MODE must be json or raw")
    temperature = float(os.environ.get("VULNMAZE_LLM_TEMPERATURE", "0.2"))
    max_tokens = int(os.environ.get("VULNMAZE_LLM_MAX_TOKENS", "768"))
    if kind == "ollama":
        think_env = os.environ.get("VULNMAZE_LLM_THINK")
        think = None if think_env is None else think_env.lower() in ("1", "true", "yes")
        return OllamaBackend(url, model, mode, temperature, max_tokens, think=think)
    if kind == "openai":
        return OpenAIBackend(url, model, mode, temperature, max_tokens,
                             api_key=os.environ.get("VULNMAZE_LLM_API_KEY", "unused"))
    raise ValueError(f"unknown VULNMAZE_LLM_BACKEND {kind!r}")
