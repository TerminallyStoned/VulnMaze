"""Request/response shapes between Cowrie, the gateway and the model."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

MAX_STDOUT = 16_000
MAX_FILE_BYTES = 64_000
MAX_FILES = 3
MAX_FACTS = 5

Outcome = Literal["generated", "pinned", "not_installed", "refused", "fallback"]


class EscalationRequest(BaseModel):
    """What Cowrie sends for one pipeline stage it cannot answer."""

    session: str = Field(max_length=64)
    src_ip: str = Field(max_length=64)
    username: str = Field(max_length=128)
    cwd: str = Field(default="/root", max_length=1024)
    home: str = Field(default="/root", max_length=1024)
    argv: list[str] = Field(min_length=1, max_length=256)
    stdin: str | None = Field(default=None, max_length=16_384)
    history: list[str] = Field(default_factory=list, max_length=50)


class CreatedFile(BaseModel):
    path: str
    content: str


class ShellResult(BaseModel):
    """What the gateway returns to Cowrie. Always well-formed, whatever the
    model did: on any failure it carries a deterministic fallback."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    files: list[CreatedFile] = Field(default_factory=list)
    outcome: Outcome
    reasons: list[str] = Field(default_factory=list)
    latency_ms: int = 0


# JSON schema the model must follow in `json` mode. Passed to Ollama as
# `format` and to OpenAI-compatible servers as `response_format`, so the
# server constrains decoding to it.
MODEL_OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "command_exists": {"type": "boolean"},
        "stdout": {"type": "string"},
        "stderr": {"type": "string"},
        "exit_code": {"type": "integer", "minimum": 0, "maximum": 255},
        "files_created": {
            "type": "array",
            "maxItems": MAX_FILES,
            "items": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
            },
        },
        "facts": {
            "type": "array",
            "maxItems": MAX_FACTS,
            "items": {
                "type": "object",
                "properties": {"key": {"type": "string"}, "value": {"type": "string"}},
                "required": ["key", "value"],
            },
        },
    },
    "required": ["command_exists", "stdout", "stderr", "exit_code"],
}
