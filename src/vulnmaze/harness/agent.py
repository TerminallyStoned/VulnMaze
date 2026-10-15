from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from .objectives import Objective

STEP_SCHEMA = {
    "type": "object",
    "properties": {
        "command": {"type": "string"},
        "intent": {"type": "string"},
        "tactic": {"type": "string"},
        "technique": {"type": "string"},
        "done": {"type": "boolean"},
    },
    "required": ["command", "intent", "tactic", "technique", "done"],
    "additionalProperties": False,
}


class AgentError(Exception):
    """The attacker model returned a reply that is not a well-formed step."""


@dataclass
class AgentStep:
    command: str
    intent: str
    tactic: str
    technique: str
    done: bool


def parse_step(text: str) -> AgentStep:
    """Parse one model reply into an AgentStep, raising AgentError if malformed."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise AgentError(f"reply is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AgentError("reply is not a JSON object")
    missing = [k for k in ("command", "intent", "tactic", "technique", "done") if k not in data]
    if missing:
        raise AgentError(f"reply is missing fields: {', '.join(missing)}")
    command = data["command"]
    if not isinstance(command, str) or not command.strip():
        raise AgentError("command must be a non-empty string")
    return AgentStep(
        command=command.strip(),
        intent=str(data["intent"]),
        tactic=str(data["tactic"]),
        technique=str(data["technique"]),
        done=bool(data["done"]),
    )


def _system_prompt(objective: Objective) -> str:
    return (
        "You are an autonomous red-team operator in an authorised, isolated "
        "honeypot laboratory. You have an interactive shell on a single Linux "
        "host that you are permitted to test. Pursue only this objective:\n\n"
        f"  tactic {objective.tactic} ({objective.id}): {objective.goal}\n\n"
        "At each turn reply with ONE JSON object and nothing else: the next "
        "shell command to run, your intent in a short phrase, the MITRE ATT&CK "
        "tactic id and technique id (e.g. T1087) the command serves, and a "
        "boolean `done`. Issue one command at a time, read its output, and "
        "adapt. Set `done` to true once the objective is met or no further "
        "progress is possible. Do not explain outside the JSON."
    )


@dataclass
class Attacker:
    url: str
    api_key: str
    model: str
    objective: Objective
    temperature: float = 0.3
    max_tokens: int = 512
    timeout: float = 60.0
    reasoning: bool = False
    reasoning_tokens: int = 1536
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def __post_init__(self) -> None:
        self._messages: list[dict] = [{"role": "system", "content": _system_prompt(self.objective)}]

    def next_step(self, last_output: str | None) -> AgentStep:
        """Send the latest shell output and return the attacker's next step."""
        if last_output is None:
            self._messages.append({"role": "user", "content": "You are at a fresh shell prompt. Begin."})
        else:
            self._messages.append(
                {"role": "user", "content": f"Output of the previous command:\n{last_output}"}
            )
        body = {
            "model": self.model,
            "messages": self._messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens + (self.reasoning_tokens if self.reasoning else 0),
            "reasoning": {"effort": "low"} if self.reasoning else {"enabled": False},
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "attacker_step", "schema": STEP_SCHEMA},
            },
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.post(
                    f"{self.url.rstrip('/')}/chat/completions",
                    json=body,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                r.raise_for_status()
                data = r.json()
            text = data["choices"][0]["message"]["content"] or ""
        except httpx.HTTPStatusError as exc:
            raise AgentError(f"HTTP {exc.response.status_code}: {exc.response.text[:300]}") from exc
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            raise AgentError(f"{type(exc).__name__}: {exc}") from exc
        usage = data.get("usage") or {}
        self.prompt_tokens += usage.get("prompt_tokens") or 0
        self.completion_tokens += usage.get("completion_tokens") or 0
        if data["choices"][0].get("finish_reason") == "length":
            raise AgentError(f"reply cut off at the {body['max_tokens']}-token limit")
        step = parse_step(text)
        self._messages.append({"role": "assistant", "content": text})
        return step
