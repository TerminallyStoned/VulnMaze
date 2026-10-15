from __future__ import annotations

import io
import json

import httpx
import pytest

from vulnmaze.harness import agent, runner
from vulnmaze.harness.agent import AgentError, AgentStep, Attacker, parse_step
from vulnmaze.harness.objectives import OBJECTIVES, load_objectives
from vulnmaze.harness.runner import ContainmentError, check_target, run_session


class _FakeClient:
    def close(self) -> None:
        pass


class _FakeChan:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def sendall(self, data: str) -> None:
        self.sent.append(data)


class _ScriptedAttacker:
    model = "fake/model"
    prompt_tokens = 11
    completion_tokens = 7

    def __init__(self, steps: list[AgentStep]) -> None:
        self._steps = steps
        self.seen: list[str | None] = []

    def next_step(self, last_output):
        self.seen.append(last_output)
        return self._steps.pop(0)


@pytest.mark.parametrize(
    "command, done",
    [("id", True), ("uname -a", True)],
)
def test_valid_step_drives_command(monkeypatch, command, done):
    """A parsed step sends its command to the shell and logs a well-formed record."""
    chan = _FakeChan()
    monkeypatch.setattr(runner, "_open_shell", lambda *a, **k: (_FakeClient(), chan, "127.0.0.1", 54321))
    monkeypatch.setattr(runner, "_read_until_idle", lambda *a, **k: "uid=0(root)\n")
    step = AgentStep(command=command, intent="probe", tactic="TA0007", technique="T1082", done=done)
    attacker = _ScriptedAttacker([step])
    sink = io.StringIO()

    summary = run_session(
        OBJECTIVES["discovery"],
        attacker,
        sink,
        host="127.0.0.1",
        port=2222,
        username="root",
        password="hunter2x",
        max_steps=5,
        read_timeout=1.0,
    )

    assert chan.sent == [command + "\n"]
    record = json.loads(sink.getvalue().splitlines()[-1])
    assert record["command"] == command
    assert record["tier"] == "llm_agent"
    assert record["output_len"] == len("uid=0(root)\n")
    assert summary["steps"] == 1


@pytest.mark.parametrize(
    "body",
    [
        "- id: discovery\n  tactic: TA0007\n  goal: Fingerprint the host.\n",
        "- {id: a, tactic: TA0001, goal: g1}\n- {id: b, tactic: TA0002, goal: g2}\n",
    ],
)
def test_load_objectives_valid(tmp_path, body):
    """A well-formed YAML objective set loads into Objective records keyed by id."""
    path = tmp_path / "objectives.yml"
    path.write_text(body, encoding="utf-8")
    catalog = load_objectives(path)
    first = next(iter(catalog.values()))
    assert all(k == v.id for k, v in catalog.items())
    assert first.tactic.startswith("TA")


@pytest.mark.parametrize(
    "body",
    [
        "{}\n",
        "- id: discovery\n  tactic: TA0007\n",
        "- id: Bad_Id\n  tactic: TA0007\n  goal: g\n",
        "- id: discovery\n  tactic: discovery\n  goal: g\n",
        "- id: dup\n  tactic: TA0001\n  goal: g\n- id: dup\n  tactic: TA0002\n  goal: g\n",
    ],
)
def test_load_objectives_invalid(tmp_path, body):
    """Malformed structure, bad id/tactic or a duplicate id is rejected."""
    path = tmp_path / "objectives.yml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        load_objectives(path)


@pytest.mark.parametrize(
    "kind, payload",
    [
        ("reply", "not json at all"),
        ("reply", '{"command": "", "intent": "x", "tactic": "t", "technique": "y", "done": false}'),
        ("reply", '{"intent": "x", "tactic": "t", "technique": "y", "done": false}'),
        ("target", ("8.8.8.8", 2222)),
        ("target", ("127.0.0.1", 22)),
    ],
)
def test_invalid_input_rejected(kind, payload):
    """Malformed agent replies raise AgentError and out-of-scope targets are refused."""
    if kind == "reply":
        with pytest.raises(AgentError):
            parse_step(payload)
    else:
        with pytest.raises(ContainmentError):
            check_target(*payload)


def _openrouter(monkeypatch, status, payload):
    """Answer every chat completion with status and payload, keeping the request bodies sent."""
    bodies = []

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, json, headers):
            bodies.append(json)
            return httpx.Response(status, json=payload, request=httpx.Request("POST", url))

    monkeypatch.setattr(agent.httpx, "Client", Client)
    return bodies


STEP = {"command": "id", "intent": "probe", "tactic": "TA0007", "technique": "T1082", "done": False}


@pytest.mark.parametrize("reasoning, sent, limit", [(False, {"enabled": False}, 512), (True, {"effort": "low"}, 2048)])
def test_attacker_turns_reasoning_off_unless_asked(monkeypatch, reasoning, sent, limit):
    """Reasoning is off by default and on at low effort with --reasoning, for models that cannot turn it off, with room for it in the reply limit."""
    bodies = _openrouter(monkeypatch, 200, {"choices": [{"message": {"content": json.dumps(STEP)}}]})
    attacker = Attacker("https://openrouter.ai/api/v1", "k", "m", OBJECTIVES["discovery"], reasoning=reasoning)
    assert attacker.next_step(None).command == "id"
    assert bodies[0]["reasoning"] == sent and bodies[0]["max_tokens"] == limit


@pytest.mark.parametrize("reasoning, limit", [(False, 512), (True, 2048)])
def test_reply_cut_off_at_the_limit_raises_saying_so(monkeypatch, reasoning, limit):
    """A reply the provider ended at the token limit raises AgentError naming the limit, not a JSON error."""
    content = json.dumps(STEP)[:20]
    _openrouter(monkeypatch, 200, {"choices": [{"message": {"content": content}, "finish_reason": "length"}]})
    attacker = Attacker("https://openrouter.ai/api/v1", "k", "m", OBJECTIVES["discovery"], reasoning=reasoning)
    with pytest.raises(AgentError, match=f"cut off at the {limit}-token limit"):
        attacker.next_step(None)


@pytest.mark.parametrize(
    "status, message",
    [(400, "Reasoning is mandatory for this endpoint and cannot be disabled."), (404, "No endpoints found")],
)
def test_rejected_request_raises_with_the_providers_message(monkeypatch, status, message):
    """A rejected request raises AgentError carrying the status and the provider's explanation."""
    _openrouter(monkeypatch, status, {"error": {"message": message, "code": status}})
    attacker = Attacker("https://openrouter.ai/api/v1", "k", "m", OBJECTIVES["discovery"])
    with pytest.raises(AgentError, match=f"HTTP {status}: .*{message}"):
        attacker.next_step(None)
