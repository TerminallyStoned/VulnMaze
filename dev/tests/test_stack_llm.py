"""Isolation probes against the running compose stack, with the LLM services up.

    docker compose -f infra/docker-compose.yml --profile probe up -d --build --wait
    VULNMAZE_STACK=1 pytest tests/v0_6/test_stack_llm.py -v
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.stack

ROOT = Path(__file__).parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "infra/docker-compose.yml"), "--profile", "probe"]

PROBE = """
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=4).close()
    print("OPEN")
except Exception as e:
    print("BLOCKED", type(e).__name__)
"""


def exec_py(service: str, code: str, *args: str) -> str:
    return subprocess.run(COMPOSE + ["exec", "-T", service, "python", "-c", code, *args],
                          capture_output=True, text=True, timeout=60).stdout.strip()


def exec_sh(service: str, script: str) -> str:
    """For the ollama image, which has bash but no python."""
    return subprocess.run(COMPOSE + ["exec", "-T", service, "bash", "-c", script],
                          capture_output=True, text=True, timeout=60).stdout.strip()


def test_honeypot_reaches_gateway_api():
    assert exec_py("cowrie", PROBE, "llm-gateway", "8090") == "OPEN"


@pytest.mark.parametrize("target", [("ollama", "11434"), ("postgres", "5432")])
def test_honeypot_cannot_reach_model_or_database(target):
    assert exec_py("cowrie", PROBE, *target).startswith("BLOCKED")


def test_harness_cannot_reach_gateway():
    assert exec_py("probe", PROBE, "llm-gateway", "8090").startswith("BLOCKED")


@pytest.mark.parametrize("target", [("1.1.1.1", "443"), ("8.8.8.8", "53")])
def test_gateway_has_no_internet(target):
    assert exec_py("llm-gateway", PROBE, *target).startswith("BLOCKED")


def test_model_server_has_no_internet():
    out = exec_sh("ollama", "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && echo OPEN || echo BLOCKED")
    assert out.endswith("BLOCKED")


def test_gateway_health():
    out = exec_py("llm-gateway", "import urllib.request; print(urllib.request.urlopen("
                                 "'http://127.0.0.1:8090/healthz', timeout=5).read().decode())")
    health = json.loads(out)
    assert health["ok"] is True
    # model_ready is False until `--profile models run --rm ollama-pull` has run.


def test_gateway_rejects_requests_without_token():
    code = ("import urllib.request, urllib.error\n"
            "try:\n"
            "    urllib.request.urlopen(urllib.request.Request('http://llm-gateway:8090/v1/escalate', "
            "data=b'{}', method='POST'), timeout=5)\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(e.code)\n")
    assert exec_py("cowrie", code) == "401"
