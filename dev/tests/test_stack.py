"""Checks against the running compose stack.

    cp infra/.env.example infra/.env   # fill in the secrets
    docker compose -f infra/docker-compose.yml --profile probe up -d --build --wait
    VULNMAZE_STACK=1 pytest tests/v0_1/test_stack.py -v

Each probe runs *inside* a container with `docker compose exec`, so it
tests what that container can really reach.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.stack

ROOT = Path(__file__).parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "infra/docker-compose.yml"), "--profile", "probe"]

PROBE = """
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    socket.create_connection((host, port), timeout=4).close()
    print("OPEN")
except Exception as e:
    print("BLOCKED", type(e).__name__)
"""

DNS_PROBE = """
import socket
try:
    socket.getaddrinfo("example.com", 443)
    print("RESOLVED")
except Exception as e:
    print("BLOCKED", type(e).__name__)
"""


def exec_py(service: str, code: str, *args: str) -> str:
    out = subprocess.run(COMPOSE + ["exec", "-T", service, "python", "-c", code, *args],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


def test_all_services_healthy():
    out = subprocess.run(COMPOSE + ["ps", "--format", "json"], capture_output=True, text=True, check=True).stdout
    services = [json.loads(line) for line in out.splitlines() if line.strip()]
    if len(services) == 1 and isinstance(services[0], list):     # older compose prints one array
        services = services[0]
    states = {s["Service"]: (s["State"], s.get("Health", "")) for s in services}
    for name in ("edge", "cowrie", "postgres", "ingester", "llm-gateway", "ollama"):
        assert states[name][0] == "running", states
        assert states[name][1] in ("healthy", ""), states


@pytest.mark.parametrize("service", ["cowrie", "probe", "ingester"])
@pytest.mark.parametrize("target", [("1.1.1.1", "443"), ("8.8.8.8", "53")])
def test_no_internet_egress(service, target):
    assert exec_py(service, PROBE, *target).startswith("BLOCKED")


@pytest.mark.parametrize("service", ["cowrie", "probe"])
def test_no_dns(service):
    assert exec_py(service, DNS_PROBE).startswith("BLOCKED")


@pytest.mark.parametrize("target", [("postgres", "5432"), ("ingester", "80")])
def test_honeypot_cannot_reach_backend(target):
    assert exec_py("cowrie", PROBE, *target).startswith("BLOCKED")


def test_harness_reaches_only_the_honeypot():
    assert exec_py("probe", PROBE, "edge", "2222") == "OPEN"
    for target in (("postgres", "5432"), ("1.1.1.1", "443")):
        assert exec_py("probe", PROBE, *target).startswith("BLOCKED")


def test_ssh_banner_on_published_port():
    import socket

    host, port = os.environ.get("SSH_PUBLISH", "127.0.0.1:2222").rsplit(":", 1)
    with socket.create_connection((host if host != "0.0.0.0" else "127.0.0.1", int(port)), timeout=5) as s:
        assert s.recv(64).startswith(b"SSH-2.0-OpenSSH_9.2p1")


def test_state_survives_container_restart():
    store = """
import psycopg
from vulnmaze.common.deid import Deidentifier
from vulnmaze.db import dsn_from_env
from vulnmaze.state.store import StateStore
with psycopg.connect(dsn_from_env(), autocommit=True) as conn:
    store = StateStore(conn, Deidentifier.from_env())
    print(store.CALL.value)
"""
    put = store.replace("CALL", 'create_if_absent("203.0.113.7", "root", "persist-check", "persist-check", "test")')
    assert exec_py("llm-gateway", put) == "persist-check"
    subprocess.run(COMPOSE + ["restart", "postgres", "llm-gateway"], check=True, timeout=120)
    time.sleep(5)
    subprocess.run(COMPOSE + ["up", "-d", "--wait"], check=True, timeout=120)
    assert exec_py("llm-gateway", store.replace("CALL", 'get("203.0.113.7", "root", "persist-check")')) == "persist-check"
