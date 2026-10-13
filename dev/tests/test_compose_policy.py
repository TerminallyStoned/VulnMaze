"""Static checks on infra/docker-compose.yml: the network policy that contains Cowrie.

These run everywhere (no Docker needed) and stop someone from quietly
weakening the isolation in a pull request.
"""

from __future__ import annotations

import configparser
from pathlib import Path

import pytest
import yaml

COMPOSE = Path(__file__).parents[2] / "infra/docker-compose.yml"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


def _nets(svc):
    n = svc.get("networks", [])
    return set(n) if isinstance(n, list) else set(n.keys())


def test_internal_networks_have_no_gateway(compose):
    nets = compose["networks"]
    assert nets["dmz"]["internal"] is True
    assert nets["backend"]["internal"] is True


def test_honeypot_networks(compose):
    # v0.1: dmz only. v0.6: plus hpgw, which it shares with the LLM gateway alone.
    assert _nets(compose["services"]["cowrie"]) == {"dmz", "hpgw"}


def test_only_edge_publishes_ports(compose):
    for name, svc in compose["services"].items():
        if name != "edge":
            assert "ports" not in svc, f"{name} must not publish ports"


def test_no_service_bridges_dmz_and_backend(compose):
    for name, svc in compose["services"].items():
        assert not {"dmz", "backend"} <= _nets(svc), f"{name} joins both dmz and backend"


def test_edge_is_the_only_service_on_the_outside_network(compose):
    on_edge = [n for n, s in compose["services"].items() if "edge" in _nets(s)]
    assert on_edge == ["edge"]


@pytest.mark.parametrize("name", ["cowrie", "edge", "ingester", "state-api", "llm-gateway", "ollama"])
def test_hardening(compose, name):
    svc = compose["services"][name]
    assert svc.get("read_only") is True
    assert "ALL" in svc.get("cap_drop", [])
    assert "no-new-privileges:true" in svc.get("security_opt", [])


def test_honeypot_resource_limits(compose):
    svc = compose["services"]["cowrie"]
    assert svc.get("mem_limit") and svc.get("pids_limit")


def test_ingester_reads_logs_read_only(compose):
    vols = compose["services"]["ingester"]["volumes"]
    assert any(v.startswith("cowrie-logs:") and v.endswith(":ro") for v in vols)


def test_harness_only_reaches_dmz(compose):
    assert _nets(compose["services"]["probe"]) == {"dmz"}


def test_secrets_are_required_not_defaulted(compose):
    text = COMPOSE.read_text()
    for var in ("POSTGRES_PASSWORD", "VULNMAZE_DEID_KEY", "VULNMAZE_STATE_TOKEN", "VULNMAZE_GATEWAY_TOKEN"):
        assert f"${{{var}:?" in text, f"{var} must fail if unset"


def test_cowrie_only_accepts_proxied_connections():
    cfg = (Path(__file__).parents[2] / "infra/honeypot/cowrie.cfg").read_text()
    assert "listen_endpoints = haproxy:tcp:2222" in cfg
    assert "hostname = svr04" not in cfg          # Cowrie's well-known default


def _fits_human_sessions(idle, session):
    """True when the idle and per-session limits allow a 10-minute human session and stay within HAProxy's 1 h."""
    return 600 <= idle <= session <= 3600


def test_cowrie_timeouts_fit_human_sessions():
    """Cowrie's idle and per-session timeouts leave room for a human session (#41)."""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(Path(__file__).parents[2] / "infra/honeypot/cowrie.cfg")
    assert _fits_human_sessions(cfg.getint("honeypot", "idle_timeout"), cfg.getint("honeypot", "interactive_timeout"))


@pytest.mark.parametrize("idle,session", [(180, 300), (900, 7200), (1800, 900)])
def test_short_or_inconsistent_timeouts_are_rejected(idle, session):
    """Cowrie's defaults, a session cap above HAProxy's 1 h, or an idle limit above the session cap all fail."""
    assert not _fits_human_sessions(idle, session)
