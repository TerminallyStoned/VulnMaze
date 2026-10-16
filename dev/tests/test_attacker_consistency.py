"""Consistency seen by an attacker across sessions."""

from __future__ import annotations

import pytest


@pytest.mark.cowrie
def test_same_output_after_reconnect(cowrie_server):
    """What the attacker sees must not change between sessions. In Phase A
    Cowrie serves these from its static filesystem; from v0.6 LLM-created
    files must pass this same test via the state store."""
    from _support import ssh_session

    cmds = ["cat /etc/passwd", "uname -a", "hostname", "ls -la /root", "exit"]
    first = ssh_session(cowrie_server.host, cowrie_server.port, cmds)
    second = ssh_session(cowrie_server.host, cowrie_server.port, cmds)
    assert first == second
