"""Per-attacker state store.

Every artefact the honeypot invents for an attacker (a user, a credential, a
file, a banner) is stored once under (attacker, username, fact) and served
unchanged forever after. An LLM layer may only *add* facts the store does
not hold yet (pin facts, shrink the generative surface).

Write-once is enforced twice: ``create_if_absent`` never overwrites, and a
database trigger rejects any UPDATE on the table.

Keys: the attacker is identified by the HMAC of the source IP, never the IP
itself. Callers pass the raw IP; it is hashed here with the same key the
ingester uses, so facts line up with telemetry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from vulnmaze.common.deid import Deidentifier

MAX_FACT_NAME = 512
MAX_VALUE_BYTES = 256 * 1024


@dataclass(frozen=True)
class Fact:
    fact: str
    value: Any
    created_by: str
    created: bool   # True only for the call that actually wrote it


class StateStore:
    def __init__(self, conn: psycopg.Connection, deid: Deidentifier):
        self.conn = conn
        self.deid = deid

    def attacker_key(self, src_ip: str) -> str:
        key = self.deid.ip(src_ip)
        if key is None:
            raise ValueError("src_ip is required")
        return key

    @staticmethod
    def _check(fact: str, value: Any) -> None:
        if not fact or len(fact) > MAX_FACT_NAME:
            raise ValueError("fact name must be 1-512 characters")
        if len(json.dumps(value, default=str)) > MAX_VALUE_BYTES:
            raise ValueError("fact value too large")

    def get(self, src_ip: str, username: str, fact: str) -> Fact | None:
        row = self.conn.execute(
            "SELECT value, created_by FROM attacker_facts WHERE attacker_key=%s AND username=%s AND fact=%s",
            (self.attacker_key(src_ip), username, fact),
        ).fetchone()
        return Fact(fact, row[0], row[1], False) if row else None

    def create_if_absent(self, src_ip: str, username: str, fact: str, value: Any,
                         created_by: str = "unknown") -> Fact:
        """Store `value` unless the fact exists; either way return the stored
        value. Safe under concurrency: exactly one caller wins, everyone gets
        the winner's value."""
        self._check(fact, value)
        key = self.attacker_key(src_ip)
        with self.conn.transaction():
            row = self.conn.execute(
                """INSERT INTO attacker_facts (attacker_key, username, fact, value, created_by)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (attacker_key, username, fact) DO NOTHING
                   RETURNING value, created_by""",
                (key, username, fact, Jsonb(value), created_by),
            ).fetchone()
            if row:
                return Fact(fact, row[0], row[1], True)
            row = self.conn.execute(
                "SELECT value, created_by FROM attacker_facts WHERE attacker_key=%s AND username=%s AND fact=%s",
                (key, username, fact),
            ).fetchone()
        return Fact(fact, row[0], row[1], False)

    def list(self, src_ip: str, username: str, prefix: str = "") -> list[Fact]:
        cur = self.conn.execute(
            """SELECT fact, value, created_by FROM attacker_facts
                WHERE attacker_key=%s AND username=%s AND fact LIKE %s ORDER BY fact""",
            (self.attacker_key(src_ip), username, prefix.replace("%", r"\%") + "%"),
        )
        return [Fact(f, v, c, False) for f, v, c in cur]
