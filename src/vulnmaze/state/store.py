"""Per-attacker state store.

Every artefact the honeypot invents for an attacker (a user, a credential, a
file, a banner) is stored once under (attacker, username, fact) and served
unchanged forever after. The LLM may only *add* facts the store
does not hold yet (Magazov et al. [13]: pin facts, shrink the generative
surface).

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

GLOBAL_KEY = "global"
GLOBAL_USER = "*"
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

    # ---- keyed by (attacker_key, username); used by both public forms ----

    def _get(self, key: str, username: str, fact: str) -> Fact | None:
        row = self.conn.execute(
            "SELECT value, created_by FROM attacker_facts WHERE attacker_key=%s AND username=%s AND fact=%s",
            (key, username, fact),
        ).fetchone()
        return Fact(fact, row[0], row[1], False) if row else None

    def _create(self, key: str, username: str, fact: str, value: Any, created_by: str) -> Fact:
        self._check(fact, value)
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
        found = self._get(key, username, fact)
        assert found is not None
        return found

    def _list(self, key: str, username: str, prefix: str) -> list[Fact]:
        cur = self.conn.execute(
            """SELECT fact, value, created_by FROM attacker_facts
                WHERE attacker_key=%s AND username=%s AND fact LIKE %s ORDER BY fact""",
            (key, username, prefix.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%"),
        )
        return [Fact(f, v, c, False) for f, v, c in cur]

    # ---- per attacker ----------------------------------------------------

    def get(self, src_ip: str, username: str, fact: str) -> Fact | None:
        return self._get(self.attacker_key(src_ip), username, fact)

    def create_if_absent(self, src_ip: str, username: str, fact: str, value: Any,
                         created_by: str = "unknown") -> Fact:
        """Store `value` unless the fact exists; either way return the stored
        value. Safe under concurrency: exactly one caller wins, everyone gets
        the winner's value."""
        return self._create(self.attacker_key(src_ip), username, fact, value, created_by)

    def list(self, src_ip: str, username: str, prefix: str = "") -> list[Fact]:
        return self._list(self.attacker_key(src_ip), username, prefix)

    # ---- global (the machine itself, same for every attacker) -------------
    # Global facts: whether a command is installed, package versions. Stored under a
    # reserved key that can never equal an HMAC (those are 32 hex chars).

    def get_global(self, fact: str) -> Fact | None:
        return self._get(GLOBAL_KEY, GLOBAL_USER, fact)

    def create_global_if_absent(self, fact: str, value: Any, created_by: str = "unknown") -> Fact:
        return self._create(GLOBAL_KEY, GLOBAL_USER, fact, value, created_by)

    def list_global(self, prefix: str = "") -> list[Fact]:
        return self._list(GLOBAL_KEY, GLOBAL_USER, prefix)
