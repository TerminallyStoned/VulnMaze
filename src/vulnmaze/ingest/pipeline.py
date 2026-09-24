"""Write normalised events and their digests to PostgreSQL.

One batch = one transaction: the events, the updated digests and (for the
live tailer) the file checkpoint commit together, so a crash never loses or
duplicates an event.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import OrderedDict
from collections.abc import Iterable

import psycopg
from psycopg.types.json import Jsonb

from vulnmaze.common.deid import Deidentifier
from vulnmaze.digest.builder import apply as apply_digest
from vulnmaze.digest.builder import new_digest
from vulnmaze.ingest.normalize import Row, SessionSecrets, normalise

log = logging.getLogger("vulnmaze.ingest")

INSERT_EVENT = """
INSERT INTO events (event_hash, source, sensor, session, eventid, ts, src_ip_hmac, src_prefix,
                    username, password_hmac, password_len, input, data)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (event_hash) DO NOTHING
RETURNING id
"""

UPSERT_DIGEST = """
INSERT INTO session_digests (source, session, digest, closed, n_events, updated_at)
VALUES (%s, %s, %s, %s, %s, now())
ON CONFLICT (source, session) DO UPDATE
   SET digest = EXCLUDED.digest, closed = EXCLUDED.closed,
       n_events = EXCLUDED.n_events, updated_at = now()
"""


class _LRU(OrderedDict):
    def __init__(self, maxsize: int):
        super().__init__()
        self.maxsize = maxsize

    def get_or_create(self, key, factory):
        if key in self:
            self.move_to_end(key)
            return self[key]
        value = factory()
        self[key] = value
        if len(self) > self.maxsize:
            self.popitem(last=False)
        return value


class Ingestor:
    def __init__(self, conn: psycopg.Connection, deid: Deidentifier, source: str = "live"):
        self.conn = conn
        self.deid = deid
        self.source = source
        # Per-session memory needed to scrub later events (passwords typed at
        # login may be echoed in commands). Bounded so floods cannot exhaust RAM.
        self.secrets: _LRU = _LRU(50_000)
        self.stats = {"inserted": 0, "duplicates": 0, "errors": 0}

    def _record_error(self, line: str, err: Exception) -> None:
        self.stats["errors"] += 1
        self.conn.execute(
            "INSERT INTO ingest_errors (source, error, line_sha256) VALUES (%s, %s, %s)",
            (self.source, f"{type(err).__name__}: {err}"[:500], hashlib.sha256(line.encode()).digest()),
        )

    def ingest_lines(self, lines: Iterable[str]) -> int:
        """Normalise and store raw JSON lines. Caller owns the transaction."""
        rows: list[Row] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                sess = str(event.get("session"))
                secrets = self.secrets.get_or_create((self.source, sess), SessionSecrets)
                rows.append(normalise(event, line, self.deid, secrets, self.source))
            except Exception as err:  # malformed line: keep going, record it
                self._record_error(line, err)
        return self.store_rows(rows)

    def store_rows(self, rows: list[Row]) -> int:
        inserted: list[Row] = []
        with self.conn.cursor() as cur:
            for r in rows:
                cur.execute(INSERT_EVENT, (
                    r.event_hash, r.source, r.sensor, r.session, r.eventid, r.ts, r.src_ip_hmac,
                    r.src_prefix, r.username, r.password_hmac, r.password_len, r.input, Jsonb(r.data),
                ))
                if cur.fetchone() is not None:
                    inserted.append(r)
                else:
                    self.stats["duplicates"] += 1
        self.stats["inserted"] += len(inserted)
        self._update_digests(inserted)
        return len(inserted)

    def _update_digests(self, rows: list[Row]) -> None:
        by_session: dict[tuple[str, str], list[Row]] = {}
        for r in rows:
            by_session.setdefault((r.source, r.session), []).append(r)
        with self.conn.cursor() as cur:
            for (source, session), sess_rows in by_session.items():
                cur.execute(
                    "SELECT digest FROM session_digests WHERE source=%s AND session=%s FOR UPDATE",
                    (source, session),
                )
                found = cur.fetchone()
                digest = found[0] if found else new_digest(source, session)
                # Events can arrive slightly out of order across batches only
                # if two writers interleave; within a batch keep file order.
                for r in sess_rows:
                    apply_digest(digest, r.as_dict(), inplace=True)
                cur.execute(UPSERT_DIGEST, (
                    source, session, Jsonb(digest), digest["closed"], digest["counts"]["events"],
                ))
                if digest["closed"]:
                    self.secrets.pop((source, session), None)


def rebuild_digest(conn: psycopg.Connection, source: str, session: str) -> dict:
    """Recompute a digest from the events table (after a digest schema change)."""
    from vulnmaze.digest.builder import build

    cur = conn.execute(
        """SELECT eventid, session, ts, src_ip_hmac, src_prefix, username, password_hmac,
                  password_len, input, sensor, data
             FROM events WHERE source=%s AND session=%s ORDER BY ts, id""",
        (source, session),
    )
    events = []
    for eventid, sess, ts, ip, prefix, user, pwh, pwl, inp, sensor, data in cur:
        e = dict(data)
        e.update(eventid=eventid, session=sess, ts=ts.isoformat(), src_ip_hmac=ip,
                 src_prefix=str(prefix) if prefix else None)
        for k, v in (("username", user), ("password_hmac", pwh), ("password_len", pwl),
                     ("input", inp), ("sensor", sensor)):
            if v is not None:
                e[k] = v
        events.append(e)
    return build(events, source, session)
