"""Turn one raw Cowrie JSON event into a de-identified row.

The row keeps a few typed columns we query often and puts everything else
in ``data`` (JSONB). Fields that identify people or our sensor are removed
here, so nothing downstream ever sees them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vulnmaze.common.deid import Deidentifier

# Raw fields never stored. `message` repeats the password and IP in prose;
# dst_ip is our own sensor's address; geo fields appear in some public sets.
DROP_FIELDS = {"src_ip", "dst_ip", "password", "message", "format", "time", "isError", "system"}
DROP_PREFIXES = ("geo", "location")
TEXT_FIELDS_TO_SCRUB = ("input", "url", "destfile", "filename")


@dataclass
class SessionSecrets:
    """What the normaliser must remember per session to scrub later events."""

    src_ip: str | None = None
    passwords: set[str] = field(default_factory=set)


@dataclass
class Row:
    event_hash: bytes
    source: str
    sensor: str | None
    session: str
    eventid: str
    ts: datetime
    src_ip_hmac: str | None
    src_prefix: str | None
    username: str | None
    password_hmac: str | None
    password_len: int | None
    input: str | None
    data: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        """JSON-friendly view used by the digest builder."""
        d = dict(self.data)
        d.update(
            eventid=self.eventid,
            session=self.session,
            ts=self.ts.isoformat(),
            src_ip_hmac=self.src_ip_hmac,
            src_prefix=self.src_prefix,
        )
        for k in ("username", "password_hmac", "password_len", "input", "sensor"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def parse_ts(event: dict[str, Any]) -> datetime:
    raw = event.get("timestamp", event.get("time"))
    if isinstance(raw, int | float):
        return datetime.fromtimestamp(float(raw), tz=UTC)
    if isinstance(raw, str):
        s = raw.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return datetime.fromtimestamp(float(s), tz=UTC)
        # Always store UTC so timestamps compare correctly as strings too.
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)
    raise ValueError(f"event has no usable timestamp: {raw!r}")


def event_hash(raw_line: str) -> bytes:
    """Idempotency key: re-reading the same line never creates a duplicate."""
    return hashlib.sha256(raw_line.strip().encode("utf-8", "replace")).digest()


def normalise(
    event: dict[str, Any],
    raw_line: str,
    deid: Deidentifier,
    secrets: SessionSecrets,
    source: str = "live",
) -> Row:
    eventid = event.get("eventid")
    session = event.get("session")
    if not eventid or not session:
        raise ValueError("event lacks eventid or session")

    src_ip = event.get("src_ip") or secrets.src_ip
    if src_ip:
        secrets.src_ip = src_ip

    password = event.get("password")
    if eventid.startswith("cowrie.login.") and isinstance(password, str):
        secrets.passwords.add(password)

    data: dict[str, Any] = {}
    for k, v in event.items():
        if k in DROP_FIELDS or k.startswith(DROP_PREFIXES):
            continue
        if k in {"eventid", "session", "timestamp", "sensor", "username", "input"}:
            continue
        data[k] = v
    for k in TEXT_FIELDS_TO_SCRUB:
        if isinstance(data.get(k), str):
            data[k] = Deidentifier.redact_text(data[k], secrets.passwords, secrets.src_ip)

    return Row(
        event_hash=event_hash(raw_line),
        source=source,
        sensor=event.get("sensor"),
        session=str(session),
        eventid=eventid,
        ts=parse_ts(event),
        src_ip_hmac=deid.ip(src_ip),
        src_prefix=deid.prefix(src_ip),
        username=event.get("username"),
        password_hmac=deid.secret(password) if isinstance(password, str) else None,
        password_len=len(password) if isinstance(password, str) else None,
        input=Deidentifier.redact_text(event.get("input"), secrets.passwords, secrets.src_ip),
        data=json.loads(json.dumps(data, default=str)),
    )
