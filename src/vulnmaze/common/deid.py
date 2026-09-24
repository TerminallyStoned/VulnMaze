"""De-identification applied before anything reaches long-term storage.

* Source IPs are replaced by a keyed HMAC (so the same attacker keeps the same
  pseudonym across sessions) plus a coarse network prefix for analysis.
  A plain SHA-256 of an IPv4 address is NOT de-identification: there are only
  2^32 addresses, so anyone can hash them all and reverse it. The HMAC key is
  what makes the pseudonym irreversible; keep it out of the repository and
  out of any data release.
* Passwords are replaced by a keyed HMAC and their length. Equality survives
  (password reuse is a useful feature), the plaintext does not.
* Any password the session tried, and the session's own source IP, are also
  scrubbed from free text such as command lines.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"
SRC_IP_TOKEN = "[SRC_IP]"
MIN_SECRET_LEN = 4  # shorter strings would redact ordinary words


class DeidKeyMissing(RuntimeError):
    pass


class Deidentifier:
    def __init__(self, key: bytes):
        if len(key) < 16:
            raise DeidKeyMissing("VULNMAZE_DEID_KEY must be at least 16 bytes (32 hex chars)")
        self._key = key

    @classmethod
    def from_env(cls, var: str = "VULNMAZE_DEID_KEY") -> Deidentifier:
        raw = os.environ.get(var, "")
        if not raw:
            # Fail closed: never ingest with a missing key.
            raise DeidKeyMissing(f"{var} is not set; refusing to ingest raw telemetry")
        try:
            return cls(bytes.fromhex(raw))
        except ValueError as exc:
            raise DeidKeyMissing(f"{var} must be hex") from exc

    def _mac(self, domain: str, value: str) -> str:
        return hmac.new(self._key, f"{domain}:{value}".encode(), hashlib.sha256).hexdigest()[:32]

    def ip(self, ip: str | None) -> str | None:
        return self._mac("ip", ip) if ip else None

    def secret(self, value: str | None) -> str | None:
        return self._mac("pw", value) if value is not None else None

    @staticmethod
    def prefix(ip: str | None) -> str | None:
        """IPv4 -> /16, IPv6 -> /32. Coarse enough not to identify a host,
        fine enough to see that a campaign comes from one provider."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        bits = 16 if addr.version == 4 else 32
        return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))

    @staticmethod
    def redact_text(text: str | None, secrets: Iterable[str] = (), src_ip: str | None = None) -> str | None:
        if text is None:
            return None
        out = text
        # Longest first so "admin123" is replaced before "admin".
        for s in sorted({s for s in secrets if s and len(s) >= MIN_SECRET_LEN}, key=len, reverse=True):
            out = out.replace(s, REDACTED)
        if src_ip:
            out = re.sub(rf"(?<![\d.]){re.escape(src_ip)}(?![\d.])", SRC_IP_TOKEN, out)
        return out
