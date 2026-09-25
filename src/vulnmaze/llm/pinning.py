"""Fact pinning: the model may add facts, never change them.

Two kinds of contradiction are caught deterministically:

* Persona contradictions: the answer names a different hostname, distro,
  Debian release, kernel, IP address or service version than the persona.
  Checked with regular expressions over the text, so no model is needed to
  judge the model.
* Stored-fact contradictions: the answer declares a fact (in its `facts`
  list) that the state store already holds with a different value.

Either one makes the gateway regenerate, telling the model which fact it got
wrong; if the retry still contradicts, the answer is replaced by a fallback.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from vulnmaze.llm.persona import Persona

FACT_KEY = re.compile(r"^[a-z0-9][a-z0-9_.:/-]{0,99}$")

_OTHER_DISTROS = re.compile(
    r"\b(Ubuntu|CentOS|Fedora|Red Hat|RHEL|Alpine Linux|Arch Linux|Amazon Linux|Rocky Linux|AlmaLinux|"
    r"openSUSE|SUSE Linux|Kali|Raspbian|Linux Mint|Windows(?: Server)?)\b"
)
_CODENAMES = {"buster", "bullseye", "bookworm", "trixie", "stretch", "jessie",
              "jammy", "focal", "noble", "bionic", "xenial", "kinetic", "lunar", "mantic"}
_CODENAME = re.compile(r"\b(" + "|".join(sorted(_CODENAMES)) + r")\b", re.IGNORECASE)
_DEBIAN_VERSION = re.compile(r"Debian GNU/Linux (\d+)")
_KERNEL = re.compile(r"\b(\d+\.\d+\.\d+-\d+-(?:amd64|arm64|generic|cloud-amd64|rt-amd64|aws|azure))\b")
_HOST_PATTERNS = [
    re.compile(r"\b[a-z_][a-z0-9_-]*@([A-Za-z0-9][A-Za-z0-9-]{0,62}):[~/]"),   # shell prompt user@host:~
    re.compile(r"^Linux ([A-Za-z0-9][A-Za-z0-9.-]{0,62}) \d+\.\d+", re.MULTILINE),  # uname -a
    re.compile(r"Static hostname:\s*(\S+)"),                                       # hostnamectl
]
_INET = re.compile(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/\d+")

# (regex capturing a version, persona fact key, how to compare)
_VERSION_CHECKS: list[tuple[re.Pattern, str, Callable[[str], str]]] = [
    (re.compile(r"(\d+\.\d+\.\d+)-MariaDB"), "mariadb_version", lambda v: v.split("-")[0]),
    (re.compile(r"\bnginx/(\d+\.\d+\.\d+)"), "nginx_version", lambda v: v),
    (re.compile(r"\bPHP (\d+\.\d+\.\d+)"), "php_version", lambda v: v),
    (re.compile(r"\bOpenSSL (\d+\.\d+\.\d+)"), "openssl_version", lambda v: v),
]


@dataclass
class PersonaChecker:
    persona: Persona

    def check(self, text: str) -> list[str]:
        p = self.persona
        reasons: list[str] = []
        for pat in _HOST_PATTERNS:
            for host in pat.findall(text):
                if host not in (p.hostname, "localhost"):
                    reasons.append(f"contradicts_persona:hostname={host}")
        for m in _OTHER_DISTROS.findall(text):
            reasons.append(f"contradicts_persona:os={m}")
        for m in _CODENAME.findall(text):
            if m.lower() != p.codename.lower():
                reasons.append(f"contradicts_persona:codename={m}")
        for m in _DEBIAN_VERSION.findall(text):
            if m != p.os_version:
                reasons.append(f"contradicts_persona:debian={m}")
        for m in _KERNEL.findall(text):
            if m != p.kernel:
                reasons.append(f"contradicts_persona:kernel={m}")
        allowed_ips = {"127.0.0.1", p.facts.get("primary_ip", "")}
        for ip in _INET.findall(text):
            if ip not in allowed_ips:
                reasons.append(f"contradicts_persona:ip={ip}")
        for pat, key, norm in _VERSION_CHECKS:
            expected = p.facts.get(key)
            if not expected:
                continue
            for found in pat.findall(text):
                if norm(found) != norm(expected):
                    reasons.append(f"contradicts_persona:{key}={found}")
        return sorted(set(reasons))

    def check_declared(self, facts: dict[str, str]) -> list[str]:
        """A declared fact whose key is a persona fact must match it."""
        return [
            f"contradicts_persona:{k}={v}"
            for k, v in facts.items()
            if k in self.persona.facts and str(v) != self.persona.facts[k]
        ]


def fact_contradictions(declared: dict[str, str], stored: dict[str, str]) -> list[str]:
    return [f"contradicts_fact:{k}" for k, v in declared.items() if k in stored and stored[k] != v]
