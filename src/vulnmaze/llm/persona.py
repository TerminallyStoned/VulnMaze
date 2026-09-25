"""The persona the honeypot presents (loaded from infra/persona/persona.yml)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Persona:
    hostname: str
    os_pretty: str
    os_id: str
    os_version: str
    codename: str
    kernel: str
    arch: str
    role: str
    facts: dict[str, str] = field(default_factory=dict)
    installed: frozenset[str] = frozenset()
    absent: frozenset[str] = frozenset()

    @classmethod
    def load(cls, path: str | Path) -> Persona:
        raw = yaml.safe_load(Path(path).read_text())
        os_ = raw["os"]
        cmds = raw.get("commands", {}) or {}
        installed = frozenset(cmds.get("installed", []) or [])
        absent = frozenset(cmds.get("absent", []) or [])
        overlap = installed & absent
        if overlap:
            raise ValueError(f"commands both installed and absent: {sorted(overlap)}")
        return cls(
            hostname=raw["hostname"],
            os_pretty=os_["pretty_name"],
            os_id=os_["id"],
            os_version=str(os_["version_id"]),
            codename=os_["codename"],
            kernel=raw["kernel"],
            arch=raw.get("arch", "x86_64"),
            role=" ".join(str(raw.get("role", "")).split()),
            facts={k: str(v) for k, v in (raw.get("facts") or {}).items()},
            installed=installed,
            absent=absent,
        )

    @classmethod
    def from_env(cls) -> Persona:
        default = Path(__file__).resolve().parents[3] / "infra/persona/persona.yml"
        return cls.load(os.environ.get("VULNMAZE_PERSONA", default))
