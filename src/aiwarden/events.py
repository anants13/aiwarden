"""Event model shared by every sensor (egress monitor, gateway, scanner)."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


@dataclass
class Event:
    """A single observation. Only severities >= the sink threshold become alerts."""

    sensor: str  # "egress" | "gateway" | "scan" | "host"
    rule: str  # stable rule id, e.g. "egress.cross_border"
    severity: Severity
    title: str
    details: dict[str, Any] = field(default_factory=dict)
    # Events with the same dedupe_key are only alerted once per dedupe window.
    dedupe_key: str | None = None
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name.lower()
        return d
