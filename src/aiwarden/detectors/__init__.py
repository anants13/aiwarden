"""Content detectors. Each takes text and returns a list of Findings.

Detectors are deliberately simple and transparent (regex + checksums) so that
anyone can audit and extend them. Add new patterns in the module lists.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..events import Severity


@dataclass
class Finding:
    rule: str
    severity: Severity
    title: str
    match: str  # already redacted / truncated; safe to store
    start: int = 0


def redact(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return value[:2] + "***"
    return f"{value[:keep]}***{value[-2:]}"


def snippet(text: str, start: int, end: int, width: int = 40) -> str:
    """Context around a match, with the match itself redacted."""
    left = text[max(0, start - width):start]
    right = text[end:end + width]
    s = f"{left}[{redact(text[start:end])}]{right}"
    return " ".join(s.split())
