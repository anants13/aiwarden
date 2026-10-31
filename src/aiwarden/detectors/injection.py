"""Heuristic prompt-injection detection.

Applied to content that comes from *untrusted* sources and flows into the
model: tool results, retrieved documents, web pages. Heuristics are noisy, so
severities are low/medium. The point is a trail of evidence when a later
tool-call alert fires.
"""

from __future__ import annotations

import re
import unicodedata

from ..events import Severity
from . import Finding

PHRASES: list[tuple[str, Severity, re.Pattern]] = [
    ("ignore_instructions", Severity.MEDIUM, re.compile(
        r"(?i)\b(?:ignore|disregard|forget|override)\b.{0,30}\b(?:previous|prior|above|earlier|all|system|your)\b.{0,20}\b(?:instructions?|prompts?|rules?|directions?|guidelines?)")),
    ("new_instructions", Severity.LOW, re.compile(r"(?i)\b(?:new|updated|real|actual) (?:system )?instructions?\s*[:\-]")),
    ("role_hijack", Severity.LOW, re.compile(r"(?i)\byou are (?:now|no longer)\b|\bact as (?:an? )?(?:unrestricted|jailbroken|DAN)\b")),
    ("fake_system_tag", Severity.MEDIUM, re.compile(r"(?i)<\|?(?:system|im_start\|>system|start_header_id\|>system)|\[/?INST\]|<<SYS>>|</?system>")),
    ("hidden_from_user", Severity.MEDIUM, re.compile(
        r"(?i)\b(?:do not|don't|never)\b.{0,20}\b(?:tell|inform|mention|reveal|show)\b.{0,20}\b(?:the )?user\b")),
    ("exfil_instruction", Severity.HIGH, re.compile(
        r"(?i)\b(?:send|post|upload|forward|exfiltrate|transmit|email)\b.{0,60}\b(?:api[_ ]?keys?|credentials?|passwords?|secrets?|tokens?|ssh keys?|\.env|private keys?|conversation|chat history)\b")),
    ("tool_coercion", Severity.MEDIUM, re.compile(
        r"(?i)\b(?:immediately|silently|now)\b.{0,20}\b(?:run|execute|call|invoke)\b.{0,30}\b(?:command|tool|function|shell|curl|bash)\b")),
]

INVISIBLE = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
}


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for name, sev, rx in PHRASES:
        m = rx.search(text)
        if m:
            frag = " ".join(m.group(0).split())[:120]
            out.append(Finding(f"injection.{name}", sev, f"Prompt-injection pattern: {name.replace('_', ' ')}", frag, m.start()))
    # Unicode tag characters (U+E0000-E007F) can smuggle invisible ASCII instructions.
    tags = [c for c in text if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        out.append(Finding("injection.unicode_tags", Severity.HIGH,
                           "Invisible Unicode tag characters (hidden instructions)", hidden[:120]))
    invis = sum(1 for c in text if c in INVISIBLE or unicodedata.category(c) == "Cf")
    if invis >= 20 and not tags:
        out.append(Finding("injection.invisible_chars", Severity.LOW, f"{invis} invisible format characters", ""))
    return out
