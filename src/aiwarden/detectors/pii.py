"""Lightweight PII detection with checksum validation to keep false positives down.

This is intentionally conservative. For heavy-duty PII detection, plug in
Microsoft Presidio (planned optional extra).
"""

from __future__ import annotations

import re

from ..events import Severity
from . import Finding, redact

EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
CARD = re.compile(r"\b(?:\d[ \-]?){12,18}\d\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
US_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
IN_PAN = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")
IN_AADHAAR = re.compile(r"\b[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}\b")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    s = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


# Verhoeff checksum used by Aadhaar
_V_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
        [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
        [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_V_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
        [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    return c == 0


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits) and len(set(digits)) > 1:
            out.append(Finding("pii.credit_card", Severity.HIGH, "Possible payment card number", redact(digits), m.start()))
    for m in IBAN.finditer(text):
        if iban_ok(m.group(0)):
            out.append(Finding("pii.iban", Severity.MEDIUM, "Possible IBAN", redact(m.group(0)), m.start()))
    for m in US_SSN.finditer(text):
        out.append(Finding("pii.us_ssn", Severity.HIGH, "Possible US Social Security number", redact(m.group(0)), m.start()))
    for m in IN_AADHAAR.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if verhoeff_ok(digits):
            out.append(Finding("pii.aadhaar", Severity.MEDIUM, "Possible Aadhaar number", redact(digits), m.start()))
    for m in IN_PAN.finditer(text):
        out.append(Finding("pii.pan", Severity.MEDIUM, "Possible Indian PAN", redact(m.group(0)), m.start()))
    emails = list(EMAIL.finditer(text))
    if emails:
        sev = Severity.MEDIUM if len(emails) >= 5 else Severity.LOW
        out.append(Finding("pii.email", sev, f"{len(emails)} email address(es)", redact(emails[0].group(0)), emails[0].start()))
    return out
