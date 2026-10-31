"""Secret / credential detection."""

from __future__ import annotations

import math
import re

from ..events import Severity
from . import Finding, redact

H, M = Severity.HIGH, Severity.MEDIUM

# (rule suffix, severity, regex)
PATTERNS: list[tuple[str, Severity, re.Pattern]] = [
    ("private_key", H, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws_access_key", H, re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("github_token", H, re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("gitlab_token", H, re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_key", H, re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", H, re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("huggingface_token", H, re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("google_api_key", H, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", H, re.compile(r"\bxox[abposr]-[0-9A-Za-z\-]{10,}")),
    ("slack_webhook", H, re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("discord_webhook", H, re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+")),
    ("stripe_key", H, re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("twilio_key", M, re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("sendgrid_key", H, re.compile(r"\bSG\.[\w\-]{22}\.[\w\-]{43}\b")),
    ("npm_token", H, re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi_token", H, re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    ("jwt", M, re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("db_url_with_password", H, re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]{3,}@[^\s]+")),
]

# key = "value" style assignments; value must look random enough.
ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd|pwd|client[_-]?secret)"
    r"\s*[:=]\s*[\"']?([^\s\"']{8,})"
)

PLACEHOLDERS = {"changeme", "password", "xxxxxxxx", "your_api_key", "<redacted>", "********", "example"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def detect(text: str) -> list[Finding]:
    findings: list[Finding] = []
    covered: list[tuple[int, int]] = []
    for name, sev, rx in PATTERNS:
        for m in rx.finditer(text):
            covered.append(m.span())
            findings.append(Finding(f"secret.{name}", sev, f"Possible {name.replace('_', ' ')}", redact(m.group(0)), m.start()))
    for m in ASSIGNMENT.finditer(text):
        val = m.group(1)
        s = m.start(1)
        if any(a <= s < b for a, b in covered):
            continue
        if val.lower() in PLACEHOLDERS or val.startswith(("$", "{", "<", "os.environ", "process.env")):
            continue
        if shannon_entropy(val) < 3.0:
            continue
        findings.append(Finding("secret.assignment", Severity.MEDIUM, "Possible hard-coded credential", redact(val), s))
    return findings
