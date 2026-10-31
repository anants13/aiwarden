"""Dangerous tool-call / command detection.

Applied to tool calls the model emits (function arguments) and to code or
shell blocks in its responses. These rules matter most for agents, which
execute what the model says.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..events import Severity
from . import Finding

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW

RULES: list[tuple[str, Severity, str, re.Pattern]] = [
    ("pipe_to_shell", H, "Downloads and executes remote code",
     re.compile(r"(?i)\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\bpython[0-9.]*\s+-c\s+[\"'].*urlopen.*exec")),
    ("reverse_shell", H, "Reverse shell pattern",
     re.compile(r"/dev/tcp/\d|\bnc(?:at)?\b[^\n]*\s-[a-z]*e\s|\bsocat\b[^\n]*exec:|mkfifo\s+/tmp/[^\n]*\bnc\b|pty\.spawn\(|socket\.socket\([^\n]*connect\(")),
    ("destructive_rm", H, "Recursive delete of home/root",
     re.compile(r"\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|/\*|~/\*|\.\*?)(?:\s|$|;|&)")),
    ("disk_wipe", H, "Disk overwrite / format",
     re.compile(r"\bdd\s+if=[^\n]*\bof=/dev/(?:sd|nvme|disk|hd)|\bmkfs(?:\.\w+)?\s+/dev/|\bdiskutil\s+(?:erase|zero)")),
    ("credential_read", H, "Reads credential files",
     re.compile(r"(?i)(?:~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+|/root)?/?\.(?:ssh/(?:id_[a-z0-9]+|identity)|aws/credentials|azure/|config/gcloud/|netrc|pgpass|docker/config\.json|kube/config|git-credentials|npmrc|pypirc)|/etc/shadow\b|\bsecurity\s+(?:find|dump)-(?:generic|internet)-password|\bsecurity\s+dump-keychain|Login Data|Cookies\.binarycookies|key[34]\.db|logins\.json")),
    ("env_dump", M, "Dumps environment / .env files",
     re.compile(r"(?:\bcat|\bless|\bhead|\btail|\bcp|\bscp|open\()\s*[\"']?[^\s\"']*\.env\b|\bprintenv\b|\benv\s*\|\s*(?:curl|nc|base64)|os\.environ(?!\.get)")),
    ("upload_file", H, "Uploads local data to a remote host",
     re.compile(r"(?i)\bcurl\b[^\n]*(?:-d\s*@|--data(?:-binary|-raw|-urlencode)?\s*[@\"']?@|-F\s*[\"']?\w+=@|-T\s|--upload-file)|\bwget\b[^\n]*--post-file|\bscp\s+[^\n]*\s[\w.\-]+@[\w.\-]+:|\brsync\b[^\n]*\s[\w.\-]+@[\w.\-]+:")),
    ("encode_and_send", H, "Encodes data and sends it over the network",
     re.compile(r"(?i)\b(?:base64|xxd|gzip|tar)\b[^\n]*\|\s*(?:curl|nc|wget|ncat|socat)\b")),
    ("persistence", M, "Sets up persistence / autostart",
     re.compile(r"\bcrontab\s+(?:-[a-z]\s+)*-?[^l\s]|>>?\s*~?/?(?:\$HOME/)?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b|\blaunchctl\s+(?:load|bootstrap|submit)|LaunchAgents/|\bsystemctl\s+(?:--user\s+)?enable\b|authorized_keys")),
    ("security_disable", H, "Disables OS security controls",
     re.compile(r"\bsetenforce\s+0|\bspctl\s+--master-disable|\bcsrutil\s+disable|\bufw\s+disable|\biptables\s+-F|xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine")),
    ("privilege_escalation", M, "Privilege escalation",
     re.compile(r"\bsudo\s+(?:-S|su\b|bash|sh\b|chmod\s+[0-7]*4[0-7]{3}|chown\s+root)|\bchmod\s+(?:u\+s|[0-7]*4[0-7]{3})\b|NOPASSWD")),
    ("obfuscated_exec", M, "Executes obfuscated code",
     re.compile(r"(?i)base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba)?sh|\beval\s*\(\s*(?:base64|atob|bytes\.fromhex|codecs\.decode)|exec\(\s*(?:base64|__import__\(['\"]base64|zlib\.decompress|marshal\.loads)")),
    ("crypto_miner", M, "Crypto-miner indicators",
     re.compile(r"(?i)\b(?:xmrig|minerd|stratum\+tcp://|cryptonight)\b")),
]

# Hosts commonly used to receive exfiltrated data or tunnel out.
EXFIL_HOSTS = re.compile(
    r"(?i)\b(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin|transfer\.sh|file\.io|0x0\.st|temp\.sh|"
    r"webhook\.site|requestbin|pipedream\.net|beeceptor\.com|hookbin|ngrok(?:-free)?\.(?:io|app|dev)|"
    r"trycloudflare\.com|serveo\.net|localhost\.run|interact\.sh|oast\.(?:fun|live|me|pro|site|online)|"
    r"burpcollaborator\.net|canarytokens|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|"
    r"hooks\.slack\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com)"
)


def detect_command(text: str) -> list[Finding]:
    out: list[Finding] = []
    for name, sev, title, rx in RULES:
        m = rx.search(text)
        if m:
            out.append(Finding(f"tool.{name}", sev, title, " ".join(m.group(0).split())[:160], m.start()))
    m = EXFIL_HOSTS.search(text)
    if m:
        out.append(Finding("tool.exfil_host", Severity.HIGH if out else Severity.MEDIUM,
                           f"References a paste / webhook / tunnel service ({m.group(0)})", m.group(0), m.start()))
    return out


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        # Arguments are often a JSON string; parse to catch nested commands.
        try:
            return _flatten(json.loads(value))
        except (ValueError, TypeError):
            return value
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return "\n".join(_flatten(v) for v in value)
    return "" if value is None else str(value)


def detect_tool_call(name: str, arguments: Any) -> list[Finding]:
    text = _flatten(arguments)
    findings = detect_command(text)
    for f in findings:
        f.title = f"Tool call `{name}`: {f.title}"
    return findings
