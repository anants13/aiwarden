"""Configuration loading. A YAML file is merged over built-in defaults."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from .alerts import (
    ConsoleSink,
    DesktopSink,
    EventBus,
    JsonlSink,
    SqliteSink,
    WebhookSink,
)
from .events import Severity

HOME = Path(os.environ.get("AIWARDEN_HOME", Path.home() / ".aiwarden"))

DEFAULTS: dict[str, Any] = {
    # ISO 3166-1 alpha-2 code of the country you are in. Required for
    # cross-border alerts; `aiwarden init` asks for it.
    "home_country": None,
    # Countries data may go to without an alert (home_country is always included).
    "allow_countries": [],
    "mode": "alert",  # only "alert" is implemented in v0.1
    "geoip": {
        "country_db": str(HOME / "geo" / "dbip-country-lite.mmdb"),
        "asn_db": str(HOME / "geo" / "dbip-asn-lite.mmdb"),
    },
    "egress": {
        # Processes to watch. Plain string = exact process name.
        # "cmd:<text>" = substring of the full command line.
        "processes": [
            "ollama",
            "llama-server",
            "llama-cli",
            "lms",
            "LM Studio",
            "koboldcpp",
            "cmd:vllm",
            "cmd:text-generation-launcher",
            "cmd:llama_cpp.server",
            "cmd:sglang",
        ],
        "include_children": True,
        "interval": 1.0,
        # Destinations that never alert (still logged as INFO).
        # Domains are resolved periodically and also matched against reverse DNS.
        "allow_domains": [
            "huggingface.co",
            "cdn-lfs.huggingface.co",
            "cdn-lfs.hf.co",
            "cas-bridge.xethub.hf.co",
            "registry.ollama.ai",
        ],
        "allow_asns": [],
        "allow_cidrs": [],
        "alert_on_lan": False,
        # Inference servers should not talk to the internet after they have
        # finished loading. Any connection after the grace period alerts.
        "silent_processes": ["ollama", "llama-server", "cmd:vllm", "cmd:llama_cpp.server"],
        "silent_grace_seconds": 120,
        # Child processes that are suspicious when spawned by a watched process.
        "suspicious_children": [
            "sh", "bash", "zsh", "dash", "fish", "curl", "wget", "nc", "ncat",
            "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet",
            "base64", "openssl", "osascript", "security",
        ],
        # Alert if a watched server listens on 0.0.0.0 / :: (reachable from your network).
        "alert_on_public_listen": True,
    },
    "gateway": {
        "listen_host": "127.0.0.1",
        "listen_port": 8787,
        "upstream": "http://127.0.0.1:11434",
        "detectors": {
            "secrets": True,
            "pii": True,
            "prompt_injection": True,
            "tool_calls": True,
            "exfil_urls": True,
        },
        # Store a redacted snippet of the matching text in events.
        "store_snippets": True,
        # Max bytes of a request/response body to inspect.
        "max_inspect_bytes": 4_000_000,
    },
    "alerts": {
        "console": {"min_severity": "low"},
        "desktop": {"enabled": True, "min_severity": "medium"},
        "jsonl": {"enabled": True, "path": str(HOME / "events.jsonl"), "min_severity": "info"},
        "sqlite": {"enabled": True, "path": str(HOME / "events.db"), "min_severity": "info"},
        # - {url: https://ntfy.sh/my-topic, format: ntfy, min_severity: high}
        "webhooks": [],
        "dedupe_seconds": 600,
    },
}

CONFIG_SEARCH = [Path("aiwarden.yaml"), HOME / "config.yaml"]


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config(dict):
    path: Path | None = None

    @property
    def home_country(self) -> str | None:
        hc = self.get("home_country")
        return hc.upper() if hc else None

    @property
    def allowed_countries(self) -> set[str]:
        allowed = {c.upper() for c in self.get("allow_countries") or []}
        if self.home_country:
            allowed.add(self.home_country)
        return allowed


def load_config(path: str | Path | None = None) -> Config:
    data: dict[str, Any] = {}
    found: Path | None = None
    candidates = [Path(path).expanduser()] if path else CONFIG_SEARCH
    for cand in candidates:
        if cand.exists():
            with cand.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            found = cand
            break
    else:
        if path:
            raise FileNotFoundError(f"config file not found: {path}")
    cfg = Config(_merge(DEFAULTS, data))
    cfg.path = found
    if cfg.get("mode") != "alert":
        raise ValueError("only mode: alert is supported in this version")
    return cfg


def build_bus(cfg: Config, console: bool = True) -> EventBus:
    a = cfg["alerts"]
    bus = EventBus(dedupe_window=float(a.get("dedupe_seconds", 600)))
    if console:
        bus.add(ConsoleSink(Severity.parse(a["console"].get("min_severity", "low"))))
    if a["jsonl"].get("enabled"):
        bus.add(JsonlSink(Path(a["jsonl"]["path"]), Severity.parse(a["jsonl"].get("min_severity", "info"))))
    if a["sqlite"].get("enabled"):
        bus.add(SqliteSink(Path(a["sqlite"]["path"]), Severity.parse(a["sqlite"].get("min_severity", "info"))))
    if a["desktop"].get("enabled"):
        bus.add(DesktopSink(Severity.parse(a["desktop"].get("min_severity", "medium"))))
    for hook in a.get("webhooks") or []:
        bus.add(
            WebhookSink(
                hook["url"],
                hook.get("format", "json"),
                Severity.parse(hook.get("min_severity", "medium")),
            )
        )
    return bus
