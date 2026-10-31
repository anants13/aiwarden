"""Alert sinks and the event bus that fans events out to them.

Everything stays local by default. Webhooks are opt-in and only receive the
redacted event (never raw prompts or secrets).
"""

from __future__ import annotations

import json
import logging
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Protocol

from .events import Event, Severity

log = logging.getLogger(__name__)

_COLORS = {
    Severity.INFO: "\033[2m",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[1;31m",
}
_RESET = "\033[0m"


class Sink(Protocol):
    min_severity: Severity

    def emit(self, event: Event) -> None: ...


class ConsoleSink:
    def __init__(self, min_severity: Severity = Severity.LOW, stream=None, color: bool | None = None):
        self.min_severity = min_severity
        self.stream = stream or sys.stderr
        self.color = self.stream.isatty() if color is None else color

    def emit(self, event: Event) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime(event.ts))
        sev = event.severity.name
        if self.color:
            sev = f"{_COLORS[event.severity]}{sev:<6}{_RESET}"
        else:
            sev = f"{sev:<6}"
        line = f"{ts} {sev} [{event.rule}] {event.title}"
        brief = _brief(event.details)
        if brief:
            line += f"\n         {brief}"
        print(line, file=self.stream, flush=True)


def _brief(details: dict[str, Any], limit: int = 6) -> str:
    parts = []
    for k, v in [(k, v) for k, v in details.items() if v not in (None, "", [], {})][:limit]:
        if isinstance(v, (dict, list)):
            v = json.dumps(v, default=str)
        s = str(v)
        if len(s) > 120:
            s = s[:117] + "..."
        parts.append(f"{k}={s}")
    return "  ".join(parts)


class JsonlSink:
    def __init__(self, path: Path, min_severity: Severity = Severity.INFO):
        self.min_severity = min_severity
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event: Event) -> None:
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), default=str) + "\n")


class SqliteSink:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        ts REAL NOT NULL,
        sensor TEXT NOT NULL,
        rule TEXT NOT NULL,
        severity INTEGER NOT NULL,
        title TEXT NOT NULL,
        details TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
    """

    def __init__(self, path: Path, min_severity: Severity = Severity.INFO):
        self.min_severity = min_severity
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(self.SCHEMA)

    def emit(self, event: Event) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?)",
                (
                    event.id,
                    event.ts,
                    event.sensor,
                    event.rule,
                    int(event.severity),
                    event.title,
                    json.dumps(event.details, default=str),
                ),
            )
            self._db.commit()

    @staticmethod
    def query(path: Path, limit: int = 50, min_severity: Severity = Severity.LOW) -> list[dict[str, Any]]:
        path = Path(path).expanduser()
        if not path.exists():
            return []
        db = sqlite3.connect(path)
        try:
            rows = db.execute(
                "SELECT id, ts, sensor, rule, severity, title, details FROM events "
                "WHERE severity >= ? ORDER BY ts DESC LIMIT ?",
                (int(min_severity), limit),
            ).fetchall()
        finally:
            db.close()
        return [
            {
                "id": r[0],
                "ts": r[1],
                "sensor": r[2],
                "rule": r[3],
                "severity": Severity(r[4]).name.lower(),
                "title": r[5],
                "details": json.loads(r[6]),
            }
            for r in rows
        ]


class DesktopSink:
    """Native notifications: notify-send on Linux, osascript on macOS."""

    def __init__(self, min_severity: Severity = Severity.MEDIUM):
        self.min_severity = min_severity
        self.system = platform.system()

    def emit(self, event: Event) -> None:
        title = f"aiwarden: {event.severity.name}"
        body = event.title[:240]
        try:
            if self.system == "Darwin":
                # Pass text via argv so nothing in the event can be interpreted as AppleScript.
                subprocess.run(
                    [
                        "osascript",
                        "-e", "on run argv",
                        "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                        "-e", "end run",
                        title,
                        body,
                    ],
                    check=False,
                    timeout=5,
                    capture_output=True,
                )
            elif shutil.which("notify-send"):
                urgency = "critical" if event.severity >= Severity.HIGH else "normal"
                subprocess.run(
                    ["notify-send", "-u", urgency, "--", title, body],
                    check=False,
                    timeout=5,
                    capture_output=True,
                )
        except Exception as exc:  # notifications must never crash the monitor
            log.debug("desktop notification failed: %s", exc)


class WebhookSink:
    """POST alerts to a webhook. format: json | slack | ntfy."""

    def __init__(self, url: str, fmt: str = "json", min_severity: Severity = Severity.MEDIUM):
        self.url = url
        self.fmt = fmt
        self.min_severity = min_severity

    def _request(self, event: Event) -> urllib.request.Request:
        text = f"[{event.severity.name}] {event.title}"
        if self.fmt == "slack":
            data = json.dumps({"text": f"*aiwarden* {text}\n```{_brief(event.details)}```"}).encode()
            headers = {"Content-Type": "application/json"}
        elif self.fmt == "ntfy":
            data = f"{event.title}\n{_brief(event.details)}".encode()
            headers = {
                "Title": f"aiwarden {event.severity.name}",
                "Priority": "high" if event.severity >= Severity.HIGH else "default",
                "Tags": "warning",
            }
        else:
            data = json.dumps(event.to_dict(), default=str).encode()
            headers = {"Content-Type": "application/json"}
        return urllib.request.Request(self.url, data=data, headers=headers, method="POST")

    def emit(self, event: Event) -> None:
        req = self._request(event)

        def _send():
            try:
                urllib.request.urlopen(req, timeout=10).close()
            except Exception as exc:
                log.warning("webhook delivery failed: %s", exc)

        threading.Thread(target=_send, daemon=True).start()


class EventBus:
    """Dedupes events and fans them out to sinks."""

    def __init__(self, sinks: Iterable[Sink] = (), dedupe_window: float = 600.0):
        self.sinks = list(sinks)
        self.dedupe_window = dedupe_window
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, sink: Sink) -> None:
        self.sinks.append(sink)

    def _is_duplicate(self, event: Event) -> bool:
        if not event.dedupe_key or self.dedupe_window <= 0:
            return False
        key = f"{event.rule}|{event.dedupe_key}"
        now = event.ts
        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < self.dedupe_window:
                return True
            self._seen[key] = now
            if len(self._seen) > 50_000:  # bound memory
                cutoff = now - self.dedupe_window
                self._seen = {k: t for k, t in self._seen.items() if t >= cutoff}
        return False

    def publish(self, event: Event) -> bool:
        """Returns True if the event was delivered (not a duplicate)."""
        if self._is_duplicate(event):
            return False
        for sink in self.sinks:
            if event.severity >= sink.min_severity:
                try:
                    sink.emit(event)
                except Exception as exc:
                    log.warning("sink %s failed: %s", type(sink).__name__, exc)
        return True
