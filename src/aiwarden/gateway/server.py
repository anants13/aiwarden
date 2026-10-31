"""The inspecting LLM gateway.

Point your app/agent at http://127.0.0.1:8787 instead of the model server.
Requests are forwarded unchanged and responses stream back unchanged. A copy
is inspected in the background, so alert-only mode adds no latency.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, web

from ..config import Config
from ..detectors import Finding, exfil, injection, pii, secrets, toolcalls
from ..events import Event, Severity
from ..geo import GeoResolver, ip_scope, resolve_host
from .parse import ModelOutput, Segment, StreamAccumulator, request_segments

log = logging.getLogger(__name__)
SENSOR = "gateway"
UPSTREAM_TASK = web.AppKey("upstream_task", asyncio.Task)

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding",
}
RESPONSE_DROP = HOP_BY_HOP | {"content-encoding"}


def _downgrade(sev: Severity) -> Severity:
    return Severity(max(int(Severity.LOW), int(sev) - 10))


class Inspector:
    """Runs detectors over parsed requests/responses and publishes events."""

    def __init__(self, cfg: Config, publish: Callable[[Event], object], upstream_is_local: bool):
        g = cfg["gateway"]
        self.det = g["detectors"]
        self.store_snippets = bool(g.get("store_snippets", True))
        self.publish = publish
        self.upstream_is_local = upstream_is_local

    def _emit(self, f: Finding, direction: str, role: str, ctx: dict, severity: Severity | None = None) -> None:
        sev = severity or f.severity
        digest = hashlib.sha256(f"{f.rule}|{f.match}".encode()).hexdigest()[:16]
        details = {
            **ctx,
            "direction": direction,
            "role": role,
            "match": f.match if self.store_snippets else "",
        }
        where = "prompt" if direction == "request" else "model output"
        self.publish(Event(SENSOR, f.rule, sev, f"{f.title} in {where} ({role})", details, dedupe_key=digest))

    def inspect_request(self, body: dict, ctx: dict) -> None:
        for seg in request_segments(body):
            self._inspect_segment(seg, ctx)

    def _inspect_segment(self, seg: Segment, ctx: dict) -> None:
        text = seg.text
        if seg.role in ("user", "system", "tool"):
            # Data flowing *to* the model. If the model is local the data has
            # not left the machine yet, so findings are one level lower.
            if self.det.get("secrets"):
                for f in secrets.detect(text):
                    sev = _downgrade(f.severity) if self.upstream_is_local else f.severity
                    self._emit(f, "request", seg.role, ctx, sev)
            if self.det.get("pii"):
                for f in pii.detect(text):
                    sev = _downgrade(f.severity) if self.upstream_is_local else f.severity
                    self._emit(f, "request", seg.role, ctx, sev)
        if self.det.get("prompt_injection") and seg.role in ("tool", "user"):
            for f in injection.detect(text):
                # Untrusted tool output is where injections arrive; user text is usually benign.
                sev = f.severity if seg.role == "tool" else Severity.LOW
                self._emit(f, "request", seg.role, ctx, sev)

    def inspect_response(self, out: ModelOutput, ctx: dict) -> None:
        if self.det.get("tool_calls"):
            for call in out.tool_calls:
                for f in toolcalls.detect_tool_call(call.name, call.arguments):
                    self._emit(f, "response", f"tool_call:{call.name}", ctx)
            for f in toolcalls.detect_command(out.text):
                # Commands in prose/code blocks are lower risk than an actual tool call.
                self._emit(f, "response", "assistant", ctx, _downgrade(f.severity))
        if self.det.get("exfil_urls"):
            for f in exfil.detect(out.text):
                self._emit(f, "response", "assistant", ctx)
        if self.det.get("secrets"):
            for f in secrets.detect(out.text):
                self._emit(f, "response", "assistant", ctx)


class Gateway:
    def __init__(self, cfg: Config, publish: Callable[[Event], object], geo: GeoResolver | None = None):
        g = cfg["gateway"]
        self.cfg = cfg
        self.publish = publish
        self.upstream = g["upstream"].rstrip("/")
        self.max_inspect = int(g.get("max_inspect_bytes", 4_000_000))
        self.geo = geo or GeoResolver(cfg["geoip"]["country_db"], cfg["geoip"]["asn_db"])
        host = urlsplit(self.upstream).hostname or ""
        self.upstream_host = host
        ips = resolve_host(host)
        # Loopback or LAN: prompts don't leave your network.
        self.upstream_is_local = host == "localhost" or (
            bool(ips) and all(ip_scope(ip) in ("loopback", "private", "link_local") for ip in ips)
        )
        self.inspector = Inspector(cfg, publish, self.upstream_is_local)
        self._session: ClientSession | None = None
        self._bg: set[asyncio.Task] = set()

    # -- upstream location check
    def check_upstream(self) -> None:
        if self.upstream_is_local:
            log.info("upstream %s is local", self.upstream_host)
            return
        ips = resolve_host(self.upstream_host)
        allowed = self.cfg.allowed_countries
        countries = {}
        for ip in ips:
            info = self.geo.lookup(ip)
            countries[ip] = info.country
        details = {"upstream": self.upstream, "resolved": countries, "allowed": sorted(allowed)}
        known = {c for c in countries.values() if c}
        if not self.geo.available or not allowed or not known:
            self.publish(Event(SENSOR, "gateway.upstream_unverified", Severity.LOW,
                               f"Prompts go to remote host {self.upstream_host}; country could not be verified",
                               details, dedupe_key=self.upstream_host))
            return
        outside = sorted(known - allowed)
        if outside:
            self.publish(Event(SENSOR, "gateway.cross_border_upstream", Severity.HIGH,
                               f"Prompts are sent to {self.upstream_host} in {', '.join(outside)} (outside allowed countries)",
                               details, dedupe_key=f"{self.upstream_host}|{','.join(outside)}"))
        else:
            self.publish(Event(SENSOR, "gateway.upstream_ok", Severity.INFO,
                               f"Upstream {self.upstream_host} is in {', '.join(sorted(known))}", details,
                               dedupe_key=self.upstream_host))

    async def _upstream_loop(self) -> None:
        while True:
            await asyncio.to_thread(self.check_upstream)
            await asyncio.sleep(1800)

    # -- background inspection
    def _spawn(self, fn, *args) -> None:
        task = asyncio.ensure_future(asyncio.to_thread(self._safe, fn, *args))
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    @staticmethod
    def _safe(fn, *args) -> None:
        try:
            fn(*args)
        except Exception:
            log.exception("inspection failed")

    # -- proxy handler
    async def handle(self, request: web.Request) -> web.StreamResponse:
        assert self._session is not None
        body = await request.read()
        started = time.time()
        ctx: dict = {"endpoint": request.path, "upstream": self.upstream_host}
        parsed = None
        if body and len(body) <= self.max_inspect and body.lstrip()[:1] in (b"{", b"["):
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
        if isinstance(parsed, dict):
            ctx["model"] = parsed.get("model")
            self._spawn(self.inspector.inspect_request, parsed, dict(ctx))

        url = self.upstream + request.rel_url.path_qs
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
        headers["Accept-Encoding"] = "identity"
        try:
            upstream = await self._session.request(
                request.method, url, data=body if body else None, headers=headers,
                allow_redirects=False, auto_decompress=True,
            )
        except Exception as exc:
            self.publish(Event(SENSOR, "gateway.upstream_error", Severity.LOW,
                               f"Upstream unreachable: {exc}", {"url": self.upstream}, dedupe_key=str(exc)[:80]))
            return web.json_response({"error": f"aiwarden: upstream unreachable: {exc}"}, status=502)

        resp = web.StreamResponse(status=upstream.status, reason=upstream.reason)
        for k, v in upstream.headers.items():
            if k.lower() not in RESPONSE_DROP:
                resp.headers.add(k, v)
        await resp.prepare(request)
        acc = StreamAccumulator(self.max_inspect)
        sent = 0
        try:
            async for chunk in upstream.content.iter_any():
                await resp.write(chunk)
                sent += len(chunk)
                acc.feed(chunk)
            await resp.write_eof()
        finally:
            upstream.release()

        if isinstance(parsed, dict) and upstream.status < 400:
            self._spawn(self._after_response, acc, ctx)
        self.publish(Event(SENSOR, "gateway.request", Severity.INFO,
                           f"{request.method} {request.path} -> {upstream.status}",
                           {**ctx, "status": upstream.status, "bytes_in": len(body), "bytes_out": sent,
                            "ms": int((time.time() - started) * 1000)}))
        return resp

    def _after_response(self, acc: StreamAccumulator, ctx: dict) -> None:
        out = acc.finish()
        if acc.truncated:
            ctx = {**ctx, "truncated": True}
        self.inspector.inspect_response(out, ctx)

    # -- app lifecycle
    def app(self) -> web.Application:
        app = web.Application(client_max_size=256 * 1024 * 1024)
        app.router.add_route("*", "/{tail:.*}", self.handle)

        async def on_startup(_app):
            self._session = ClientSession(timeout=ClientTimeout(total=None, sock_connect=30))
            _app[UPSTREAM_TASK] = asyncio.create_task(self._upstream_loop())

        async def on_cleanup(_app):
            _app[UPSTREAM_TASK].cancel()
            if self._bg:
                await asyncio.gather(*self._bg, return_exceptions=True)
            if self._session:
                await self._session.close()

        app.on_startup.append(on_startup)
        app.on_cleanup.append(on_cleanup)
        return app

    def run(self) -> None:
        g = self.cfg["gateway"]
        web.run_app(self.app(), host=g["listen_host"], port=int(g["listen_port"]), print=None)
