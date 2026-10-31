"""Egress monitor: which watched process is talking to which country.

v0.1 polls the OS connection table with psutil. That works unprivileged for
your own processes on Linux and macOS, but very short-lived connections that
open and close between polls can be missed. The sandbox (`aiwarden run`,
planned) and eBPF backends close that gap.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

import psutil

from .config import Config
from .events import Event, Severity
from .geo import GeoInfo, GeoResolver, ReverseDNS, resolve_host

log = logging.getLogger(__name__)

SENSOR = "egress"


# --------------------------------------------------------------------------- matching

def process_matches(name: str, cmdline: list[str] | None, patterns: Iterable[str]) -> bool:
    name_l = (name or "").lower()
    cmd = " ".join(cmdline or []).lower()
    for p in patterns:
        p = str(p)
        if p.startswith("cmd:"):
            needle = p[4:].strip().lower()
            if needle and needle in cmd:
                return True
        elif p.lower() == name_l:
            return True
    return False


def domain_matches(host: str | None, domains: Iterable[str]) -> str | None:
    if not host:
        return None
    host = host.lower().rstrip(".")
    for d in domains:
        d = d.lower().lstrip("*").lstrip(".")
        if host == d or host.endswith("." + d):
            return d
    return None


# --------------------------------------------------------------------------- policy

@dataclass
class ConnInfo:
    pid: int
    proc_name: str
    cmdline: list[str]
    root_pid: int
    root_name: str
    root_age: float  # seconds since the watched root process started
    root_is_silent: bool
    raddr: str
    rport: int
    proto: str = "tcp"


@dataclass
class EgressPolicy:
    allowed_countries: set[str]
    home_country: str | None
    allow_domains: list[str] = field(default_factory=list)
    allow_asns: set[int] = field(default_factory=set)
    allow_cidrs: list = field(default_factory=list)
    alert_on_lan: bool = False
    silent_grace_seconds: float = 120
    geo_available: bool = True
    # ip -> domain, filled by periodically resolving allow_domains
    resolved_allow: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_config(cls, cfg: Config, geo_available: bool) -> EgressPolicy:
        e = cfg["egress"]
        return cls(
            allowed_countries=cfg.allowed_countries,
            home_country=cfg.home_country,
            allow_domains=list(e.get("allow_domains") or []),
            allow_asns={int(a) for a in e.get("allow_asns") or []},
            allow_cidrs=[ipaddress.ip_network(c, strict=False) for c in e.get("allow_cidrs") or []],
            alert_on_lan=bool(e.get("alert_on_lan")),
            silent_grace_seconds=float(e.get("silent_grace_seconds", 120)),
            geo_available=geo_available,
        )

    def _allow_reason(self, c: ConnInfo, geo: GeoInfo, host: str | None) -> str | None:
        if c.raddr in self.resolved_allow:
            return f"domain:{self.resolved_allow[c.raddr]}"
        d = domain_matches(host, self.allow_domains)
        if d:
            return f"domain:{d}"
        if geo.asn is not None and geo.asn in self.allow_asns:
            return f"asn:{geo.asn}"
        try:
            ip = ipaddress.ip_address(c.raddr)
            for net in self.allow_cidrs:
                if ip in net:
                    return f"cidr:{net}"
        except ValueError:
            pass
        return None

    def evaluate(self, c: ConnInfo, geo: GeoInfo, host: str | None) -> Event | None:
        if geo.scope in ("loopback", "multicast", "reserved"):
            return None
        details = {
            "process": c.proc_name,
            "pid": c.pid,
            "watched_root": f"{c.root_name}({c.root_pid})",
            "remote": f"{c.raddr}:{c.rport}",
            "proto": c.proto,
            "host": host,
            "country": geo.country,
            "asn": geo.asn,
            "as_org": geo.as_org,
            "cmdline": " ".join(c.cmdline)[:300],
        }
        dedupe = f"{c.root_name}|{c.raddr}|{c.rport}"
        where = host or c.raddr

        def ev(rule, sev, title, **extra):
            return Event(SENSOR, rule, sev, title, {**details, **extra}, dedupe_key=dedupe)

        if geo.scope in ("private", "link_local"):
            if self.alert_on_lan:
                return ev("egress.lan", Severity.LOW, f"{c.proc_name} connected to LAN host {where}:{c.rport}")
            return None

        allow = self._allow_reason(c, geo, host)
        if allow:
            return ev("egress.allowed", Severity.INFO, f"{c.proc_name} -> {where} (allowlisted {allow})", allowed_by=allow)

        silent_violation = c.root_is_silent and c.root_age > self.silent_grace_seconds
        reasons = []
        if silent_violation:
            reasons.append(
                f"{c.root_name} is an inference server and should not make outbound "
                f"connections after startup (running {int(c.root_age)}s)"
            )

        if not self.geo_available or not self.home_country:
            why = "no GeoIP database" if not self.geo_available else "home_country not configured"
            sev = Severity.MEDIUM if silent_violation else Severity.LOW
            return ev("egress.unverified", sev, f"{c.proc_name} -> {where}:{c.rport} (country unknown: {why})", reasons=reasons)

        if geo.country is None:
            sev = Severity.MEDIUM if silent_violation else Severity.LOW
            return ev("egress.unknown_country", sev, f"{c.proc_name} -> {where}:{c.rport} (country not in GeoIP database)", reasons=reasons)

        if geo.country not in self.allowed_countries:
            reasons.insert(0, f"destination country {geo.country} is outside allowed {sorted(self.allowed_countries)}")
            return ev(
                "egress.cross_border",
                Severity.HIGH,
                f"{c.proc_name} sent data to {geo.country}: {where}:{c.rport}"
                + (f" ({geo.as_org})" if geo.as_org else ""),
                reasons=reasons,
            )

        if silent_violation:
            return ev("egress.inference_server_outbound", Severity.MEDIUM,
                      f"Inference server {c.root_name} connected out to {where}:{c.rport}", reasons=reasons)

        return ev("egress.connection", Severity.INFO, f"{c.proc_name} -> {where}:{c.rport} ({geo.country})")


# --------------------------------------------------------------------------- watcher

def _conns(proc: psutil.Process):
    fn = getattr(proc, "net_connections", None) or proc.connections  # psutil < 6
    return fn(kind="inet")


class EgressWatcher:
    ROOT_RESCAN_SECONDS = 3.0
    ALLOW_RESOLVE_SECONDS = 300.0

    def __init__(
        self,
        cfg: Config,
        publish: Callable[[Event], object],
        geo: GeoResolver | None = None,
        extra_pids: Iterable[int] = (),
        watch_all: bool = False,
    ):
        e = cfg["egress"]
        self.cfg = cfg
        self.publish = publish
        self.geo = geo or GeoResolver(cfg["geoip"]["country_db"], cfg["geoip"]["asn_db"])
        self.rdns = ReverseDNS()
        self.policy = EgressPolicy.from_config(cfg, self.geo.available)
        self.patterns = list(e.get("processes") or [])
        self.silent_patterns = list(e.get("silent_processes") or [])
        self.suspicious_children = {s.lower() for s in e.get("suspicious_children") or []}
        self.include_children = bool(e.get("include_children", True))
        self.alert_on_public_listen = bool(e.get("alert_on_public_listen", True))
        self.interval = float(e.get("interval", 1.0))
        self.extra_pids = set(extra_pids)
        self.watch_all = watch_all
        self._me = psutil.Process().pid

        self.roots: dict[int, psutil.Process] = {}
        self._seen_conns: set[tuple] = set()
        self._seen_children: set[tuple[int, float]] = set()
        self._denied: set[int] = set()
        self._last_rescan = 0.0
        self._last_allow_resolve = 0.0
        self._stop = threading.Event()

    # -- discovery
    def _rescan_roots(self) -> None:
        roots: dict[int, psutil.Process] = {}
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if p.pid == self._me:
                    continue
                if p.pid in self.extra_pids or self.watch_all or process_matches(
                    p.info["name"], p.info["cmdline"], self.patterns
                ):
                    roots[p.pid] = p
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # Don't treat children of an already-watched root as separate roots.
        if not self.watch_all:
            for pid, p in list(roots.items()):
                try:
                    if any(a.pid in roots for a in p.parents()):
                        del roots[pid]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        new = set(roots) - set(self.roots)
        for pid in new:
            log.info("watching %s (pid %s)", roots[pid].info.get("name"), pid)
        self.roots = roots

    def _resolve_allowlist(self) -> None:
        resolved: dict[str, str] = {}
        for d in self.policy.allow_domains:
            if d.startswith("*"):
                continue  # wildcards only match via reverse DNS
            for ip in resolve_host(d):
                resolved[ip] = d
        self.policy.resolved_allow = resolved

    # -- one polling pass
    def poll_once(self) -> None:
        now = time.time()
        if now - self._last_allow_resolve > self.ALLOW_RESOLVE_SECONDS:
            self._last_allow_resolve = now
            threading.Thread(target=self._resolve_allowlist, daemon=True).start()
        if now - self._last_rescan > self.ROOT_RESCAN_SECONDS:
            self._last_rescan = now
            self._rescan_roots()

        for root_pid, root in list(self.roots.items()):
            try:
                root_name = root.info.get("name") or root.name()
                root_cmd = root.info.get("cmdline") or []
                root_age = now - root.create_time()
                silent = process_matches(root_name, root_cmd, self.silent_patterns)
                procs = [root]
                if self.include_children and not self.watch_all:
                    procs += root.children(recursive=True)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            for proc in procs:
                self._inspect(proc, root_pid, root_name, root_age, silent, now)

    def _inspect(self, proc, root_pid, root_name, root_age, silent, now) -> None:
        try:
            name = proc.name()
            cmdline = proc.cmdline()
            if proc.pid != root_pid:
                self._check_child(proc, name, cmdline, root_pid, root_name, silent)
            conns = _conns(proc)
        except psutil.AccessDenied:
            if proc.pid not in self._denied:
                self._denied.add(proc.pid)
                self.publish(Event(
                    SENSOR, "egress.access_denied", Severity.LOW,
                    f"Cannot inspect connections of pid {proc.pid}; run aiwarden as the same user or with sudo",
                    {"pid": proc.pid}, dedupe_key=str(proc.pid),
                ))
            return
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return

        for c in conns:
            if self.alert_on_public_listen and c.status == psutil.CONN_LISTEN and c.laddr:
                if c.laddr.ip in ("0.0.0.0", "::", "*"):
                    self.publish(Event(
                        SENSOR, "egress.public_listen", Severity.MEDIUM,
                        f"{name} is listening on {c.laddr.ip}:{c.laddr.port}: reachable from other machines on your network",
                        {"process": name, "pid": proc.pid, "port": c.laddr.port,
                         "hint": "bind to 127.0.0.1 (e.g. OLLAMA_HOST=127.0.0.1)"},
                        dedupe_key=f"{name}|{c.laddr.port}",
                    ))
                continue
            if not c.raddr:
                continue  # unconnected UDP / listening
            key = (proc.pid, c.raddr.ip, c.raddr.port)
            if key in self._seen_conns:
                continue
            self._seen_conns.add(key)
            if len(self._seen_conns) > 200_000:
                self._seen_conns.clear()
            geo = self.geo.lookup(c.raddr.ip)
            host = self.rdns.get(c.raddr.ip, wait=0.5) if geo.scope == "public" else None
            info = ConnInfo(
                pid=proc.pid, proc_name=name, cmdline=cmdline, root_pid=root_pid,
                root_name=root_name, root_age=root_age, root_is_silent=silent,
                raddr=c.raddr.ip, rport=c.raddr.port,
                proto="udp" if c.type == socket.SOCK_DGRAM else "tcp",
            )
            event = self.policy.evaluate(info, geo, host)
            if event:
                self.publish(event)

    def _check_child(self, proc, name, cmdline, root_pid, root_name, silent) -> None:
        try:
            key = (proc.pid, proc.create_time())
        except psutil.Error:
            return
        if key in self._seen_children:
            return
        self._seen_children.add(key)
        if name.lower() in self.suspicious_children:
            sev = Severity.HIGH if silent else Severity.MEDIUM
            self.publish(Event(
                "host", "host.suspicious_child", sev,
                f"{root_name} spawned {name}: {' '.join(cmdline)[:160]}",
                {"process": name, "pid": proc.pid, "watched_root": f"{root_name}({root_pid})",
                 "cmdline": " ".join(cmdline)[:500]},
                dedupe_key=f"{root_name}|{' '.join(cmdline)[:200]}",
            ))

    # -- loop
    def run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                self.poll_once()
            except Exception:
                log.exception("poll failed")
            self._stop.wait(max(0.05, self.interval - (time.monotonic() - started)))

    def stop(self) -> None:
        self._stop.set()
