"""IP -> country / ASN / hostname enrichment, fully offline.

Uses the free DB-IP Lite databases (CC BY 4.0, "IP Geolocation by DB-IP",
https://db-ip.com). Run `aiwarden geoip download` to fetch them.
MaxMind GeoLite2 .mmdb files work too: point the config at them.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import ipaddress
import logging
import shutil
import socket
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import __version__

log = logging.getLogger(__name__)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")

DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"


@dataclass(frozen=True)
class GeoInfo:
    ip: str
    country: str | None = None  # ISO alpha-2
    asn: int | None = None
    as_org: str | None = None
    scope: str = "public"  # public | private | loopback | link_local | multicast | reserved


def ip_scope(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "reserved"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private or addr in _CGNAT:  # RFC1918, ULA, carrier-grade NAT
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


class GeoResolver:
    def __init__(self, country_db: str | Path | None = None, asn_db: str | Path | None = None):
        self._country = self._open(country_db)
        self._asn = self._open(asn_db)
        self._cache: dict[str, GeoInfo] = {}

    @staticmethod
    def _open(path):
        if not path:
            return None
        p = Path(path).expanduser()
        if not p.exists():
            return None
        import maxminddb

        return maxminddb.open_database(str(p))

    @property
    def available(self) -> bool:
        return self._country is not None

    def lookup(self, ip: str) -> GeoInfo:
        cached = self._cache.get(ip)
        if cached is None:
            cached = self._lookup(ip)
            if len(self._cache) > 65536:
                self._cache.clear()
            self._cache[ip] = cached
        return cached

    def _lookup(self, ip: str) -> GeoInfo:
        scope = ip_scope(ip)
        if scope != "public":
            return GeoInfo(ip=ip, scope=scope)
        country = asn = org = None
        if self._country is not None:
            rec = self._country.get(ip) or {}
            country = (rec.get("country") or {}).get("iso_code")
        if self._asn is not None:
            rec = self._asn.get(ip) or {}
            asn = rec.get("autonomous_system_number")
            org = rec.get("autonomous_system_organization")
        return GeoInfo(ip=ip, country=country, asn=asn, as_org=org, scope=scope)


class ReverseDNS:
    """Non-blocking PTR lookups with a cache. Returns None until resolved."""

    def __init__(self, workers: int = 4):
        self._cache: dict[str, str | None] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdns")

    def get(self, ip: str, wait: float = 0.0) -> str | None:
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip not in self._pending:
                self._pending.add(ip)
                fut = self._pool.submit(self._resolve, ip)
            else:
                fut = None
        if wait and fut is not None:
            try:
                return fut.result(timeout=wait)
            except Exception:
                return None
        return None

    def _resolve(self, ip: str) -> str | None:
        try:
            name = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
        except Exception:
            name = None
        with self._lock:
            self._cache[ip] = name
            self._pending.discard(ip)
        return name


def resolve_host(host: str) -> set[str]:
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def download_dbip(dest_dir: Path) -> list[Path]:
    """Download the current month's DB-IP Lite country + ASN databases."""
    dest_dir = Path(dest_dir).expanduser()
    dest_dir.mkdir(parents=True, exist_ok=True)
    today = _dt.date.today()
    prev = (today.replace(day=1) - _dt.timedelta(days=1))
    out = []
    for kind in ("country", "asn"):
        target = dest_dir / f"dbip-{kind}-lite.mmdb"
        last_err = None
        for d in (today, prev):  # new month's file may not be published yet
            url = DBIP_URL.format(kind=kind, ym=d.strftime("%Y-%m"))
            try:
                tmp = target.with_suffix(".tmp")
                req = urllib.request.Request(url, headers={"User-Agent": f"aiwarden/{__version__}"})
                with urllib.request.urlopen(req, timeout=120) as resp, gzip.GzipFile(fileobj=resp) as gz, tmp.open("wb") as fh:
                    shutil.copyfileobj(gz, fh)
                tmp.replace(target)
                out.append(target)
                break
            except Exception as exc:
                last_err = exc
        else:
            raise RuntimeError(f"could not download DB-IP {kind} database: {last_err}")
    return out
