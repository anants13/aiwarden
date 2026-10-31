"""aiwarden command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

from . import __version__
from .config import HOME, build_bus, load_config
from .events import Event, Severity

BANNER = "aiwarden {v}: alert-only mode. Nothing is blocked, everything is logged locally."


def _warn_setup(cfg) -> None:
    from .geo import GeoResolver

    if not cfg.home_country:
        print("! home_country is not set: cross-border alerts are disabled. Run `aiwarden init`.", file=sys.stderr)
    if not GeoResolver(cfg["geoip"]["country_db"]).available:
        print("! GeoIP database missing: run `aiwarden geoip download`.", file=sys.stderr)


# --------------------------------------------------------------------------- commands

def cmd_init(args) -> int:
    target = Path(args.path).expanduser() if args.path else HOME / "config.yaml"
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)")
        return 1
    country = args.country
    if not country and sys.stdin.isatty():
        country = input("Your country (ISO 2-letter code, e.g. IN, US, DE): ").strip()
    if not country or len(country) != 2 or not country.isalpha():
        print("A 2-letter country code is required (--country XX)")
        return 1
    allow = [c.strip().upper() for c in (args.allow or "").split(",") if c.strip()]
    cfg = {
        "home_country": country.upper(),
        "allow_countries": allow,
        "gateway": {"upstream": args.upstream},
        "egress": {"processes": ["ollama", "llama-server", "lms", "cmd:vllm", "cmd:llama_cpp.server"]},
        "alerts": {"webhooks": []},
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# aiwarden configuration. See config.example.yaml in the repo for every option.\n"
        "# Add your agent with e.g. `- cmd:my_agent.py` under egress.processes.\n"
    )
    target.write_text(header + yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    print(f"wrote {target}")
    if not args.no_geoip:
        return cmd_geoip_download(args)
    return 0


def cmd_geoip_download(args) -> int:
    from .geo import download_dbip

    cfg = load_config(getattr(args, "config", None))
    dest = Path(cfg["geoip"]["country_db"]).expanduser().parent
    print(f"downloading DB-IP Lite databases to {dest} ...")
    for p in download_dbip(dest):
        print(f"  {p}")
    print("IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0")
    return 0


def cmd_geoip_lookup(args) -> int:
    from .geo import GeoResolver, ReverseDNS, resolve_host

    cfg = load_config(args.config)
    geo = GeoResolver(cfg["geoip"]["country_db"], cfg["geoip"]["asn_db"])
    ips = {args.target} if args.target.replace(".", "").replace(":", "").isalnum() and any(
        c.isdigit() for c in args.target) else resolve_host(args.target)
    rdns = ReverseDNS()
    for ip in sorted(ips):
        g = geo.lookup(ip)
        ok = "" if not g.country else ("allowed" if g.country in cfg.allowed_countries else "OUTSIDE allowed")
        print(f"{ip:<40} {g.scope:<9} {g.country or '-':<3} AS{g.asn or '-'} {g.as_org or ''}  "
              f"{rdns.get(ip, wait=2) or ''}  {ok}")
    return 0


def cmd_watch(args) -> int:
    from .egress import EgressWatcher

    cfg = load_config(args.config)
    if args.interval:
        cfg["egress"]["interval"] = args.interval
    bus = build_bus(cfg)
    print(BANNER.format(v=__version__), file=sys.stderr)
    _warn_setup(cfg)
    w = EgressWatcher(cfg, bus.publish, extra_pids=args.pid or (), watch_all=args.all)
    if args.once:
        w.poll_once()
        names = [f"{p.info.get('name')}({pid})" for pid, p in w.roots.items()]
        print(f"watched processes: {', '.join(names) or 'none found'}", file=sys.stderr)
        return 0
    signal.signal(signal.SIGTERM, lambda *_: w.stop())
    try:
        w.run()
    except KeyboardInterrupt:
        w.stop()
    return 0


def _gateway(cfg, args):
    from .gateway import Gateway

    if getattr(args, "upstream", None):
        cfg["gateway"]["upstream"] = args.upstream
    if getattr(args, "port", None):
        cfg["gateway"]["listen_port"] = args.port
    return Gateway(cfg, build_bus(cfg).publish)


def cmd_gateway(args) -> int:
    cfg = load_config(args.config)
    print(BANNER.format(v=__version__), file=sys.stderr)
    _warn_setup(cfg)
    gw = _gateway(cfg, args)
    g = cfg["gateway"]
    print(f"gateway listening on http://{g['listen_host']}:{g['listen_port']} -> {g['upstream']}", file=sys.stderr)
    gw.run()
    return 0


def cmd_up(args) -> int:
    """Run the egress watcher and the gateway together."""
    from .egress import EgressWatcher

    cfg = load_config(args.config)
    print(BANNER.format(v=__version__), file=sys.stderr)
    _warn_setup(cfg)
    gw = _gateway(cfg, args)
    w = EgressWatcher(cfg, gw.publish)
    threading.Thread(target=w.run, daemon=True, name="egress").start()
    g = cfg["gateway"]
    print(f"egress watcher running; gateway on http://{g['listen_host']}:{g['listen_port']} -> {g['upstream']}",
          file=sys.stderr)
    gw.run()
    w.stop()
    return 0


def cmd_scan(args) -> int:
    from .scan import scan_path

    cfg = load_config(args.config) if args.alert else None
    findings = scan_path(args.path)
    if args.json:
        print(json.dumps([{**f.__dict__, "severity": f.severity.name.lower()} for f in findings], indent=2))
    else:
        if not findings:
            print("no findings")
        for f in sorted(findings, key=lambda f: -f.severity):
            print(f"{f.severity.name:<6} {f.title}\n       {f.path}" + (f"\n       {f.detail}" if f.detail else ""))
    if cfg is not None:
        bus = build_bus(cfg, console=False)
        for f in findings:
            bus.publish(Event("scan", f.rule, f.severity, f"{f.title}: {f.path}", {"path": f.path, "detail": f.detail}))
    fail = Severity.parse(args.fail_on)
    return 2 if any(f.severity >= fail for f in findings) else 0


def cmd_events(args) -> int:
    from .alerts import SqliteSink

    cfg = load_config(args.config)
    rows = SqliteSink.query(Path(cfg["alerts"]["sqlite"]["path"]), args.limit, Severity.parse(args.min_severity))
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    for r in reversed(rows):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        print(f"{ts} {r['severity'].upper():<6} [{r['rule']}] {r['title']}")
    return 0


def cmd_test_alert(args) -> int:
    cfg = load_config(args.config)
    bus = build_bus(cfg)
    bus.publish(Event("test", "test.alert", Severity.HIGH, "Test alert from aiwarden: notifications work",
                      {"hint": "you can ignore this"}))
    time.sleep(2)  # give webhook threads a moment
    return 0


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aiwarden", description="Local watchdog for open-source AI models.")
    p.add_argument("--version", action="version", version=f"aiwarden {__version__}")
    p.add_argument("-c", "--config", help="config file (default: ./aiwarden.yaml or ~/.aiwarden/config.yaml)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a config file and download GeoIP data")
    s.add_argument("--country", help="your ISO country code, e.g. IN")
    s.add_argument("--allow", help="extra allowed countries, comma separated")
    s.add_argument("--upstream", default="http://127.0.0.1:11434", help="model server the gateway forwards to")
    s.add_argument("--path", help="where to write the config")
    s.add_argument("--force", action="store_true")
    s.add_argument("--no-geoip", action="store_true", help="skip the GeoIP download")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("geoip", help="manage / query the GeoIP database")
    gs = s.add_subparsers(dest="geoip_cmd", required=True)
    d = gs.add_parser("download", help="download DB-IP Lite country + ASN databases")
    d.set_defaults(fn=cmd_geoip_download)
    lk = gs.add_parser("lookup", help="look up an IP or hostname")
    lk.add_argument("target")
    lk.set_defaults(fn=cmd_geoip_lookup)

    s = sub.add_parser("watch", help="monitor network egress of model processes")
    s.add_argument("--pid", type=int, action="append", help="also watch this pid (repeatable)")
    s.add_argument("--all", action="store_true", help="watch every process you can see (noisy)")
    s.add_argument("--interval", type=float, help="poll interval in seconds")
    s.add_argument("--once", action="store_true", help="single pass, then exit")
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("gateway", help="run the inspecting LLM API proxy")
    s.add_argument("--upstream", help="e.g. http://127.0.0.1:11434 or https://api.together.xyz")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=cmd_gateway)

    s = sub.add_parser("up", help="run watch + gateway together")
    s.add_argument("--upstream")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=cmd_up)

    s = sub.add_parser("scan", help="statically scan model files / directories")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on", default="high", help="exit 2 if a finding has this severity or higher")
    s.add_argument("--alert", action="store_true", help="also send findings to configured alert sinks")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("events", help="show recent events")
    s.add_argument("-n", "--limit", type=int, default=50)
    s.add_argument("--min-severity", default="low")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_events)

    s = sub.add_parser("test-alert", help="send a test alert to every configured sink")
    s.set_defaults(fn=cmd_test_alert)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        return int(args.fn(args) or 0)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
