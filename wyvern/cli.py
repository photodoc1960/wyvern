"""Command-line interface: ``wyvern <command>``.

Commands
--------
* ``monitor``  — live passive capture + dashboard (needs capture privileges).
* ``replay``   — replay a pcap through the detection pipeline.
* ``simulate`` — run the synthetic Toronto-worm scenario (demo / no privileges).
* ``report``   — print the current threat assessment from the stored data.
* ``export``   — write a forensic bundle (JSON) or alert CSV.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
from typing import Optional

from . import __version__
from .config import Config, ConfigError


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wyvern",
        description="Passive home-network sentinel for AI-worm signatures "
        "(observe / alert / recommend only — never modifies anything).",
    )
    p.add_argument("--version", action="version", version=f"wyvern {__version__}")
    p.add_argument("-c", "--config", help="path to a YAML config file")
    p.add_argument("--data-dir", help="override data directory")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("monitor", help="live passive capture + dashboard")
    m.add_argument("-i", "--iface", help="capture interface")
    m.add_argument("--no-web", action="store_true", help="don't start the dashboard")
    m.add_argument("--no-learn", action="store_true", help="skip baseline learning")

    r = sub.add_parser("replay", help="replay a pcap through detection")
    r.add_argument("pcap", help="pcap/pcapng file to replay")
    r.add_argument("--web", action="store_true", help="serve the dashboard afterwards")
    r.add_argument("--realtime", action="store_true", help="pace to capture timing")
    r.add_argument("--speed", type=float, default=1.0, help="realtime speed factor")

    s = sub.add_parser("simulate", help="run the synthetic worm scenario (safe demo)")
    s.add_argument("--web", action="store_true", help="serve the dashboard afterwards")
    s.add_argument("--pcap", help="also write the scenario to this pcap path")

    sub.add_parser("report", help="print the current threat assessment")

    e = sub.add_parser("export", help="export forensic data")
    e.add_argument("out", help="output file path")
    e.add_argument("--format", choices=["json", "csv"], default="json")
    return p


def _load_config(args) -> Config:
    if args.config:
        cfg = Config.from_file(args.config)
    else:
        cfg = Config.default()
    overrides = {}
    if getattr(args, "iface", None):
        overrides["interface"] = args.iface
    if args.data_dir:
        overrides["data_dir"] = args.data_dir
    if getattr(args, "no_web", False):
        overrides["web_enabled"] = False
    if overrides:
        cfg = dataclasses.replace(cfg, **overrides).validate()
    return cfg


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        cfg = _load_config(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "monitor":
        return _cmd_monitor(cfg, args)
    if args.command == "replay":
        return _cmd_replay(cfg, args)
    if args.command == "simulate":
        return _cmd_simulate(cfg, args)
    if args.command == "report":
        return _cmd_report(cfg)
    if args.command == "export":
        return _cmd_export(cfg, args)
    return 1


def _new_monitor(cfg: Config, *, learn: bool = True):
    from .alerting.notifier import build_notifier
    from .engine.monitor import Monitor

    return Monitor(cfg, learn=learn, notifier=build_notifier(cfg.notify))


def _cmd_monitor(cfg: Config, args) -> int:
    mon = _new_monitor(cfg, learn=not args.no_learn)
    try:
        mon.start_live()
    except RuntimeError as exc:
        print(f"capture error: {exc}\n"
              "Live capture needs privileges — try 'sudo' or set capabilities on python,\n"
              "or use 'wyvern simulate' / 'wyvern replay <pcap>' which need none.",
              file=sys.stderr)
        return 1
    print(f"Wyvern monitoring on {cfg.interface or 'default interface'} "
          f"(Ctrl-C to stop).")
    try:
        if cfg.web_enabled and not args.no_web:
            from .web.app import run_dashboard
            run_dashboard(mon, cfg.web_host, cfg.web_port)
        else:
            import time
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        mon.stop()
    return 0


def _cmd_replay(cfg: Config, args) -> int:
    mon = _new_monitor(cfg, learn=True)
    try:
        count = mon.replay(args.pcap, realtime=args.realtime, speed=args.speed)
    except RuntimeError as exc:
        print(f"replay error: {exc}", file=sys.stderr)
        return 1
    print(f"replayed {count} frames; {mon.event_count} events, "
          f"{len(mon._recent_alerts)} alerts.")
    _print_report(mon.current_assessment())
    if args.web:
        from .web.app import run_dashboard
        run_dashboard(mon, cfg.web_host, cfg.web_port)
    return 0


def _cmd_simulate(cfg: Config, args) -> int:
    from .simulate.worm_trace import worm_scenario, write_pcap

    if args.pcap:
        n = write_pcap(args.pcap)
        print(f"wrote {n} packets to {args.pcap}")

    mon = _new_monitor(cfg, learn=False)
    events = worm_scenario()
    mon.feed_events(events)
    print(f"simulated {len(events)} events; raised {len(mon._recent_alerts)} alerts.")
    _print_report(mon.current_assessment())
    if args.web:
        from .web.app import run_dashboard
        print(f"\nDashboard: http://{cfg.web_host}:{cfg.web_port}  (Ctrl-C to stop)")
        try:
            run_dashboard(mon, cfg.web_host, cfg.web_port)
        except KeyboardInterrupt:
            pass
    return 0


def _cmd_report(cfg: Config) -> int:
    from .assessment.threat import ThreatAssessor
    from .models.alert import Alert
    from .storage.db import WyvernDB
    from .tracking.registry import DeviceRegistry

    from .models.device import Device

    db = WyvernDB(cfg.db_path)
    rows = db.all_alerts()
    if not rows:
        print("No alerts recorded yet. Run 'wyvern monitor', 'replay' or 'simulate' first.")
        return 0
    alerts = [Alert.from_dict(r) for r in rows]
    registry = DeviceRegistry(cfg)
    registry.import_devices(Device.from_dict(d) for d in db.all_devices())
    assessment = ThreatAssessor(cfg).assess(alerts, registry)
    _print_report(assessment)
    return 0


def _cmd_export(cfg: Config, args) -> int:
    from .storage.db import WyvernDB
    from .storage.export import export_alerts_csv, export_forensic_bundle
    import time

    db = WyvernDB(cfg.db_path)
    if args.format == "csv":
        path = export_alerts_csv(args.out, db.all_alerts())
    else:
        path = export_forensic_bundle(
            args.out, devices=db.all_devices(), alerts=db.all_alerts(),
            assessment=None, generated_at=time.time(),
        )
    print(f"exported {args.format} -> {path}")
    return 0


def _print_report(assessment) -> None:
    print("\n" + "=" * 64)
    print(f"  THREAT LEVEL: {assessment.overall_level.label.upper()}")
    print(f"  {assessment.summary}")
    if assessment.likely_compromised:
        print(f"  Likely compromised device: {assessment.likely_compromised}")
    print("=" * 64)
    for t in assessment.device_threats[:8]:
        if t.level.value < 2 and not t.is_worm_suspect:
            continue
        flag = " [WORM SUSPECT]" if t.is_worm_suspect else ""
        print(f"\n  • {t.label} ({t.role}) — {t.level.label} "
              f"score={t.score:.0f}{flag}")
        if t.stages:
            print(f"      stages: {', '.join(t.stages)}")
        for rec in t.recommendations[:4]:
            print(f"      → {rec}")
    print()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
