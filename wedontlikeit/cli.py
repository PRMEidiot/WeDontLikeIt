"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import platform as pyplatform
import sys
import time
import unicodedata
from dataclasses import asdict
from pathlib import Path

from . import __version__, i18n, platforms, updater
from .config import Config
from .i18n import t
from .quarantine import Quarantine
from .scanner import SEV_RANK, Engine, ScanConfig
from .signatures import SignatureDB, add_to_allowlist, sha256_file

MB = 1 << 20


def _width(text: str) -> int:
    """Columns a string takes in a terminal (CJK characters take two)."""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)
SEV_COLOR = {"high": "1;31", "medium": "33", "low": "36"}


class Out:
    def __init__(self, json_mode: bool = False):
        self.json = json_mode
        self.color = platforms.use_color(sys.stdout) and not json_mode

    def c(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def say(self, *a, **kw) -> None:
        if not self.json:
            print(*a, **kw)

    def detection(self, d) -> None:
        sev = i18n.upper(t(f"sev.{d.severity}"))
        tag = self.c(f"{sev:<6}", SEV_COLOR[d.severity])
        self.say(f"{tag} {d.name}  {self.c(d.label, '2')}")


# --------------------------------------------------------------------- setup
def build_engine(args) -> Engine:
    db = SignatureDB.default([Path(d) for d in args.signatures])
    excl = [*platforms.system_excludes(), platforms.data_dir(), *args.exclude]
    if args.quarantine_dir:
        excl.append(args.quarantine_dir)
    cfg = ScanConfig(
        heuristics=not args.no_heuristics,
        archives=not args.no_archives,
        yara_paths=tuple(args.yara),
        max_size=args.max_size * MB,
        exclude=tuple(str(p) for p in excl),
    )
    try:
        return Engine(db, cfg)
    except ImportError:
        sys.exit(f"error: {t('err.yara')}")


def quarantine_handler(args, out: Out, q: Quarantine, isolated: list):
    threshold = SEV_RANK["medium"] if args.quarantine_all else SEV_RANK["high"]
    enabled = args.quarantine or args.quarantine_all

    def on_file(path: Path, dets) -> None:
        for d in dets:
            out.detection(d)
        if not (enabled and dets):
            return
        worst = max(dets, key=lambda d: SEV_RANK[d.severity])
        if SEV_RANK[worst.severity] < threshold:
            return
        try:
            qid = q.add(path, worst.name)
            isolated.append({"file": str(path), "id": qid})
            out.say(out.c(f"       {t('scan.moved', id=qid)}", "35"))
        except OSError as exc:
            print(t("scan.quarantine_failed", path=path, err=exc), file=sys.stderr)

    return on_file


def jobs_for(args) -> int:
    return args.jobs if args.jobs > 0 else min(os.cpu_count() or 1, 8)


# ------------------------------------------------------------------ commands
def run_scan(args, targets: list[Path]) -> int:
    out = Out(args.json)
    engine = build_engine(args)
    q = Quarantine(args.quarantine_dir)
    isolated: list = []

    t0 = time.monotonic()
    result = engine.scan(targets, on_file=quarantine_handler(args, out, q, isolated), jobs=jobs_for(args))
    elapsed = time.monotonic() - t0

    if args.json:
        data = asdict(result)
        data["quarantined"] = isolated
        data["seconds"] = round(elapsed, 2)
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 1 if result.detections else 0

    if args.verbose:
        for path, err in result.errors:
            print(out.c(f"{t('scan.unreadable_tag')} {path}: {err}", "2"), file=sys.stderr)

    rows = [(t("scan.files"), i18n.num(result.scanned))]
    if result.skipped:
        rows.append((t("scan.skipped", mb=args.max_size), i18n.num(result.skipped)))
    if result.errors:
        hint = "" if args.verbose else t("scan.errors_hint")
        rows.append((t("scan.errors"), i18n.num(len(result.errors)) + hint))
    if result.detections:
        by_sev = {s: sum(d.severity == s for d in result.detections) for s in SEV_RANK}
        parts = ", ".join(f"{i18n.num(n)} {t('sev.' + s)}" for s, n in sorted(by_sev.items(), key=lambda kv: -SEV_RANK[kv[0]]) if n)
        rows.append((t("scan.flagged"), out.c(str(result.infected_files), "1;31") + f"  ({parts})"))
    else:
        rows.append((t("scan.flagged"), out.c("0", "1;32")))
    if isolated:
        rows.append((t("scan.quarantined"), str(len(isolated))))
    rows.append((t("scan.time"), f"{elapsed:.1f}s"))

    width = max(_width(k) for k, _ in rows)
    print()
    for k, v in rows:
        print(f"{k}{' ' * (width - _width(k))}  {v}")
    print()
    print(out.c(t("scan.verdict_bad") if result.detections else t("scan.verdict_ok"), "1"))
    return 1 if result.detections else 0


def cmd_scan(args) -> int:
    return run_scan(args, [Path(x) for x in args.targets])


def cmd_quick(args) -> int:
    paths = platforms.quick_scan_paths()
    if not args.json:
        print(t("quick.title", system=platforms.system_name()))
        for p in paths:
            print(f"  {p}")
        print()
    return run_scan(args, paths)


def cmd_watch(args) -> int:
    from .monitor import Monitor

    out = Out()
    paths = [Path(p) for p in args.folders] or platforms.watch_default_paths()
    if not paths:
        sys.exit(f"error: {t('watch.none')}")
    engine = build_engine(args)
    handler = quarantine_handler(args, out, Quarantine(args.quarantine_dir), [])
    mon = Monitor(engine, paths)
    print(t("watch.title"))
    for p in paths:
        print(f"  {p}")
    while True:
        time.sleep(args.interval)
        for path, dets in mon.poll():
            print(out.c(time.strftime("%H:%M:%S"), "2"))
            handler(path, dets)


def cmd_quarantine(args) -> int:
    q = Quarantine(args.quarantine_dir)
    if args.action == "list":
        items = q.list()
        if not items:
            print(t("q.empty"))
        for m in items:
            print(f"{m['id']}  {m['date'][:16].replace('T', ' ')}  {m['threat']:<34} {m['original']}")
    elif args.action == "restore":
        dest = q.restore(args.id, args.dest)
        print(t("q.restored", path=dest))
        print(t("q.restored_tip"))
    elif args.action == "delete":
        q.delete(args.id)
        print(t("q.deleted", id=args.id))
    return 0


def cmd_update(args) -> int:
    key = args.key or os.environ.get("ABUSECH_AUTH_KEY") or Config.load().abusech_key or None
    print(t("update.downloading", url=args.url))
    new, total = updater.update(platforms.user_signature_dir(), args.url, key)
    print(t("update.done", new=new, total=total, dir=platforms.user_signature_dir()))
    return 0


def cmd_allow(args) -> int:
    for path, digest in add_to_allowlist(args.files):
        print(t("allow.done", path=path, digest=digest[:16]))
    return 0


def cmd_hash(args) -> int:
    for f in args.files:
        print(f"{sha256_file(f)}  {f}")
    return 0


def cmd_info(args) -> int:
    db = SignatureDB.default()
    q = Quarantine(args.quarantine_dir)
    try:
        import yara  # type: ignore  # noqa: F401
        yara_ok = t("info.yes")
    except ImportError:
        yara_ok = t("info.yara_missing")
    rows = [
        (t("info.system"), f"{platforms.system_name()} ({pyplatform.machine()}), Python {pyplatform.python_version()}"),
        (t("info.language"), i18n.LANGS[i18n.current()]),
        (t("info.data"), str(platforms.data_dir())),
        (t("info.quarantine"), t("info.items", path=q.dir, n=len(q.list()))),
        (t("info.signatures"), t("info.sig_counts", h=len(db.hashes), p=len(db.patterns), a=len(db.allow))),
        ("YARA", yara_ok),
    ]
    width = max(_width(k) for k, _ in rows)
    print(f"WeDontLikeIt {__version__}\n")
    for k, v in rows:
        print(f"{k}{' ' * (width - _width(k))}  {v}")
    print(f"\n{t('info.quick')}")
    for p in platforms.quick_scan_paths():
        print(f"  {p}")
    return 0


def cmd_gui(args) -> int:
    from .gui import main as gui_main

    gui_main()
    return 0


# -------------------------------------------------------------------- parser
def _engine_options(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group(t("opt.detection"))
    g.add_argument("--no-heuristics", action="store_true", help=t("opt.no_heuristics"))
    g.add_argument("--no-archives", action="store_true", help=t("opt.no_archives"))
    g.add_argument("--yara", action="append", default=[], metavar="PATH", help=t("opt.yara"))
    g.add_argument("--signatures", action="append", default=[], metavar="DIR", help=t("opt.signatures"))
    g.add_argument("--exclude", action="append", default=[], type=Path, metavar="PATH", help=t("opt.exclude"))
    g.add_argument("--max-size", type=int, default=512, metavar="MB", help=t("opt.max_size"))
    a = p.add_argument_group(t("opt.action"))
    a.add_argument("-q", "--quarantine", action="store_true", help=t("opt.quarantine"))
    a.add_argument("--quarantine-all", action="store_true", help=t("opt.quarantine_all"))


def _scan_options(p: argparse.ArgumentParser) -> None:
    _engine_options(p)
    p.add_argument("-j", "--jobs", type=int, default=0, help=t("opt.jobs"))
    p.add_argument("--json", action="store_true", help=t("opt.json"))
    p.add_argument("-v", "--verbose", action="store_true", help=t("opt.verbose"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wedontlikeit", description=t("cli.description"))
    p.add_argument("--version", action="version", version=f"wedontlikeit {__version__}")
    p.add_argument("--lang", choices=list(i18n.LANGS), help=t("opt.lang"))
    p.add_argument("--quarantine-dir", type=Path, default=None, help=t("opt.quarantine_dir"))
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    s = sub.add_parser("scan", help=t("cmd.scan"))
    s.add_argument("targets", nargs="+", metavar="PATH")
    _scan_options(s)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("quick", help=t("cmd.quick"))
    _scan_options(r)
    r.set_defaults(func=cmd_quick)

    w = sub.add_parser("watch", help=t("cmd.watch"))
    w.add_argument("folders", nargs="*", metavar="FOLDER")
    w.add_argument("-i", "--interval", type=float, default=2.0, metavar="SEC", help=t("opt.interval"))
    _engine_options(w)
    w.set_defaults(func=cmd_watch)

    qp = sub.add_parser("quarantine", help=t("cmd.quarantine"))
    qsub = qp.add_subparsers(dest="action", required=True, metavar="ACTION")
    qsub.add_parser("list", help=t("cmd.q_list"))
    rr = qsub.add_parser("restore", help=t("cmd.q_restore"))
    rr.add_argument("id")
    rr.add_argument("--dest", type=Path, default=None)
    dp = qsub.add_parser("delete", help=t("cmd.q_delete"))
    dp.add_argument("id")
    qp.set_defaults(func=cmd_quarantine)

    u = sub.add_parser("update", help=t("cmd.update"))
    u.add_argument("--url", default=updater.DEFAULT_URL)
    u.add_argument("--key", default=None, help=t("opt.key"))
    u.set_defaults(func=cmd_update)

    al = sub.add_parser("allow", help=t("cmd.allow"))
    al.add_argument("files", nargs="+", metavar="FILE")
    al.set_defaults(func=cmd_allow)

    h = sub.add_parser("hash", help=t("cmd.hash"))
    h.add_argument("files", nargs="+", metavar="FILE")
    h.set_defaults(func=cmd_hash)

    i = sub.add_parser("info", help=t("cmd.info"))
    i.set_defaults(func=cmd_info)

    g = sub.add_parser("gui", help=t("cmd.gui"))
    g.set_defaults(func=cmd_gui)
    return p


def _lang_from_argv(argv: list[str]) -> str | None:
    for i, a in enumerate(argv):
        if a == "--lang" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--lang="):
            return a.split("=", 1)[1]
    return None


def _normalize_lang_arg(argv: list[str]) -> list[str]:
    """Lets people write --lang pt-BR or --lang de_DE."""
    out = list(argv)
    for i, a in enumerate(out):
        if a == "--lang" and i + 1 < len(out):
            out[i + 1] = i18n.normalize(out[i + 1]) or out[i + 1]
        elif a.startswith("--lang="):
            out[i] = "--lang=" + (i18n.normalize(a.split("=", 1)[1]) or a.split("=", 1)[1])
    return out


def main(argv: list[str] | None = None) -> int:
    platforms.setup_terminal()
    argv = sys.argv[1:] if argv is None else list(argv)
    i18n.set_lang(i18n.resolve(_lang_from_argv(argv)))
    argv = _normalize_lang_arg(argv)  # before building the parser: help text is translated
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        return 130
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
