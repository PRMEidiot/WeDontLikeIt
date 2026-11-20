"""Scan engine."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Iterator

from . import archives, heuristics, scripts
from .signatures import SignatureDB

CHUNK = 1 << 20
SEVERITIES = ("low", "medium", "high")
SEV_RANK = {s: i + 1 for i, s in enumerate(SEVERITIES)}


@dataclass
class Detection:
    path: str
    name: str
    method: str      # hash | pattern | heuristic | yara
    severity: str    # high | medium | low
    inner: str = ""  # path inside an archive, if any

    @property
    def label(self) -> str:
        return f"{self.path}!{self.inner}" if self.inner else self.path


@dataclass
class ScanResult:
    scanned: int = 0
    skipped: int = 0
    cancelled: bool = False
    errors: list[tuple[str, str]] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)

    @property
    def infected_files(self) -> int:
        return len({d.path for d in self.detections})


@dataclass(frozen=True)
class ScanConfig:
    heuristics: bool = True
    archives: bool = True
    yara_paths: tuple[str, ...] = ()
    max_size: int = 512 << 20     # bigger files are skipped
    full_limit: int = 64 << 20    # up to this size a file is analyzed fully in memory
    exclude: tuple[str, ...] = ()


def load_yara(paths: Iterable[str]):
    import yara  # type: ignore  # optional: pip install yara-python

    files: dict[str, str] = {}
    for rp in paths:
        p = Path(rp)
        targets = sorted([*p.rglob("*.yar"), *p.rglob("*.yara")]) if p.is_dir() else [p]
        for t in targets:
            files[str(t)] = str(t)
    if not files:
        raise ValueError("no YARA rules found")
    return yara.compile(filepaths=files)


class Engine:
    def __init__(self, db: SignatureDB, cfg: ScanConfig = ScanConfig()):
        self.db = db
        self.cfg = cfg
        self.yara = load_yara(cfg.yara_paths) if cfg.yara_paths else None
        self._exclude = [Path(e).resolve() for e in cfg.exclude]

    # --------------------------------------------------------------- files
    def iter_files(self, targets: Iterable[Path], errors: list) -> Iterator[Path]:
        def onerror(exc: OSError):
            errors.append((exc.filename or "?", exc.strerror or str(exc)))

        for target in targets:
            target = Path(target)
            try:
                rt = target.resolve()
            except OSError as exc:
                errors.append((str(target), str(exc)))
                continue
            # whatever the user asked for explicitly is scanned, even inside an excluded path
            excl = [e for e in self._exclude if not (e == rt or e in rt.parents)]
            if target.is_symlink():
                continue
            if target.is_file():
                yield target
                continue
            if not target.is_dir():
                errors.append((str(target), "not found"))
                continue
            for root, dirs, files in os.walk(target, onerror=onerror):
                rp = Path(root)
                dirs[:] = [d for d in dirs if not _skip_dir(rp / d, excl)]
                for name in files:
                    p = rp / name
                    if p.is_symlink() or not p.is_file():
                        continue  # skip links, FIFOs, sockets and devices
                    if excl and _under(p, excl):
                        continue
                    yield p

    # ---------------------------------------------------------------- scan
    def scan_path(self, path: Path) -> list[Detection]:
        path = Path(path)
        if path.stat().st_size <= self.cfg.full_limit:
            return self.scan_bytes(str(path), path.read_bytes())
        return self._scan_stream(path)

    def scan_bytes(self, outer: str, data: bytes, inner: str = "", depth: int = 0) -> list[Detection]:
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.db.allow:
            return []
        name = PurePosixPath(inner.rsplit("!", 1)[-1]).name if inner else Path(outer).name
        dets: list[Detection] = []

        def add(n: str, method: str, sev: str):
            dets.append(Detection(outer, n, method, sev, inner))

        if digest in self.db.hashes:
            add(self.db.hashes[digest], "hash", "high")
        for n in sorted(self.db.match_patterns(data)):
            add(n, "pattern", "high")
        if self.yara is not None:
            for m in self.yara.match(data=data, timeout=30):
                add(f"YARA.{m.rule}", "yara", _yara_sev(m))
        if self.cfg.heuristics:
            for f in heuristics.analyze(name, data):
                add(f.name, "heuristic", f.severity)
            for f in scripts.analyze(data):
                add(f.name, "heuristic", f.severity)
        if self.cfg.archives and depth < archives.MAX_DEPTH and archives.is_zip(data):
            dets += archives.scan_zip(self, outer, data, inner, depth)
        return dets

    def _scan_stream(self, path: Path) -> list[Detection]:
        """Big files are read in chunks (hash + patterns + header)."""
        sha = hashlib.sha256()
        overlap = max(self.db.max_pattern_len - 1, 0)
        tail = head = b""
        hits: set[str] = set()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                if len(head) < 65536:
                    head += chunk[: 65536 - len(head)]
                sha.update(chunk)
                window = tail + chunk
                hits |= self.db.match_patterns(window)
                tail = window[-overlap:] if overlap else b""
        digest = sha.hexdigest()
        if digest in self.db.allow:
            return []
        sp = str(path)
        dets = []
        if digest in self.db.hashes:
            dets.append(Detection(sp, self.db.hashes[digest], "hash", "high"))
        dets += [Detection(sp, n, "pattern", "high") for n in sorted(hits)]
        if self.yara is not None:
            dets += [Detection(sp, f"YARA.{m.rule}", "yara", _yara_sev(m)) for m in self.yara.match(sp, timeout=60)]
        if self.cfg.heuristics:
            for f in heuristics.name_findings(path.name, heuristics.exec_type(head)):
                dets.append(Detection(sp, f.name, "heuristic", f.severity))
        return dets

    def scan(self, targets: Iterable[Path], on_file: Callable | None = None, jobs: int = 1,
             stop=None) -> ScanResult:
        """Scans files and folders. ``on_file(path, detections)`` runs for every file scanned;
        ``stop`` is an optional threading.Event that cancels the scan."""
        result = ScanResult()

        def collect(item):
            path, status, payload = item
            if status == "skip":
                result.skipped += 1
            elif status == "error":
                result.errors.append((path, payload))
            else:
                result.scanned += 1
                result.detections.extend(payload)
                if on_file:
                    on_file(Path(path), payload)

        def stopped() -> bool:
            if stop is not None and stop.is_set():
                result.cancelled = True
            return result.cancelled

        files = self.iter_files(targets, result.errors)
        if jobs <= 1:
            for p in files:
                if stopped():
                    break
                collect(_scan_one(self, str(p)))
            return result

        with ProcessPoolExecutor(jobs, initializer=_init_worker, initargs=(self.db, self.cfg)) as ex:
            pending: set = set()
            for p in files:
                if stopped():
                    break
                pending.add(ex.submit(_worker_scan, str(p)))
                if len(pending) >= jobs * 4:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for fut in done:
                        collect(fut.result())
            if stopped():
                for fut in pending:
                    fut.cancel()
            for fut in wait(pending).done:
                if not fut.cancelled():
                    collect(fut.result())
        return result


# ------------------------------------------------------------------ helpers
def _under(p: Path, excl: list[Path]) -> bool:
    try:
        rp = p.resolve()
    except OSError:
        return True
    return any(rp == e or e in rp.parents for e in excl)


def _skip_dir(d: Path, excl: list[Path]) -> bool:
    if d.is_symlink() or (hasattr(d, "is_junction") and d.is_junction()):
        return True
    return bool(excl) and _under(d, excl)


def _yara_sev(match) -> str:
    meta = getattr(match, "meta", {}) or {}
    sev = str(meta.get("severity", meta.get("severidade", "high"))).lower()
    sev = {"alta": "high", "media": "medium", "baixa": "low"}.get(sev, sev)
    return sev if sev in SEV_RANK else "high"


def _scan_one(engine: Engine, path: str):
    try:
        if os.stat(path).st_size > engine.cfg.max_size:
            return path, "skip", None
        return path, "ok", engine.scan_path(Path(path))
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop the scan
        return path, "error", f"{type(exc).__name__}: {exc}"


_WORKER: Engine | None = None


def _init_worker(db: SignatureDB, cfg: ScanConfig) -> None:
    global _WORKER
    _WORKER = Engine(db, cfg)


def _worker_scan(path: str):
    return _scan_one(_WORKER, path)
