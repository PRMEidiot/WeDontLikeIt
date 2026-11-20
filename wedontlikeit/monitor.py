"""Real-time protection by polling.

Works the same on Windows, macOS and Linux with no dependencies: on every tick it
compares modification time and size and scans the files that changed.
"""

from __future__ import annotations

import time
from pathlib import Path

from .scanner import Detection, Engine, _scan_one


class Monitor:
    def __init__(self, engine: Engine, paths, settle: float = 1.0):
        self.engine = engine
        self.paths = [Path(p) for p in paths]
        self.settle = settle  # wait until a file stops changing (download in progress)
        self.snapshot = self._snap()

    def _snap(self) -> dict[str, tuple[int, int]]:
        snap: dict[str, tuple[int, int]] = {}
        for p in self.engine.iter_files(self.paths, []):
            try:
                st = p.stat()
            except OSError:
                continue
            snap[str(p)] = (st.st_mtime_ns, st.st_size)
        return snap

    def poll(self) -> list[tuple[Path, list[Detection]]]:
        now = time.time()
        new = self._snap()
        changed, pending = [], []
        for p, sig in new.items():
            if self.snapshot.get(p) == sig:
                continue
            (pending if now - sig[0] / 1e9 < self.settle else changed).append(p)
        for p in pending:  # still being written: check again on the next tick
            if p in self.snapshot:
                new[p] = self.snapshot[p]
            else:
                del new[p]
        self.snapshot = new

        results = []
        for p in changed:
            _, status, dets = _scan_one(self.engine, p)
            if status == "ok" and dets:
                results.append((Path(p), dets))
        return results
