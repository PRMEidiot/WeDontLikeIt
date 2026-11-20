"""Quarantine: locks suspicious files away so they can't run.

The file is moved into the quarantine folder, XOR-obfuscated (so it can't be
executed or picked up again by another antivirus) and made readable by the owner
only. A .json file next to it keeps the original path so it can be restored.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import platforms

XOR_KEY = 0xA5
_TABLE = bytes(b ^ XOR_KEY for b in range(256))
CHUNK = 1 << 20


def _copy_xor(src: Path, dst: Path) -> str:
    """Copies src to dst applying XOR; returns the SHA-256 of the original content."""
    sha = hashlib.sha256()
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
        while chunk := fin.read(CHUNK):
            sha.update(chunk)
            fout.write(chunk.translate(_TABLE))
    return sha.hexdigest()


class Quarantine:
    def __init__(self, directory: Path | None = None):
        self.dir = Path(directory) if directory else platforms.quarantine_dir()

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def add(self, path: Path, threat: str) -> str:
        self._ensure()
        path = Path(path).resolve()
        qid = uuid.uuid4().hex[:12]
        blob = self.dir / f"{qid}.bin"
        mode = path.stat().st_mode & 0o777
        digest = _copy_xor(path, blob)
        try:
            path.unlink()  # on Windows this fails if another program has the file open
        except OSError:
            blob.unlink()
            raise
        meta = {
            "id": qid,
            "original": str(path),
            "threat": threat,
            "sha256": digest,
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": mode,
        }
        (self.dir / f"{qid}.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return qid

    def list(self) -> list[dict]:
        if not self.dir.exists():
            return []
        items = []
        for f in self.dir.glob("*.json"):
            try:
                items.append(json.loads(f.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(items, key=lambda m: m.get("date", ""))

    def get(self, qid: str) -> dict:
        return json.loads((self.dir / f"{qid}.json").read_text(encoding="utf-8"))

    def restore(self, qid: str, dest: Path | None = None) -> Path:
        meta = self.get(qid)
        blob = self.dir / f"{qid}.bin"
        target = Path(dest) if dest else Path(meta["original"])
        if target.exists():
            raise FileExistsError(f"a file already exists at {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(blob, "rb") as fin, open(target, "xb") as fout:
            while chunk := fin.read(CHUNK):
                fout.write(chunk.translate(_TABLE))
        os.chmod(target, (meta.get("mode") or 0o600) & ~0o111)  # restored without execute permission
        blob.unlink()
        (self.dir / f"{qid}.json").unlink()
        return target

    def delete(self, qid: str) -> None:
        (self.dir / f"{qid}.bin").unlink()
        (self.dir / f"{qid}.json").unlink()
