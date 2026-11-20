"""Signature database: SHA-256 hashes, byte patterns and the allowlist."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from . import platforms

_HEX = set("0123456789abcdef")


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _parse_hash_lines(text: str, default_name: str):
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        digest = parts[0].lower()
        if len(digest) != 64 or not set(digest) <= _HEX:
            raise ValueError(f"invalid hash on line {lineno}: {parts[0]!r}")
        yield digest, (parts[1].strip() if len(parts) > 1 else default_name)


@dataclass
class SignatureDB:
    hashes: dict[str, str] = field(default_factory=dict)       # sha256 -> name
    patterns: dict[bytes, str] = field(default_factory=dict)   # bytes -> name
    allow: set[str] = field(default_factory=set)               # trusted sha256
    _regex: re.Pattern | None = field(default=None, repr=False, compare=False)

    # ---------------------------------------------------------------- load
    def load_hashes(self, text: str, default_name: str = "Unknown") -> None:
        for digest, name in _parse_hash_lines(text, default_name):
            self.hashes[digest] = name

    def load_allow(self, text: str) -> None:
        for digest, _ in _parse_hash_lines(text, ""):
            self.allow.add(digest)

    def load_patterns(self, text: str) -> None:
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                name, hexstr = line.split(maxsplit=1)
                pattern = bytes.fromhex(hexstr)
            except ValueError as exc:
                raise ValueError(f"invalid pattern on line {lineno}") from exc
            if len(pattern) < 4:
                raise ValueError(f"pattern too short on line {lineno} (minimum is 4 bytes)")
            self.patterns[pattern] = name
        self._regex = None

    def load_dir(self, directory: Path) -> None:
        """Loads every *.hashes and *.patterns file in a folder."""
        directory = Path(directory)
        for f in sorted(directory.glob("*.hashes")):
            self.load_hashes(f.read_text(encoding="utf-8"), default_name=f.stem)
        for f in sorted(directory.glob("*.patterns")):
            self.load_patterns(f.read_text(encoding="utf-8"))

    @classmethod
    def default(cls, extra_dirs=(), user: bool = True) -> "SignatureDB":
        db = cls()
        data = resources.files("wedontlikeit") / "data"
        db.load_hashes((data / "signatures.hashes").read_text(encoding="utf-8"))
        db.load_patterns((data / "signatures.patterns").read_text(encoding="utf-8"))
        if user:
            udir = platforms.user_signature_dir()
            if udir.is_dir():
                db.load_dir(udir)
            allow = platforms.allowlist_file()
            if allow.is_file():
                db.load_allow(allow.read_text(encoding="utf-8"))
        for d in extra_dirs:
            db.load_dir(Path(d))
        return db

    # --------------------------------------------------------------- query
    @property
    def max_pattern_len(self) -> int:
        return max(map(len, self.patterns), default=0)

    def match_patterns(self, data: bytes) -> set[str]:
        if not self.patterns:
            return set()
        if self._regex is None:
            # longest first, so a short pattern never hides a longer one that starts the same way
            ordered = sorted(self.patterns, key=len, reverse=True)
            self._regex = re.compile(b"|".join(re.escape(p) for p in ordered))
        return {self.patterns[m.group()] for m in self._regex.finditer(data)}


def add_to_allowlist(paths) -> list[tuple[Path, str]]:
    """Marks files as trusted (false positives). Returns [(path, sha256)]."""
    dest = platforms.allowlist_file()
    dest.parent.mkdir(parents=True, exist_ok=True)
    done = []
    with open(dest, "a", encoding="utf-8") as f:
        for p in paths:
            p = Path(p)
            digest = sha256_file(p)
            f.write(f"{digest} {p.name}\n")
            done.append((p, digest))
    return done
