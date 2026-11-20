"""Scanning inside archives (.zip and zip-based formats: .docx/.xlsx/.pptx, .jar, .apk, .odt...),
with zip-bomb protection."""

from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from .heuristics import EXEC_EXTS, Finding

if TYPE_CHECKING:
    from .scanner import Detection, Engine

MAX_DEPTH = 3                   # zip inside a zip inside a zip
MAX_MEMBERS = 2000
MAX_MEMBER_SIZE = 64 << 20
MAX_TOTAL_SIZE = 256 << 20
BOMB_RATIO = 100                # uncompressed / compressed
BOMB_MIN_SIZE = 32 << 20

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")


def is_zip(data: bytes) -> bool:
    return data[:4] in ZIP_MAGICS


def scan_zip(engine: "Engine", outer: str, data: bytes, inner: str, depth: int) -> list["Detection"]:
    from .scanner import Detection

    dets: list[Detection] = []

    def add(member: str, f: Finding):
        dets.append(Detection(outer, f.name, "heuristic", f.severity, member))

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return dets

    total = 0
    with zf:
        for info in zf.infolist()[:MAX_MEMBERS]:
            if info.is_dir():
                continue
            member = f"{inner}!{info.filename}" if inner else info.filename
            suffix = PurePosixPath(info.filename).suffix.lower()

            if info.flag_bits & 0x1:  # password protected: the content can't be read
                if suffix in EXEC_EXTS:
                    add(member, Finding("Heuristic.EncryptedZipWithExecutable", "medium"))
                continue
            if (info.compress_size and info.file_size >= BOMB_MIN_SIZE
                    and info.file_size / info.compress_size >= BOMB_RATIO):
                add(member, Finding("Heuristic.ZipBomb", "medium"))
                break
            if info.file_size > MAX_MEMBER_SIZE:
                continue
            total += info.file_size
            if total > MAX_TOTAL_SIZE:
                break
            try:
                content = zf.read(info)
            except Exception:  # noqa: BLE001 - unsupported compression, bad CRC, etc.
                continue
            dets += engine.scan_bytes(outer, content, member, depth + 1)
    return dets
