"""Heuristics for executables (PE, ELF, Mach-O), Office documents and file names."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from pathlib import PurePath


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str  # high | medium | low


ENTROPY_THRESHOLD = 7.2      # bits per byte (max 8.0); above this it's compressed or encrypted
ENTROPY_SAMPLE = 1 << 20     # entropy is computed on at most 1 MB

DOC_EXTS = {
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".rtf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".csv",
}
EXEC_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".jar", ".msi", ".ps1", ".lnk", ".dll", ".cpl", ".sh", ".command", ".app",
}
RTLO = "‮"  # right-to-left override: "invoice‮fdp.exe" is displayed as "invoiceexe.pdf"

MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
MACHO_FAT = b"\xca\xfe\xba\xbe"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
VBA_PROJECT_WIDE = "_VBA_PROJECT".encode("utf-16-le")
MACRO_AUTOEXEC = (b"autoopen", b"auto_open", b"document_open", b"workbook_open",
                  b"autoexec", b"autoclose", b"auto_close", b"document_close")

PACKER_SECTIONS = {
    b"UPX0": "UPX", b"UPX1": "UPX", b"UPX2": "UPX",
    b".aspack": "ASPack", b".MPRESS1": "MPRESS", b".MPRESS2": "MPRESS",
    b".petite": "Petite", b"nsp0": "NsPack", b"nsp1": "NsPack",
    b".themida": "Themida", b".winlice": "Themida",
    b".vmp0": "VMProtect", b".vmp1": "VMProtect",
    b".enigma1": "Enigma", b".enigma2": "Enigma", b"PEC2": "PECompact", b"pec1": "PECompact",
}
INJECTION_APIS = (b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
                  b"NtUnmapViewOfSection", b"QueueUserAPC", b"SetThreadContext")
HOOK_APIS = (b"SetWindowsHookExA", b"SetWindowsHookExW")
KEY_APIS = (b"GetAsyncKeyState", b"GetKeyboardState")

SCN_EXEC = 0x20000000
SCN_WRITE = 0x80000000


# ------------------------------------------------------------------ helpers
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    if len(data) > ENTROPY_SAMPLE:  # sample the start, middle and end
        third = ENTROPY_SAMPLE // 3
        mid = len(data) // 2
        data = data[:third] + data[mid:mid + third] + data[-third:]
    n = len(data)
    ent = 0.0
    for byte in range(256):
        c = data.count(byte)
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    off = struct.unpack_from("<I", data, 0x3C)[0]
    return off + 24 <= len(data) and data[off:off + 4] == b"PE\0\0"


def exec_type(data: bytes) -> str | None:
    magic = data[:4]
    if magic == b"\x7fELF":
        return "ELF"
    if is_pe(data):
        return "PE"
    if magic in MACHO_MAGICS:
        return "MachO"
    # macOS universal binary; Java .class files share the magic but have a large version number
    if magic == MACHO_FAT and len(data) >= 8 and 0 < int.from_bytes(data[4:8], "big") <= 20:
        return "MachO"
    return None


# ----------------------------------------------------------------- analyses
def name_findings(name: str, kind: str | None) -> list[Finding]:
    out: list[Finding] = []
    if RTLO in name:
        out.append(Finding("Heuristic.RTLOFilename", "medium"))
    suffixes = [s.lower().strip() for s in PurePath(name).suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXEC_EXTS and suffixes[-2] in DOC_EXTS:
        out.append(Finding("Heuristic.DoubleExtension", "medium"))
    if kind and suffixes and suffixes[-1] in DOC_EXTS:
        out.append(Finding(f"Heuristic.Disguised{kind}", "medium"))
    return out


def analyze_pe(data: bytes) -> list[Finding]:
    out: list[Finding] = []
    off = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, off + 6)[0]
    opt_size = struct.unpack_from("<H", data, off + 20)[0]
    table = off + 24 + opt_size

    packers: set[str] = set()
    rwx = encrypted = False
    for i in range(min(nsec, 96)):
        s = table + 40 * i
        if s + 40 > len(data):
            break
        name = data[s:s + 8].rstrip(b"\0")
        raw_size, raw_ptr = struct.unpack_from("<II", data, s + 16)
        chars = struct.unpack_from("<I", data, s + 36)[0]
        if name in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[name])
        is_exec = bool(chars & SCN_EXEC)
        if is_exec and chars & SCN_WRITE:
            rwx = True
        if is_exec and raw_size >= 4096 and raw_ptr < len(data):
            if entropy(data[raw_ptr:raw_ptr + raw_size]) >= ENTROPY_THRESHOLD:
                encrypted = True

    for p in sorted(packers):
        out.append(Finding(f"Heuristic.PE.Packer.{p}", "low"))
    if rwx and not packers:
        out.append(Finding("Heuristic.PE.WritableCode", "low"))
    if encrypted:
        out.append(Finding("Heuristic.PE.EncryptedCode", "low"))

    if sum(api in data for api in INJECTION_APIS) >= 3:
        out.append(Finding("Heuristic.PE.ProcessInjection", "medium"))
    if any(a in data for a in HOOK_APIS) and any(a in data for a in KEY_APIS):
        out.append(Finding("Heuristic.PE.Keylogger", "low"))
    return out


def _elf_exec_sections(data: bytes):
    """[(offset, size)] of executable sections, or None when there is no section table."""
    if len(data) < 0x40:
        return None
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
        shentsize, shnum = struct.unpack_from(end + "HH", data, 0x3A)
    else:
        shoff = struct.unpack_from(end + "I", data, 0x20)[0]
        shentsize, shnum = struct.unpack_from(end + "HH", data, 0x2E)
    if shnum == 0 or shoff == 0 or shentsize < (0x40 if is64 else 0x28):
        return None
    out = []
    for i in range(min(shnum, 512)):
        s = shoff + i * shentsize
        if s + shentsize > len(data):
            break
        sh_type = struct.unpack_from(end + "I", data, s + 4)[0]
        if is64:
            flags, = struct.unpack_from(end + "Q", data, s + 8)
            off, size = struct.unpack_from(end + "QQ", data, s + 0x18)
        else:
            flags, = struct.unpack_from(end + "I", data, s + 8)
            off, size = struct.unpack_from(end + "II", data, s + 0x10)
        if flags & 0x4 and sh_type != 8:  # SHF_EXECINSTR and not SHT_NOBITS
            out.append((off, size))
    return out


def analyze_elf(data: bytes) -> list[Finding]:
    if b"UPX!" in data[:ENTROPY_SAMPLE]:
        return [Finding("Heuristic.ELF.Packer.UPX", "low")]
    sections = _elf_exec_sections(data)
    if sections is None:  # no section table: typical of a packed binary
        if entropy(data) >= ENTROPY_THRESHOLD:
            return [Finding("Heuristic.ELF.Packed", "low")]
        return []
    for off, size in sections:
        if size >= 4096 and entropy(data[off:off + size]) >= ENTROPY_THRESHOLD:
            return [Finding("Heuristic.ELF.EncryptedCode", "low")]
    return []


def macro_findings(data: bytes) -> list[Finding]:
    """Old Office files (.doc/.xls) and the vbaProject.bin inside .docm/.xlsm are OLE files."""
    if not data.startswith(OLE_MAGIC) or VBA_PROJECT_WIDE not in data:
        return []
    low = data.lower()
    if any(k in low for k in MACRO_AUTOEXEC):
        return [Finding("Office.AutoExecMacro", "medium")]
    return [Finding("Office.Macro", "low")]


def analyze(name: str, data: bytes) -> list[Finding]:
    kind = exec_type(data)
    out = name_findings(name, kind)
    if kind == "PE":
        out += analyze_pe(data)
    elif kind == "ELF":
        out += analyze_elf(data)
    elif kind == "MachO" and b"UPX!" in data[:ENTROPY_SAMPLE]:
        out.append(Finding("Heuristic.MachO.Packer.UPX", "low"))
    out += macro_findings(data)
    return out
