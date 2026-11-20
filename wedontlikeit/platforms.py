"""Everything that differs between Windows, macOS and Linux lives here."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

APP = "WeDontLikeIt"
IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def system_name() -> str:
    if IS_WINDOWS:
        return "Windows"
    if IS_MAC:
        return "macOS"
    if IS_LINUX:
        return "Linux"
    return sys.platform


# ------------------------------------------------------------------ folders
def data_dir() -> Path:
    """Per-user data folder (quarantine, downloaded signatures, settings)."""
    override = os.environ.get("WEDONTLIKEIT_HOME")
    if override:
        return Path(override)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / APP
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "wedontlikeit"


def quarantine_dir() -> Path:
    return data_dir() / "quarantine"


def user_signature_dir() -> Path:
    return data_dir() / "signatures"


def allowlist_file() -> Path:
    return data_dir() / "allowlist.hashes"


def config_file() -> Path:
    return data_dir() / "config.json"


def _xdg_user_dir(key: str, fallback: str) -> Path:
    """Reads ~/.config/user-dirs.dirs, since Linux folders may be localized."""
    cfg = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "user-dirs.dirs"
    try:
        for line in cfg.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"XDG_{key}_DIR="):
                value = line.split("=", 1)[1].strip().strip('"')
                return Path(value.replace("$HOME", str(Path.home())))
    except OSError:
        pass
    return Path.home() / fallback


def downloads_dir() -> Path:
    return _xdg_user_dir("DOWNLOAD", "Downloads") if IS_LINUX else Path.home() / "Downloads"


def desktop_dir() -> Path:
    return _xdg_user_dir("DESKTOP", "Desktop") if IS_LINUX else Path.home() / "Desktop"


def _existing(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir() and p not in out:
            out.append(p)
    return out


def quick_scan_paths() -> list[Path]:
    """Where malware usually lands, or installs itself to start automatically."""
    home = Path.home()
    cands = [downloads_dir(), desktop_dir()]
    if IS_WINDOWS:
        env = os.environ.get
        cands.append(Path(env("TEMP") or home / "AppData" / "Local" / "Temp"))
        if env("APPDATA"):
            cands.append(Path(env("APPDATA")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if env("PROGRAMDATA"):
            cands.append(Path(env("PROGRAMDATA")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    elif IS_MAC:
        cands += [
            Path("/private/tmp"),
            home / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
    else:
        cands += [
            Path("/tmp"),
            Path("/var/tmp"),
            Path("/dev/shm"),
            home / ".config" / "autostart",
            home / ".local" / "bin",
        ]
    return _existing(cands)


def watch_default_paths() -> list[Path]:
    return _existing([downloads_dir(), desktop_dir()])


def system_excludes() -> list[Path]:
    """Pseudo filesystems that should never be walked (they hang or make no sense)."""
    if IS_LINUX:
        return [Path(p) for p in ("/proc", "/sys", "/dev", "/run")]
    if IS_MAC:
        return [Path("/dev"), Path("/System/Volumes/VM"), Path("/private/var/vm")]
    return []


# ----------------------------------------------------------------- terminal
def setup_terminal() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if IS_WINDOWS and sys.stdout is not None and sys.stdout.isatty():
        os.system("")  # turns on ANSI colors in the Windows 10+ console


def use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


# ---------------------------------------------------------------- desktop
def reveal(path: Path) -> None:
    """Shows a file in Explorer / Finder / the file manager."""
    path = Path(path)
    if IS_WINDOWS:
        subprocess.Popen(["explorer", "/select,", str(path)])
    elif IS_MAC:
        subprocess.Popen(["open", "-R", str(path)])
    else:
        target = path if path.is_dir() else path.parent
        subprocess.Popen(["xdg-open", str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
