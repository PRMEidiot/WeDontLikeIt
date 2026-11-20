"""Everything that differs between Windows, macOS and Linux lives here."""

from __future__ import annotations

import os
import re
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
def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _kde_dark() -> bool | None:
    """KDE stores the window background color in kdeglobals; a dark one means a dark scheme."""
    cfg = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "kdeglobals"
    try:
        section = None
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line
            elif section == "[Colors:Window]" and line.startswith("BackgroundNormal="):
                r, g, b = (int(x) for x in line.split("=", 1)[1].split(",")[:3])
                return (0.299 * r + 0.587 * g + 0.114 * b) < 128
    except (OSError, ValueError):
        pass
    return None


def system_dark_mode() -> bool | None:
    """True for a dark system theme, False for light, None when we can't tell."""
    if IS_WINDOWS:
        try:
            import winreg

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return value == 0
        except OSError:
            return None
    if IS_MAC:
        return "dark" in _run(["defaults", "read", "-g", "AppleInterfaceStyle"]).lower()
    # Linux: the freedesktop portal (GNOME, KDE, most desktops), then GNOME, then KDE's own config
    out = _run(["gdbus", "call", "--session", "--dest", "org.freedesktop.portal.Desktop",
                "--object-path", "/org/freedesktop/portal/desktop",
                "--method", "org.freedesktop.portal.Settings.Read",
                "org.freedesktop.appearance", "color-scheme"])
    m = re.search(r"uint32 (\d)", out)
    if m and m.group(1) in "12":
        return m.group(1) == "1"  # 1 = prefer dark, 2 = prefer light, 0 = no preference
    out = _run(["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"])
    if "dark" in out:
        return True
    kde = _kde_dark()
    if kde is not None:
        return kde
    if "default" in out or "light" in out:
        return False
    return None


def system_high_contrast() -> bool:
    """Windows has a system-wide high contrast mode; follow it when it's on."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        class HIGHCONTRAST(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwFlags", ctypes.c_uint), ("lpszDefaultScheme", ctypes.c_wchar_p)]

        hc = HIGHCONTRAST()
        hc.cbSize = ctypes.sizeof(HIGHCONTRAST)
        if ctypes.windll.user32.SystemParametersInfoW(0x0042, hc.cbSize, ctypes.byref(hc), 0):
            return bool(hc.dwFlags & 0x1)
    except Exception:  # noqa: BLE001
        pass
    return False


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
