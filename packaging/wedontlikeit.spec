# PyInstaller build for WeDontLikeIt.
#   WDLI_TARGET=cli pyinstaller packaging/wedontlikeit.spec   -> command-line tool
#   WDLI_TARGET=gui pyinstaller packaging/wedontlikeit.spec   -> desktop app
# -*- mode: python -*-
import os
import sys

from PyInstaller.utils.hooks import collect_data_files

target = os.environ.get("WDLI_TARGET", "cli")
if target not in ("cli", "gui"):
    raise SystemExit(f"WDLI_TARGET must be 'cli' or 'gui', not {target!r}")
root = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 - SPECPATH is set by PyInstaller
gui = target == "gui"
name = "WeDontLikeIt" if gui else "wedontlikeit-cli"

a = Analysis(  # noqa: F821
    [os.path.join(root, "run_gui.py" if gui else "run.py")],
    pathex=[root],
    datas=collect_data_files("wedontlikeit"),
)

# On Linux, use the system's font libraries instead of bundling the build machine's copies.
# A bundled fontconfig older than the system's /etc/fonts config prints dozens of
# "Fontconfig warning" lines on newer distros (Arch, Fedora...). Every desktop Linux
# has these libraries, and they keep a stable ABI.
SYSTEM_LIBS = ("libfontconfig.", "libfreetype.", "libexpat.", "libpng16.", "libbrotli", "libbz2.")
if sys.platform.startswith("linux"):
    a.binaries = [b for b in a.binaries if not os.path.basename(b[0]).startswith(SYSTEM_LIBS)]

pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz, a.scripts, a.binaries, a.datas, [],
    name=name,
    console=not gui,
    upx=False,
    strip=False,
)
if sys.platform == "darwin" and gui:
    app = BUNDLE(exe, name=f"{name}.app", bundle_identifier="io.github.prmeidiot.wedontlikeit")  # noqa: F821
