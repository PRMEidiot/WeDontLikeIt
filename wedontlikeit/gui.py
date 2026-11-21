"""Desktop app, built on tkinter (ships with Python on Windows, macOS and most Linux distros)."""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, i18n, platforms, updater
from .config import Config
from .i18n import t
from .quarantine import Quarantine
from .scanner import SEV_RANK, Engine, ScanConfig
from .signatures import SignatureDB, add_to_allowlist

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter import font as tkfont
except ImportError:  # pragma: no cover - depends on how Python was installed
    tk = None

# ------------------------------------------------------------------- themes
# PAPER: window background · CARD: tables and inputs · INK: text · ACCENT: logo, labels,
# selected page · RED/AMBER/GREEN: danger, warning, all good.
THEMES = {
    "light": dict(PAPER="#F2EFE7", CARD="#FBFAF6", INK="#1B1A17", INK_HOVER="#3A3731", MUTED="#6F6A60",
                  FAINT="#A7A296", RULE="#DAD4C7", HOVER="#E7E2D6", ACCENT="#B5321C", RED="#B5321C",
                  AMBER="#94600E", GREEN="#2F6A42", DARK=False, MONO=False, BORDER=1, SIZE=0),
    "dark": dict(PAPER="#191816", CARD="#211F1C", INK="#ECE7DC", INK_HOVER="#D2CCBF", MUTED="#A29C90",
                 FAINT="#6B665D", RULE="#36332E", HOVER="#2C2A26", ACCENT="#E0553B", RED="#E8634A",
                 AMBER="#D9A043", GREEN="#78C58E", DARK=True, MONO=False, BORDER=1, SIZE=0),
    "terminal": dict(PAPER="#050805", CARD="#0B110B", INK="#4CF07A", INK_HOVER="#8DFFAA", MUTED="#35B65C",
                     FAINT="#23773D", RULE="#173A22", HOVER="#102216", ACCENT="#4CF07A", RED="#FF5F52",
                     AMBER="#F2C14E", GREEN="#4CF07A", DARK=True, MONO=True, BORDER=1, SIZE=0),
    # amber phosphor; "medium" is light blue so it doesn't vanish into the amber text
    "amber": dict(PAPER="#0A0703", CARD="#120D06", INK="#FFB23E", INK_HOVER="#FFD08A", MUTED="#C98A2E",
                  FAINT="#7E561C", RULE="#3A2A12", HOVER="#21170A", ACCENT="#FFB23E", RED="#FF5F52",
                  AMBER="#8FD3FF", GREEN="#FFB23E", DARK=True, MONO=True, BORDER=1, SIZE=0),
    # for low vision: pure black and white, yellow accent, thicker borders, slightly bigger text
    "contrast": dict(PAPER="#000000", CARD="#000000", INK="#FFFFFF", INK_HOVER="#FFFF00", MUTED="#E6E6E6",
                     FAINT="#8A8A8A", RULE="#FFFFFF", HOVER="#1F3F7A", ACCENT="#FFFF00", RED="#FF7A7A",
                     AMBER="#FFB347", GREEN="#7CFF9B", DARK=True, MONO=False, BORDER=2, SIZE=1),
}
# what people can pick; "auto" follows the operating system
THEME_CHOICES = ("light", "dark", "auto", "terminal", "amber", "contrast")


def resolve_theme(choice: str) -> str:
    if choice != "auto":
        return choice if choice in THEMES else "light"
    if platforms.system_high_contrast():
        return "contrast"
    return "dark" if platforms.system_dark_mode() else "light"


THEME = "light"     # the colors in use
CHOICE = "light"    # what the user picked (may be "auto")
BORDER = 1
PAPER = CARD = INK = INK_HOVER = MUTED = FAINT = RULE = HOVER = ACCENT = RED = AMBER = GREEN = ""
SEV_FG: dict[str, str] = {}


def apply_theme(name: str) -> None:
    """Swaps the module-level colors; the window is rebuilt afterwards."""
    global THEME, CHOICE, BORDER, PAPER, CARD, INK, INK_HOVER, MUTED, FAINT, RULE, HOVER, ACCENT, RED, AMBER
    global GREEN, SEV_FG
    CHOICE = name if name in THEME_CHOICES else "light"
    THEME = resolve_theme(CHOICE)
    th = THEMES[THEME]
    BORDER = th["BORDER"]
    PAPER, CARD, INK, INK_HOVER = th["PAPER"], th["CARD"], th["INK"], th["INK_HOVER"]
    MUTED, FAINT, RULE, HOVER = th["MUTED"], th["FAINT"], th["RULE"], th["HOVER"]
    ACCENT, RED, AMBER, GREEN = th["ACCENT"], th["RED"], th["AMBER"], th["GREEN"]
    SEV_FG = {"high": RED, "medium": AMBER, "low": INK}


apply_theme("light")

# Chinese/Japanese/Korean fonts that come with Windows, macOS and common Linux distros
CJK_FONTS = {
    "ja": {"sans": ["Yu Gothic UI", "Meiryo UI", "Hiragino Sans", "Hiragino Kaku Gothic ProN",
                    "Noto Sans CJK JP", "Noto Sans JP", "IPAexGothic"],
           "serif": ["Yu Mincho", "Hiragino Mincho ProN", "Noto Serif CJK JP", "Noto Serif JP"]},
    "ko": {"sans": ["Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans CJK KR", "Noto Sans KR", "NanumGothic"],
           "serif": ["Batang", "AppleMyungjo", "Noto Serif CJK KR", "Noto Serif KR", "NanumMyeongjo"]},
    "zh": {"sans": ["Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC",
                    "Noto Sans SC", "WenQuanYi Micro Hei", "Source Han Sans SC"],
           "serif": ["SimSun", "Songti SC", "Noto Serif CJK SC", "Noto Serif SC", "Source Han Serif SC"]},
}

POLL_MS = 80
SYSTEM_THEME_CHECK_MS = 30_000
WATCH_INTERVAL = 2.0


def _pick(families: set[str], wanted: list[str], fallback: str) -> str:
    for w in wanted:
        if w in families:
            return w
    return fallback


def _elide(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    keep = max(max_chars - 1, 8)
    return "…" + text[-keep:]


def _short_path(path: str, limit: int = 64) -> str:
    """~/Downloads/x.exe instead of /home/me/Downloads/x.exe, with the middle cut when it's long."""
    home = str(Path.home())
    if path.startswith(home + os.sep) or path.startswith(home + "/"):
        path = "~" + path[len(home):]
    if len(path) <= limit:
        return path
    sep = "\\" if "\\" in path and "/" not in path else "/"
    parts = path.split(sep)
    head, tail = parts[0], parts[-1]
    rest = parts[1:-1]
    kept: list[str] = []
    while rest and len(head) + len(tail) + sum(len(p) + 1 for p in kept) + len(rest[-1]) + 4 <= limit:
        kept.insert(0, rest.pop())
    middle = [head, "…", *kept, tail] if rest else [head, *kept, tail]
    out = sep.join(middle)
    return out if len(out) <= limit + 8 else "…" + path[-limit:]


def _finding_order(d):
    return (-SEV_RANK[d.severity], d.path, d.inner, d.name)


def _short_error(exc: BaseException) -> str:
    text = str(exc).strip().splitlines()
    first = next((line.strip() for line in text if line.strip()), type(exc).__name__)
    return first[:160]


def _ago(iso: str) -> str:
    try:
        then = datetime.fromisoformat(iso)
    except ValueError:
        return ""
    secs = (datetime.now(timezone.utc) - then).total_seconds()
    if secs < 90:
        return t("time.now")
    if secs < 3600:
        return t("time.min", n=int(secs // 60))
    if secs < 86400:
        return t("time.hour", n=int(secs // 3600))
    return t("time.day", n=int(secs // 86400))


# ================================================================== widgets
class FlatButton(tk.Label if tk else object):
    """A label that behaves like a button. tk.Button ignores colors on macOS, so this is used instead."""

    @staticmethod
    def styles():
        return {
            "primary": dict(bg=INK, fg=PAPER, hover=INK_HOVER, border=INK),
            "secondary": dict(bg=CARD, fg=INK, hover=HOVER, border=RULE),
            "danger": dict(bg=CARD, fg=RED, hover=HOVER, border=RULE),
        }

    def __init__(self, parent, text, command, kind="secondary", font=None):
        st = self.styles()[kind]
        super().__init__(parent, text=text, bg=st["bg"], fg=st["fg"], font=font, padx=16, pady=7,
                         cursor="hand2", highlightthickness=BORDER, highlightbackground=st["border"],
                         highlightcolor=st["border"])
        self._st = st
        self._command = command
        self._enabled = True
        self.bind("<Enter>", lambda e: self._enabled and self.configure(bg=st["hover"]))
        self.bind("<Leave>", lambda e: self.configure(bg=st["bg"]))
        self.bind("<ButtonRelease-1>", self._click)

    def _click(self, _e):
        if self._enabled and self._command:
            self._command()

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.configure(fg=self._st["fg"] if enabled else FAINT, cursor="hand2" if enabled else "arrow")
        if BORDER > 1:  # high contrast: a dimmed border too, so "off" never looks like "on"
            border = self._st["border"] if enabled else FAINT
            self.configure(highlightbackground=border, highlightcolor=border)


class LinkButton(tk.Label if tk else object):
    def __init__(self, parent, text, command, font, fg=None, bg=None):
        fg, bg = fg or MUTED, bg or PAPER
        super().__init__(parent, text=text, fg=fg, bg=bg, font=font, cursor="hand2")
        self._font = tkfont.Font(font=font)
        self._ufont = tkfont.Font(font=font)
        self._ufont.configure(underline=True)
        self.bind("<Enter>", lambda e: self.configure(font=self._ufont, fg=INK))
        self.bind("<Leave>", lambda e: self.configure(font=self._font, fg=fg))
        self.bind("<ButtonRelease-1>", lambda e: command())


class Check(tk.Frame if tk else object):
    """A checkbox drawn by hand so it looks the same on every system."""

    def __init__(self, parent, text, value: bool, on_change, font, bg=None, wrap=520):
        bg = bg or PAPER
        super().__init__(parent, bg=bg)
        self.value = value
        self.on_change = on_change
        self.box = tk.Canvas(self, width=16, height=16, bg=bg, highlightthickness=0, cursor="hand2")
        self.box.grid(row=0, column=0, sticky="n", pady=(2, 0))
        self.label = tk.Label(self, text=text, bg=bg, fg=INK, font=font, justify="left",
                              wraplength=wrap, cursor="hand2", anchor="w")
        self.label.grid(row=0, column=1, sticky="w", padx=(10, 0))
        for w in (self, self.box, self.label):
            w.bind("<ButtonRelease-1>", self._toggle)
        self._draw()

    def _draw(self):
        c = self.box
        c.delete("all")
        if self.value:
            c.create_rectangle(1, 1, 15, 15, fill=INK, outline=INK)
            c.create_line(4, 8.5, 7, 11.5, 12.5, 4.5, fill=PAPER, width=2, capstyle="round", joinstyle="round")
        else:
            c.create_rectangle(1, 1, 15, 15, fill=CARD, outline=FAINT)

    def _toggle(self, _e=None):
        self.value = not self.value
        self._draw()
        self.on_change(self.value)


class Progress(tk.Canvas if tk else object):
    """A thin line with a sliding segment: we don't know the file count in advance."""

    def __init__(self, parent, bg=None):
        bg = bg or PAPER
        super().__init__(parent, height=3, bg=bg, highlightthickness=0)
        self._running = False
        self._x = 0.0
        self.bind("<Configure>", lambda e: self._paint())

    def start(self):
        if not self._running:
            self._running = True
            self._tick()

    def stop(self):
        self._running = False
        self._paint()

    def _paint(self):
        self.delete("all")
        w = self.winfo_width()
        if not self._running:  # idle: just a hairline
            self.create_rectangle(0, 1, w, 2, fill=RULE, width=0)
        else:
            self.create_rectangle(0, 0, w, 3, fill=RULE, width=0)
            seg = max(w * 0.22, 60)
            x = (self._x % 1.0) * (w + seg) - seg
            self.create_rectangle(x, 0, x + seg, 3, fill=INK, width=0)

    def _tick(self):
        if not self._running:
            return
        self._x += 0.012
        self._paint()
        self.after(16, self._tick)


def make_icon(size: int = 64) -> "tk.PhotoImage":
    """The app icon: a red 'no' sign, drawn pixel by pixel (no image files needed)."""
    img = tk.PhotoImage(width=size, height=size)
    c, r_out, r_in, half = size / 2, size * 0.47, size * 0.35, size * 0.065
    for y in range(size):
        xs = []
        for x in range(size):
            dx, dy = x + 0.5 - c, y + 0.5 - c
            d = (dx * dx + dy * dy) ** 0.5
            if r_in <= d <= r_out or (d < r_out and abs(dx - dy) / 1.4142 < half):
                xs.append(x)
        for x in xs:
            img.put(RED, (x, y))
    return img


# ====================================================================== app
class App:
    def __init__(self):
        if sys.platform == "win32":  # crisp text on high-DPI screens
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:  # noqa: BLE001
                pass
        self.cfg = Config.load()
        # Before the first-run setup, start in the system's language; afterwards, use the saved one.
        self.detected_lang = None
        if self.cfg.setup_done or os.environ.get("WEDONTLIKEIT_LANG"):
            i18n.set_lang(i18n.resolve(None))
        else:
            self.detected_lang = i18n.system_language()
            i18n.set_lang(self.detected_lang or "en")
        apply_theme(self.cfg.theme)
        if not self.cfg.watch_folders:
            self.cfg.watch_folders = [str(p) for p in platforms.watch_default_paths()]

        self.root = tk.Tk(className="WeDontLikeIt")  # WM_CLASS, matches StartupWMClass in the .desktop file
        self.root.title("WeDontLikeIt")
        self.root.geometry("1060x720")
        self.root.minsize(900, 660)
        self.root.configure(bg=PAPER)
        self._dark_title_bar()
        self._icon = make_icon()
        self.root.iconphoto(True, self._icon)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self._fonts()
        self._style()

        self.events: queue.Queue = queue.Queue()
        self.quarantine = Quarantine()
        self.detections: dict[str, object] = {}   # tree iid -> Detection
        self.scan_stop: threading.Event | None = None
        self.scan_files = 0
        self.scan_state = "idle"                   # idle | running | clean | found | stopped
        self.last_path = ""
        self.watch_stop: threading.Event | None = None
        self.activity: list[tuple[str, str, str]] = []  # (time, text, color)
        self.page = "scan"
        self.db_counts = self._db_counts()

        if self.cfg.setup_done:
            self.build()
        else:
            self.setup_step = 0
            self.setup_opts = {"watch": True, "quick": True}
            self.show_setup()
        self.root.after(POLL_MS, self._drain)
        self.root.after(SYSTEM_THEME_CHECK_MS, self._follow_system_theme)

    # ----------------------------------------------------------- look
    def _fonts(self):
        fam = set(tkfont.families(self.root))
        base = tkfont.nametofont("TkDefaultFont").actual("family")
        mono_base = tkfont.nametofont("TkFixedFont").actual("family")
        sans = _pick(fam, ["Inter", "Segoe UI", "SF Pro Text", "Helvetica Neue", "Noto Sans",
                           "Cantarell", "DejaVu Sans"], base)
        serif = _pick(fam, ["Charter", "Iowan Old Style", "Source Serif 4", "Georgia",
                            "Noto Serif", "DejaVu Serif", "Times New Roman"], sans)
        cjk = CJK_FONTS.get(i18n.current())
        if cjk:  # Latin fonts have no Chinese/Japanese/Korean glyphs; pick the system's own
            sans = _pick(fam, cjk["sans"], sans)
            serif = _pick(fam, cjk["serif"], sans)
        mono = _pick(fam, ["JetBrains Mono", "Cascadia Mono", "SF Mono", "Menlo", "Consolas",
                           "Noto Sans Mono", "DejaVu Sans Mono"], mono_base)
        if THEMES[THEME]["MONO"]:  # the green terminal look: one monospace font for everything
            sans = serif = mono
        z = THEMES[THEME]["SIZE"]
        self.f = {
            "body": (sans, 10 + z),
            "body_b": (sans, 10 + z, "bold"),
            "small": (sans, 9 + z),
            "eyebrow": (sans, 8 + z, "bold"),
            "nav": (sans, 11 + z),
            "nav_on": (sans, 11 + z, "bold"),
            "mark": (serif, 15, "bold"),
            "h1": (serif, 28),
            "h2": (serif, 15 + z),
            "mono": (mono, 9 + z),
            "mono_s": (mono, 8 + z),
        }
        self.mono_char = tkfont.Font(font=self.f["mono"]).measure("0") or 7
        self.families = {"sans": sans, "serif": serif, "mono": mono}

    def _style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("WD.Treeview", background=CARD, fieldbackground=CARD, foreground=INK,
                    rowheight=30, borderwidth=0, relief="flat", font=self.f["body"])
        s.configure("WD.Treeview.Heading", background=CARD, foreground=MUTED, font=self.f["eyebrow"],
                    relief="flat", borderwidth=0, padding=(10, 8))
        s.map("WD.Treeview", background=[("selected", HOVER)], foreground=[("selected", INK)])
        s.map("WD.Treeview.Heading", background=[("active", CARD)], relief=[("active", "flat")])
        s.layout("WD.Treeview", [("WD.Treeview.treearea", {"sticky": "nswe"})])
        s.configure("WD.Vertical.TScrollbar", background=RULE, troughcolor=CARD, bordercolor=CARD,
                    lightcolor=RULE, darkcolor=RULE, arrowcolor=MUTED, gripcount=0, arrowsize=11)
        s.map("WD.Vertical.TScrollbar", background=[("active", FAINT)])
        # colors for Tk's own widgets (the file chooser on Linux, message boxes)
        for opt, val in (("*Background", PAPER), ("*Foreground", INK), ("*activeBackground", HOVER),
                         ("*activeForeground", INK), ("*selectBackground", HOVER), ("*selectForeground", INK),
                         ("*insertBackground", INK), ("*highlightBackground", PAPER), ("*troughColor", CARD),
                         ("*Entry.Background", CARD), ("*Listbox.Background", CARD)):
            self.root.option_add(opt, val, "interactive")
        s.configure("TButton", background=CARD, foreground=INK, bordercolor=RULE, lightcolor=CARD,
                    darkcolor=CARD, focuscolor=RULE)
        s.map("TButton", background=[("active", HOVER)])
        for name in ("TEntry", "TCombobox"):
            s.configure(name, fieldbackground=CARD, foreground=INK, bordercolor=RULE, lightcolor=CARD,
                        darkcolor=CARD, insertcolor=INK, arrowcolor=INK, background=CARD)
        s.configure("TScrollbar", background=RULE, troughcolor=CARD, bordercolor=CARD, arrowcolor=MUTED)
        s.configure("TLabel", background=PAPER, foreground=INK)
        s.configure("TFrame", background=PAPER)

    # ------------------------------------------------------ first run
    SETUP_STEPS = 3

    def show_setup(self):
        """The first-run setup: language, theme, preferences."""
        for w in self.root.winfo_children():
            w.destroy()
        step = self.setup_step
        outer = tk.Frame(self.root, bg=PAPER)
        outer.place(relx=0, rely=0, relwidth=1, relheight=1)

        top = tk.Frame(outer, bg=PAPER)
        top.pack(fill="x", padx=44, pady=(30, 0))
        logo = tk.Canvas(top, width=22, height=22, bg=PAPER, highlightthickness=0)
        logo.create_oval(2, 2, 20, 20, outline=ACCENT, width=2.6)
        logo.create_line(5.6, 5.6, 16.4, 16.4, fill=ACCENT, width=2.6)
        logo.pack(side="left")
        tk.Label(top, text="WeDontLikeIt", bg=PAPER, fg=INK, font=self.f["mark"]).pack(side="left", padx=(10, 0))
        tk.Label(top, text=t("setup.step", n=step + 1, total=self.SETUP_STEPS), bg=PAPER, fg=MUTED,
                 font=self.f["small"]).pack(side="right")

        bar = tk.Frame(outer, bg=PAPER)
        bar.pack(fill="x", padx=44, pady=(18, 0))
        for i in range(self.SETUP_STEPS):
            tk.Frame(bar, bg=ACCENT if i <= step else RULE, height=3).pack(
                side="left", fill="x", expand=True, padx=(0 if i == 0 else 6, 0))

        foot = tk.Frame(outer, bg=PAPER)
        foot.pack(side="bottom", fill="x", padx=44, pady=(0, 30))
        if step == 0:
            LinkButton(foot, t("btn.skip"), lambda: self.finish_setup(skipped=True), self.f["small"]).pack(side="left")
        else:
            FlatButton(foot, t("btn.back"), lambda: self._setup_go(-1), "secondary", self.f["body"]).pack(side="left")
        last = step == self.SETUP_STEPS - 1
        FlatButton(foot, t("btn.finish") if last else t("btn.next"),
                   self.finish_setup if last else (lambda: self._setup_go(1)), "primary",
                   self.f["body_b"]).pack(side="right")

        body = tk.Frame(outer, bg=PAPER)
        body.pack(fill="both", expand=True, padx=44, pady=(44, 0))
        (self._setup_language, self._setup_theme, self._setup_prefs)[step](body)

    def _setup_heading(self, body, title_key, sub_key):
        tk.Label(body, text=t(title_key), bg=PAPER, fg=INK, font=self.f["h1"], anchor="w",
                 justify="left").pack(anchor="w")
        tk.Label(body, text=t(sub_key), bg=PAPER, fg=MUTED, font=self.f["body"], anchor="w", justify="left",
                 wraplength=660).pack(anchor="w", pady=(6, 0))

    def _setup_language(self, body):
        self._setup_heading(body, "setup.welcome_h", "setup.welcome_s")
        tk.Label(body, text=t("set.language"), bg=PAPER, fg=MUTED, font=self.f["small"]).pack(anchor="w", pady=(34, 4))
        self._dropdown(body, [(name, code) for code, name in i18n.LANGS.items()], i18n.current(),
                       self._setup_set_lang)
        if self.detected_lang and self.detected_lang == i18n.current():
            tk.Label(body, text=t("setup.lang_detected"), bg=PAPER, fg=FAINT, font=self.f["small"]).pack(
                anchor="w", pady=(8, 0))
        if i18n.current() not in i18n.HUMAN_TRANSLATED:
            tk.Label(body, text=t("set.lang_note"), bg=PAPER, fg=FAINT, font=self.f["small"], wraplength=520,
                     justify="left").pack(anchor="w", pady=(4, 0))

    def _setup_theme(self, body):
        self._setup_heading(body, "setup.theme_h", "setup.theme_s")
        row = tk.Frame(body, bg=PAPER)
        row.pack(anchor="w", pady=(24, 0))
        for i, name in enumerate(THEME_CHOICES):
            selected = name == CHOICE
            card = tk.Frame(row, bg=PAPER, highlightthickness=2, cursor="hand2",
                            highlightbackground=ACCENT if selected else RULE, highlightcolor=ACCENT)
            card.grid(row=i // 3, column=i % 3, padx=(0, 18), pady=(0, 14), sticky="n")
            if name == "auto":
                preview = self._theme_preview(card, THEMES["light"], THEMES["dark"])
            else:
                preview = self._theme_preview(card, THEMES[name])
            preview.pack()
            label = tk.Label(card, text=("\u2713  " if selected else "") + t(f"theme.{name}"), bg=PAPER,
                             fg=INK, font=self.f["body_b"] if selected else self.f["body"], pady=6, cursor="hand2")
            label.pack(fill="x")
            for w in (card, preview, label, *preview.winfo_children()):
                w.bind("<ButtonRelease-1>", lambda e, n=name: self._setup_set_theme(n))

    def _theme_preview(self, parent, th, th2=None):
        """A tiny drawing of the app in a theme. With th2, the right half uses th2 (for "auto")."""
        w, h, scale = 228, 146, 0.78
        cv = tk.Canvas(parent, width=int(w * scale), height=int(h * scale), bg=th["PAPER"],
                       highlightthickness=0, cursor="hand2")
        self._draw_preview(cv, th, w, h)
        cv.scale("all", 0, 0, scale, scale)
        if th2 is not None:
            # a second canvas over the right half; being its own widget, it clips the drawing for us
            half = tk.Canvas(cv, width=int(w * scale / 2) + 1, height=int(h * scale), bg=th2["PAPER"],
                             highlightthickness=0, cursor="hand2")
            self._draw_preview(half, th2, w, h)
            half.move("all", -w / 2, 0)
            half.scale("all", 0, 0, scale, scale)
            cv.create_window(int(w * scale / 2), 0, window=half, anchor="nw")
        return cv

    def _draw_preview(self, cv, th, w, h):
        cv.create_line(0, 18, w, 18, fill=th["RULE"])
        cv.create_oval(8, 5, 16, 13, outline=th["ACCENT"], width=2)
        cv.create_rectangle(22, 7, 64, 11, fill=th["INK"], outline="")
        cv.create_line(58, 18, 58, h, fill=th["RULE"])
        cv.create_rectangle(0, 28, 3, 40, fill=th["ACCENT"], outline="")
        for k in range(4):
            cv.create_rectangle(10, 32 + k * 14, 44 if k else 38, 36 + k * 14,
                                fill=th["INK"] if k == 0 else th["MUTED"], outline="")
        family = self.families["mono"] if th["MONO"] else self.families["serif"]
        cv.create_text(70, 38, text="Aa", anchor="w", fill=th["RED"], font=(family, 12))
        cv.create_rectangle(70, 54, 180, 57, fill=th["MUTED"], outline="")
        cv.create_rectangle(70, 66, 112, 80, fill=th["INK"], outline="")
        cv.create_rectangle(118, 66, 160, 80, fill=th["CARD"], outline=th["RULE"])
        cv.create_rectangle(70, 92, w - 12, h - 12, fill=th["CARD"], outline=th["RULE"])
        for k, color in enumerate((th["RED"], th["RED"], th["AMBER"])):
            y = 101 + k * 11
            cv.create_rectangle(78, y, 96, y + 3, fill=color, outline="")
            cv.create_rectangle(104, y, 150 + (k % 2) * 20, y + 3, fill=color, outline="")

    def _setup_prefs(self, body):
        self._setup_heading(body, "setup.prefs_h", "setup.prefs_s")
        box = tk.Frame(body, bg=PAPER)
        box.pack(anchor="w", pady=(28, 0))

        def cfg_setter(attr):
            return lambda v: setattr(self.cfg, attr, v)

        def opt_setter(key):
            return lambda v: self.setup_opts.__setitem__(key, v)

        items = [
            (t("set.heuristics"), self.cfg.heuristics, cfg_setter("heuristics")),
            (t("set.archives"), self.cfg.archives, cfg_setter("archives")),
            (t("set.auto_q"), self.cfg.auto_quarantine, cfg_setter("auto_quarantine")),
            (t("set.auto_q_medium"), self.cfg.quarantine_medium, cfg_setter("quarantine_medium")),
            (t("setup.watch"), self.setup_opts["watch"], opt_setter("watch")),
            (t("setup.quick"), self.setup_opts["quick"], opt_setter("quick")),
        ]
        for i, (text, value, setter) in enumerate(items):
            if i == 4:
                tk.Frame(box, bg=RULE, height=1).pack(fill="x", pady=(16, 4))
            Check(box, text, value, setter, self.f["body"], wrap=640).pack(anchor="w", pady=(12, 0))

    def rerun_setup(self):
        if self.scan_state == "running":
            return
        self.setup_step = 0
        self.setup_opts = {"watch": self.watch_stop is None, "quick": False}
        self.detected_lang = i18n.system_language()
        self.show_setup()

    def _setup_go(self, delta):
        self.setup_step = max(0, min(self.SETUP_STEPS - 1, self.setup_step + delta))
        self.show_setup()

    def _setup_set_lang(self, code):
        i18n.set_lang(code)
        self._fonts()
        self._style()
        self.show_setup()

    def _setup_set_theme(self, name):
        apply_theme(name)
        self.root.configure(bg=PAPER)
        self._dark_title_bar()
        self._fonts()
        self._style()
        self.show_setup()

    def finish_setup(self, skipped=False):
        self.cfg.lang = i18n.current()
        self.cfg.theme = CHOICE
        self.cfg.setup_done = True
        self.cfg.save()
        self.page = "scan"
        self.build()
        if not skipped:
            if self.setup_opts["watch"] and self.watch_stop is None:
                self.start_watch()
            if self.setup_opts["quick"]:
                self.quick_scan()

    # ---------------------------------------------------------- layout
    def build(self):
        for w in self.root.winfo_children():
            w.destroy()
        root = self.root
        root.grid_columnconfigure(2, weight=1)
        root.grid_rowconfigure(2, weight=1)

        # header
        header = tk.Frame(root, bg=PAPER, height=58)
        header.grid(row=0, column=0, columnspan=3, sticky="ew")
        header.grid_propagate(False)
        logo = tk.Canvas(header, width=22, height=22, bg=PAPER, highlightthickness=0)
        logo.create_oval(2, 2, 20, 20, outline=ACCENT, width=2.6)
        logo.create_line(5.6, 5.6, 16.4, 16.4, fill=ACCENT, width=2.6)
        logo.place(x=24, rely=0.5, anchor="w")
        tk.Label(header, text="WeDontLikeIt", bg=PAPER, fg=INK, font=self.f["mark"]).place(x=54, rely=0.5, anchor="w")
        self.header_info = tk.Label(header, bg=PAPER, fg=MUTED, font=self.f["small"])
        self.header_info.place(relx=1.0, x=-24, rely=0.5, anchor="e")
        self._update_header()
        tk.Frame(root, bg=RULE, height=1).grid(row=1, column=0, columnspan=3, sticky="ew")

        # sidebar
        side = tk.Frame(root, bg=PAPER, width=208)
        side.grid(row=2, column=0, sticky="ns")
        side.pack_propagate(False)
        tk.Frame(root, bg=RULE, width=1).grid(row=2, column=1, sticky="ns")
        self.nav: dict[str, tuple] = {}
        tk.Frame(side, bg=PAPER, height=18).pack()
        for key in ("scan", "watch", "quarantine", "settings"):
            self._nav_item(side, key)
        self.side_footer = tk.Label(side, bg=PAPER, fg=MUTED, font=self.f["small"], justify="left", anchor="w",
                                    wraplength=160)
        self.side_footer.pack(side="bottom", fill="x", padx=24, pady=22)
        self._update_footer()

        # pages
        self.content = tk.Frame(root, bg=PAPER)
        self.content.grid(row=2, column=2, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)
        self.pages = {
            "scan": self._build_scan(),
            "watch": self._build_watch(),
            "quarantine": self._build_quarantine(),
            "settings": self._build_settings(),
        }
        self.show(self.page)

    def _nav_item(self, side, key):
        row = tk.Frame(side, bg=PAPER, cursor="hand2")
        row.pack(fill="x", pady=1)
        bar = tk.Frame(row, bg=PAPER, width=3)
        bar.pack(side="left", fill="y")
        lbl = tk.Label(row, text=t(f"nav.{key}"), bg=PAPER, fg=MUTED, font=self.f["nav"], anchor="w",
                       padx=21, pady=9, cursor="hand2")
        lbl.pack(side="left", fill="x", expand=True)
        badge = tk.Label(row, text="", bg=PAPER, fg=MUTED, font=self.f["small"], padx=18)
        badge.pack(side="right")

        def enter(_e):
            if self.page != key:
                for w in (row, lbl, badge):
                    w.configure(bg=HOVER)

        def leave(_e):
            if self.page != key:
                for w in (row, lbl, badge):
                    w.configure(bg=PAPER)

        for w in (row, lbl, badge):
            w.bind("<Enter>", enter)
            w.bind("<Leave>", leave)
            w.bind("<ButtonRelease-1>", lambda e, k=key: self.show(k))
        self.nav[key] = (row, bar, lbl, badge)

    def show(self, key):
        self.page = key
        for k, (row, bar, lbl, badge) in self.nav.items():
            on = k == key
            for w in (row, lbl, badge):
                w.configure(bg=CARD if on else PAPER)
            bar.configure(bg=ACCENT if on else PAPER)
            lbl.configure(fg=INK if on else MUTED, font=self.f["nav_on"] if on else self.f["nav"])
        for k, page in self.pages.items():
            if k == key:
                page.grid(row=0, column=0, sticky="nsew")
            else:
                page.grid_remove()
        if key == "quarantine":
            self._refresh_quarantine()
        self._update_badges()

    def _page(self, eyebrow_key):
        page = tk.Frame(self.content, bg=PAPER, padx=40, pady=30)
        page.grid_columnconfigure(0, weight=1)
        tk.Label(page, text=t(eyebrow_key), bg=PAPER, fg=ACCENT, font=self.f["eyebrow"], anchor="w").grid(
            row=0, column=0, sticky="w")
        return page

    def _table(self, parent, columns, widths, stretch_col):
        box = tk.Frame(parent, bg=CARD, highlightthickness=BORDER, highlightbackground=RULE)
        box.grid_columnconfigure(0, weight=1)
        box.grid_rowconfigure(0, weight=1)
        tree = ttk.Treeview(box, columns=[c for c, _ in columns], show="headings", style="WD.Treeview",
                            selectmode="extended")
        for (col, title), width in zip(columns, widths):
            tree.heading(col, text=i18n.upper(title), anchor="w")
            tree.column(col, width=width, anchor="w", stretch=(col == stretch_col))
        sb = ttk.Scrollbar(box, orient="vertical", command=tree.yview, style="WD.Vertical.TScrollbar")
        tree.configure(yscrollcommand=sb.set)
        tree.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=(2, 6))
        sb.grid(row=0, column=1, sticky="ns", pady=6, padx=(0, 4))
        for sev, color in SEV_FG.items():
            tree.tag_configure(sev, foreground=color)
        empty = tk.Label(box, bg=CARD, fg=FAINT, font=self.f["body"])
        return box, tree, empty

    # ------------------------------------------------------------ scan
    def _build_scan(self):
        page = self._page("scan.eyebrow")
        self.scan_h = tk.Label(page, bg=PAPER, fg=INK, font=self.f["h1"], anchor="w")
        self.scan_h.grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.scan_s = tk.Label(page, bg=PAPER, fg=MUTED, font=self.f["body"], anchor="w", justify="left")
        self.scan_s.grid(row=2, column=0, sticky="w", pady=(4, 0))

        actions = tk.Frame(page, bg=PAPER)
        actions.grid(row=3, column=0, sticky="w", pady=(22, 0))
        self.scan_buttons = tk.Frame(actions, bg=PAPER)
        FlatButton(self.scan_buttons, t("btn.quick"), self.quick_scan, "primary", self.f["body_b"]).pack(side="left")
        FlatButton(self.scan_buttons, t("btn.folder"), self.pick_folder, "secondary", self.f["body"]).pack(side="left", padx=(10, 0))
        FlatButton(self.scan_buttons, t("btn.file"), self.pick_file, "secondary", self.f["body"]).pack(side="left", padx=(10, 0))
        self.stop_button = FlatButton(actions, t("btn.stop"), self.stop_scan, "danger", self.f["body_b"])

        self.progress = Progress(page)
        self.progress.grid(row=4, column=0, sticky="ew", pady=(22, 0))
        self.current = tk.Label(page, bg=PAPER, fg=FAINT, font=self.f["mono_s"], anchor="w")
        self.current.grid(row=5, column=0, sticky="ew", pady=(6, 0))

        head = tk.Frame(page, bg=PAPER)
        head.grid(row=6, column=0, sticky="ew", pady=(18, 8))
        tk.Label(head, text=t("findings.title"), bg=PAPER, fg=INK, font=self.f["h2"]).pack(side="left")
        self.findings_count = tk.Label(head, bg=PAPER, fg=MUTED, font=self.f["small"])
        self.findings_count.pack(side="left", padx=(10, 0), pady=(4, 0))

        box, self.tree, self.tree_empty = self._table(
            page,
            [("sev", t("col.severity")), ("threat", t("col.threat")), ("file", t("col.file"))],
            [96, 280, 420], "file")
        box.grid(row=7, column=0, sticky="nsew")
        page.grid_rowconfigure(7, weight=1)
        self.tree_empty.configure(text=t("findings.empty"))
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_result_actions())
        self.tree.bind("<Double-1>", lambda e: self.reveal_selected())

        bottom = tk.Frame(page, bg=PAPER)
        bottom.grid(row=8, column=0, sticky="ew", pady=(12, 0))
        self.btn_q = FlatButton(bottom, t("btn.quarantine"), self.quarantine_selected, "secondary", self.f["body"])
        self.btn_q.pack(side="left")
        self.btn_allow = FlatButton(bottom, t("btn.allow"), self.allow_selected, "secondary", self.f["body"])
        self.btn_allow.pack(side="left", padx=(10, 0))
        self.btn_reveal = FlatButton(bottom, t("btn.reveal"), self.reveal_selected, "secondary", self.f["body"])
        self.btn_reveal.pack(side="left", padx=(10, 0))
        self.note = tk.Label(bottom, bg=PAPER, fg=MUTED, font=self.f["small"], wraplength=420,
                             justify="left", anchor="w")
        self.note.pack(side="left", padx=(16, 0), fill="x", expand=True)

        old = list(self.detections.values())  # after a language switch
        self.detections = {}
        for d in sorted(old, key=_finding_order):
            self._insert_detection(d)
        self._render_scan_state()
        self._update_result_actions()
        return page

    def _render_scan_state(self):
        n = self.scan_files
        st = self.scan_state
        k = self._flagged_count()
        if st == "running":
            h, s = t("scan.running_h"), t("scan.running_s", n=n)
        elif st == "clean":
            h, s = t("scan.clean_h"), t("scan.clean_s", n=n)
        elif st == "found":
            h = t("scan.found_h", n=k)
            s = t("scan.found_s", n=n)
        elif st == "stopped":
            h, s = t("scan.stopped_h"), t("scan.stopped_s", n=n)
        else:
            h, s = t("scan.idle_h"), t("scan.idle_s")
        self.scan_h.configure(text=h, fg=RED if st == "found" else INK)
        self.scan_s.configure(text=s)
        if st == "running":
            self.scan_buttons.pack_forget()
            self.stop_button.pack(side="left")
            self.progress.start()
        else:
            self.stop_button.pack_forget()
            self.scan_buttons.pack(side="left")
            self.progress.stop()
            self.current.configure(text="")
        count = len(self.detections)
        self.findings_count.configure(text=str(count) if count else "")
        if count:
            self.tree_empty.place_forget()
        else:
            self.tree_empty.place(relx=0.5, rely=0.5, anchor="center")

    def _sort_findings(self):
        order = sorted(self.detections.items(), key=lambda kv: _finding_order(kv[1]))
        for idx, (iid, _d) in enumerate(order):
            self.tree.move(iid, "", idx)

    def _flagged_count(self) -> int:
        return len({d.path for d in self.detections.values()})

    def quick_scan(self):
        self.start_scan(platforms.quick_scan_paths())

    def pick_folder(self):
        d = filedialog.askdirectory(parent=self.root, title=t("dialog.folder"))
        if d:
            self.start_scan([Path(d)])

    def pick_file(self):
        f = filedialog.askopenfilename(parent=self.root, title=t("dialog.file"))
        if f:
            self.start_scan([Path(f)])

    def _engine(self) -> Engine:
        excl = [*platforms.system_excludes(), platforms.data_dir()]
        cfg = ScanConfig(heuristics=self.cfg.heuristics, archives=self.cfg.archives,
                         exclude=tuple(str(p) for p in excl))
        return Engine(SignatureDB.default(), cfg)

    def start_scan(self, targets):
        if self.scan_state == "running":
            return
        self.tree.delete(*self.tree.get_children())
        self.detections.clear()
        self.note.configure(text="")
        self.scan_files = 0
        self.scan_state = "running"
        self._render_scan_state()
        self._update_result_actions()
        self.scan_stop = stop = threading.Event()
        engine = self._engine()
        jobs = min(os.cpu_count() or 1, 4)

        def work():
            try:
                res = engine.scan(targets, on_file=lambda p, d: self.events.put(("file", str(p), d)),
                                  jobs=jobs, stop=stop)
                self.events.put(("done", res))
            except Exception as exc:  # noqa: BLE001
                self.events.put(("scan_error", _short_error(exc)))

        threading.Thread(target=work, daemon=True).start()

    def stop_scan(self):
        if self.scan_stop:
            self.scan_stop.set()

    def _insert_detection(self, d):
        label = _short_path(d.path) + (f"  ›  {d.inner}" if d.inner else "")
        iid = self.tree.insert("", "end", values=(i18n.upper(t(f"sev.{d.severity}")), d.name, label),
                               tags=(d.severity,))
        self.detections[iid] = d
        return iid

    def _auto_quarantine(self, path: Path, dets) -> bool:
        if not self.cfg.auto_quarantine or not dets:
            return False
        threshold = SEV_RANK["medium"] if self.cfg.quarantine_medium else SEV_RANK["high"]
        worst = max(dets, key=lambda d: SEV_RANK[d.severity])
        if SEV_RANK[worst.severity] < threshold:
            return False
        try:
            self.quarantine.add(path, worst.name)
            return True
        except OSError:
            return False

    def _selected_paths(self) -> list[str]:
        seen: list[str] = []
        for iid in self.tree.selection():
            p = self.detections[iid].path
            if p not in seen:
                seen.append(p)
        return seen

    def _remove_rows_for(self, paths):
        for iid, d in list(self.detections.items()):
            if d.path in paths:
                self.tree.delete(iid)
                del self.detections[iid]
        self._render_scan_state()
        self._update_result_actions()

    def _update_result_actions(self):
        any_sel = bool(self.tree.selection())
        for b in (self.btn_q, self.btn_allow, self.btn_reveal):
            b.set_enabled(any_sel)

    def quarantine_selected(self):
        paths = self._selected_paths()
        done, failed = [], None
        for p in paths:
            dets = [d for d in self.detections.values() if d.path == p]
            worst = max(dets, key=lambda d: SEV_RANK[d.severity])
            try:
                self.quarantine.add(Path(p), worst.name)
                done.append(p)
            except OSError as exc:
                failed = t("note.failed", name=Path(p).name, err=exc.strerror or exc)
        self._remove_rows_for(done)
        self.note.configure(text=failed or t("note.quarantined", n=len(done)), fg=RED if failed else MUTED)
        self._update_badges()

    def allow_selected(self):
        paths = [p for p in self._selected_paths() if Path(p).exists()]
        add_to_allowlist(paths)
        self._remove_rows_for(paths)
        self.note.configure(text=t("note.allowed", n=len(paths)), fg=MUTED)

    def reveal_selected(self):
        paths = self._selected_paths()
        if paths and Path(paths[0]).exists():
            platforms.reveal(Path(paths[0]))

    # ----------------------------------------------------------- watch
    def _build_watch(self):
        page = self._page("watch.eyebrow")
        self.watch_h = tk.Label(page, bg=PAPER, fg=INK, font=self.f["h1"], anchor="w")
        self.watch_h.grid(row=1, column=0, sticky="w", pady=(6, 0))
        tk.Label(page, text=t("watch.s"), bg=PAPER, fg=MUTED, font=self.f["body"], anchor="w",
                 justify="left", wraplength=620).grid(row=2, column=0, sticky="w", pady=(4, 0))
        actions = tk.Frame(page, bg=PAPER)
        actions.grid(row=3, column=0, sticky="w", pady=(22, 0))
        self.watch_on_btn = FlatButton(actions, t("btn.watch_on"), self.start_watch, "primary", self.f["body_b"])
        self.watch_off_btn = FlatButton(actions, t("btn.watch_off"), self.stop_watch, "secondary", self.f["body_b"])

        tk.Label(page, text=t("watch.folders"), bg=PAPER, fg=INK, font=self.f["h2"]).grid(
            row=4, column=0, sticky="w", pady=(28, 8))
        self.folder_box = tk.Frame(page, bg=CARD, highlightthickness=BORDER, highlightbackground=RULE)
        self.folder_box.grid(row=5, column=0, sticky="ew")
        self.folder_box.grid_columnconfigure(0, weight=1)
        add = tk.Frame(page, bg=PAPER)
        add.grid(row=6, column=0, sticky="w", pady=(10, 0))
        self.add_folder_btn = FlatButton(add, t("btn.add_folder"), self.add_watch_folder, "secondary", self.f["body"])
        self.add_folder_btn.pack(side="left")

        tk.Label(page, text=t("watch.activity"), bg=PAPER, fg=INK, font=self.f["h2"]).grid(
            row=7, column=0, sticky="w", pady=(28, 8))
        logbox = tk.Frame(page, bg=CARD, highlightthickness=BORDER, highlightbackground=RULE)
        logbox.grid(row=8, column=0, sticky="nsew")
        page.grid_rowconfigure(8, weight=1)
        self.log = tk.Text(logbox, bg=CARD, fg=INK, font=self.f["mono"], relief="flat", height=6,
                           padx=14, pady=10, wrap="none", highlightthickness=0, cursor="arrow")
        self.log.pack(fill="both", expand=True)
        for name, color in (("time", FAINT), ("red", RED), ("muted", MUTED), ("ink", INK)):
            self.log.tag_configure(name, foreground=color)
        self._render_folders()
        self._render_log()
        self._render_watch_state()
        return page

    def _render_folders(self):
        for w in self.folder_box.winfo_children():
            w.destroy()
        on = self.watch_stop is not None
        if not self.cfg.watch_folders:
            tk.Label(self.folder_box, text=t("watch.no_folders"), bg=CARD, fg=FAINT, font=self.f["body"],
                     padx=14, pady=12, anchor="w").grid(row=0, column=0, sticky="w")
        for i, folder in enumerate(self.cfg.watch_folders):
            if i:
                tk.Frame(self.folder_box, bg=RULE, height=1).grid(row=2 * i - 1, column=0, columnspan=2, sticky="ew", padx=14)
            tk.Label(self.folder_box, text=_short_path(folder, 80), bg=CARD, fg=INK, font=self.f["mono"], anchor="w",
                     padx=14, pady=10).grid(row=2 * i, column=0, sticky="ew")
            if not on:
                LinkButton(self.folder_box, t("btn.remove"), lambda f=folder: self.remove_watch_folder(f),
                           self.f["small"], bg=CARD).grid(row=2 * i, column=1, padx=14)
        self.add_folder_btn.set_enabled(not on)

    def _render_watch_state(self):
        on = self.watch_stop is not None
        n = len(self.cfg.watch_folders)
        if on:
            self.watch_h.configure(text=t("watch.on_h", n=n), fg=GREEN)
            self.watch_on_btn.pack_forget()
            self.watch_off_btn.pack(side="left")
        else:
            self.watch_h.configure(text=t("watch.off_h"), fg=INK)
            self.watch_off_btn.pack_forget()
            self.watch_on_btn.pack(side="left")
        self._update_footer()

    def _log(self, text, color="ink"):
        self.activity.append((time.strftime("%H:%M:%S"), text, color))
        self.activity = self.activity[-500:]
        self._render_log()

    def _render_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        if not self.activity:
            self.log.insert("end", t("watch.no_activity"), "muted")
        for ts, text, color in self.activity:
            self.log.insert("end", ts + "  ", "time")
            self.log.insert("end", text + "\n", color)
        self.log.see("end")
        self.log.configure(state="disabled")

    def add_watch_folder(self):
        d = filedialog.askdirectory(parent=self.root, title=t("dialog.watch"))
        if d and d not in self.cfg.watch_folders:
            self.cfg.watch_folders.append(d)
            self.cfg.save()
            self._render_folders()
            self._render_watch_state()

    def remove_watch_folder(self, folder):
        self.cfg.watch_folders = [f for f in self.cfg.watch_folders if f != folder]
        self.cfg.save()
        self._render_folders()
        self._render_watch_state()

    def start_watch(self):
        from .monitor import Monitor

        folders = [Path(f) for f in self.cfg.watch_folders if Path(f).is_dir()]
        if not folders:
            self._log(t("watch.no_folders"), "red")
            return
        self.watch_stop = stop = threading.Event()
        engine = self._engine()

        def work():
            try:
                mon = Monitor(engine, folders)
                while not stop.wait(WATCH_INTERVAL):
                    for path, dets in mon.poll():
                        self.events.put(("watch_hit", path, dets))
            except Exception as exc:  # noqa: BLE001
                self.events.put(("watch_error", str(exc)))

        threading.Thread(target=work, daemon=True).start()
        self._log(t("watch.started"), "muted")
        self._render_folders()
        self._render_watch_state()

    def stop_watch(self):
        if self.watch_stop:
            self.watch_stop.set()
            self.watch_stop = None
            self._log(t("watch.stopped"), "muted")
        self._render_folders()
        self._render_watch_state()

    # ------------------------------------------------------ quarantine
    def _build_quarantine(self):
        page = self._page("q.eyebrow")
        self.q_h = tk.Label(page, bg=PAPER, fg=INK, font=self.f["h1"], anchor="w")
        self.q_h.grid(row=1, column=0, sticky="w", pady=(6, 0))
        tk.Label(page, text=t("q.s"), bg=PAPER, fg=MUTED, font=self.f["body"], anchor="w", justify="left",
                 wraplength=620).grid(row=2, column=0, sticky="w", pady=(4, 0))
        box, self.q_tree, self.q_empty = self._table(
            page,
            [("date", t("col.date")), ("threat", t("col.threat")), ("original", t("col.original"))],
            [150, 260, 400], "original")
        box.grid(row=3, column=0, sticky="nsew", pady=(26, 0))
        page.grid_rowconfigure(3, weight=1)
        self.q_tree.bind("<<TreeviewSelect>>", lambda e: self._update_q_actions())
        bottom = tk.Frame(page, bg=PAPER)
        bottom.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        self.btn_restore = FlatButton(bottom, t("btn.restore"), self.restore_selected, "secondary", self.f["body"])
        self.btn_restore.pack(side="left")
        self.btn_delete = FlatButton(bottom, t("btn.delete"), self.delete_selected, "danger", self.f["body"])
        self.btn_delete.pack(side="left", padx=(10, 0))
        self.q_note = tk.Label(bottom, bg=PAPER, fg=MUTED, font=self.f["small"])
        self.q_note.pack(side="left", padx=(16, 0))
        self._refresh_quarantine()
        return page

    def _refresh_quarantine(self):
        items = self.quarantine.list()
        self.q_tree.delete(*self.q_tree.get_children())
        for m in reversed(items):
            date = m.get("date", "")
            try:
                date = datetime.fromisoformat(date).astimezone().strftime("%Y-%m-%d %H:%M")
            except ValueError:
                pass
            self.q_tree.insert("", "end", iid=m["id"], values=(date, m.get("threat", ""), _short_path(m.get("original", ""))))
        n = len(items)
        self.q_h.configure(text=t("q.h_empty") if n == 0 else t("q.h", n=n))
        self.q_empty.configure(text=t("q.h_empty"))
        if n:
            self.q_empty.place_forget()
        else:
            self.q_empty.place(relx=0.5, rely=0.5, anchor="center")
        self._update_q_actions()
        self._update_badges()

    def _update_q_actions(self):
        sel = bool(self.q_tree.selection())
        self.btn_restore.set_enabled(sel)
        self.btn_delete.set_enabled(sel)

    def restore_selected(self):
        ids = list(self.q_tree.selection())
        ok, err = 0, None
        for qid in ids:
            try:
                self.quarantine.restore(qid)
                ok += 1
            except (OSError, ValueError) as exc:
                err = str(exc)
        self._refresh_quarantine()
        self.q_note.configure(text=err or t("q.restored_note", n=ok), fg=RED if err else MUTED)

    def delete_selected(self):
        ids = list(self.q_tree.selection())
        if not ids:
            return
        if not messagebox.askyesno(t("q.confirm_title"), t("q.confirm", n=len(ids)), parent=self.root, icon="warning"):
            return
        for qid in ids:
            try:
                self.quarantine.delete(qid)
            except OSError:
                pass
        self._refresh_quarantine()
        self.q_note.configure(text=t("q.deleted_note", n=len(ids)), fg=MUTED)

    # -------------------------------------------------------- settings
    def _build_settings(self):
        page = self._page("settings.eyebrow")
        tk.Label(page, text=t("settings.h"), bg=PAPER, fg=INK, font=self.f["h1"], anchor="w").grid(
            row=1, column=0, sticky="w", pady=(6, 0))
        body = self._scroll_area(page, row=2)
        body.grid_columnconfigure(1, weight=1)
        r = 0

        def section(title):
            nonlocal r
            top = 0 if r == 0 else 26
            tk.Label(body, text=title, bg=PAPER, fg=INK, font=self.f["h2"], anchor="nw", justify="left").grid(
                row=r, column=0, sticky="nw", padx=(0, 44), pady=(top, 0))
            holder = tk.Frame(body, bg=PAPER)
            holder.grid(row=r, column=1, sticky="nw", pady=(top + 4, 0))
            r += 1
            return holder

        def setter(attr):
            def f(v):
                setattr(self.cfg, attr, v)
                self.cfg.save()
            return f

        s = section(t("set.detection"))
        Check(s, t("set.heuristics"), self.cfg.heuristics, setter("heuristics"), self.f["body"]).pack(anchor="w")
        Check(s, t("set.archives"), self.cfg.archives, setter("archives"), self.f["body"]).pack(anchor="w", pady=(10, 0))

        s = section(t("set.found"))
        Check(s, t("set.auto_q"), self.cfg.auto_quarantine, setter("auto_quarantine"), self.f["body"]).pack(anchor="w")
        Check(s, t("set.auto_q_medium"), self.cfg.quarantine_medium, setter("quarantine_medium"), self.f["body"]).pack(anchor="w", pady=(10, 0))

        s = section(t("set.signatures"))
        self.sig_label = tk.Label(s, bg=PAPER, fg=MUTED, font=self.f["body"], anchor="w")
        self.sig_label.pack(anchor="w")
        self._update_sig_label()
        row = tk.Frame(s, bg=PAPER)
        row.pack(anchor="w", pady=(10, 0))
        self.update_btn = FlatButton(row, t("btn.update"), self.update_signatures, "secondary", self.f["body"])
        self.update_btn.pack(side="left")
        self.update_note = tk.Label(row, bg=PAPER, fg=MUTED, font=self.f["small"])
        self.update_note.pack(side="left", padx=(14, 0))
        keyrow = tk.Frame(s, bg=PAPER)
        keyrow.pack(anchor="w", pady=(10, 0))
        tk.Label(keyrow, text=t("set.key"), bg=PAPER, fg=MUTED, font=self.f["small"]).pack(side="left")
        self.key_var = tk.StringVar(value=self.cfg.abusech_key)
        key = tk.Entry(keyrow, textvariable=self.key_var, width=34, bg=CARD, fg=INK, relief="flat",
                       font=self.f["mono"], insertbackground=INK, highlightthickness=BORDER,
                       highlightbackground=RULE, highlightcolor=INK, show="•")
        key.pack(side="left", padx=(10, 0), ipady=4)
        key.bind("<FocusOut>", lambda e: self._save_key())

        s = section(t("set.appearance"))
        row = tk.Frame(s, bg=PAPER)
        row.pack(anchor="w")
        for col, (label, items, current, pick) in enumerate((
                (t("set.theme"), [(t(f"theme.{k}"), k) for k in THEME_CHOICES], CHOICE, self.set_theme),
                (t("set.language"), [(name, code) for code, name in i18n.LANGS.items()], i18n.current(),
                 self.set_language))):
            cell = tk.Frame(row, bg=PAPER)
            cell.grid(row=0, column=col, sticky="nw", padx=(0, 28))
            tk.Label(cell, text=label, bg=PAPER, fg=MUTED, font=self.f["small"]).pack(anchor="w", pady=(0, 4))
            self._dropdown(cell, items, current, pick)
        self.theme_note = self.lang_note = tk.Label(s, bg=PAPER, fg=MUTED, font=self.f["small"],
                                                    wraplength=440, justify="left")
        self.lang_note.pack(anchor="w", pady=(8, 0) if i18n.current() not in i18n.HUMAN_TRANSLATED else 0)
        if i18n.current() not in i18n.HUMAN_TRANSLATED:
            self.lang_note.configure(text=t("set.lang_note"))

        s = section(t("set.about"))
        tk.Label(s, text=f"WeDontLikeIt {__version__}  ·  {platforms.system_name()}", bg=PAPER, fg=INK,
                 font=self.f["body"], anchor="w").pack(anchor="w")
        drow = tk.Frame(s, bg=PAPER)
        drow.pack(anchor="w", pady=(6, 0))
        tk.Label(drow, text=_short_path(str(platforms.data_dir()), 52), bg=PAPER, fg=MUTED, font=self.f["mono"]).pack(side="left")
        LinkButton(drow, t("btn.open_data"), self.open_data_dir, self.f["small"]).pack(side="left", padx=(12, 0))
        LinkButton(s, t("set.rerun"), self.rerun_setup, self.f["small"]).pack(anchor="w", pady=(10, 0))
        return page

    def _save_key(self):
        self.cfg.abusech_key = self.key_var.get().strip()
        self.cfg.save()

    def _update_sig_label(self):
        h, p = self.db_counts
        self.sig_label.configure(text=t("set.sig_count", h=h, p=p))

    def update_signatures(self):
        self._save_key()
        self.update_btn.set_enabled(False)
        self.update_note.configure(text=t("set.updating"), fg=MUTED)
        key = self.cfg.abusech_key or os.environ.get("ABUSECH_AUTH_KEY") or None

        def work():
            try:
                new, total = updater.update(platforms.user_signature_dir(), updater.DEFAULT_URL, key)
                self.events.put(("update_ok", new, total))
            except Exception as exc:  # noqa: BLE001
                self.events.put(("update_error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def open_data_dir(self):
        d = platforms.data_dir()
        d.mkdir(parents=True, exist_ok=True)
        platforms.reveal(d)

    def _scroll_area(self, page, row):
        """A frame that scrolls vertically when its content doesn't fit."""
        page.grid_rowconfigure(row, weight=1)
        holder = tk.Frame(page, bg=PAPER)
        holder.grid(row=row, column=0, sticky="nsew", pady=(26, 0))
        holder.grid_columnconfigure(0, weight=1)
        holder.grid_rowconfigure(0, weight=1)
        canvas = tk.Canvas(holder, bg=PAPER, highlightthickness=0, bd=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        bar = ttk.Scrollbar(holder, orient="vertical", command=canvas.yview, style="WD.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=bar.set)
        inner = tk.Frame(canvas, bg=PAPER)
        win = canvas.create_window(0, 0, window=inner, anchor="nw")

        def refresh(_e=None):
            canvas.configure(scrollregion=(0, 0, inner.winfo_reqwidth(), inner.winfo_reqheight()))
            canvas.itemconfigure(win, width=canvas.winfo_width())
            if inner.winfo_reqheight() > canvas.winfo_height() + 1:
                bar.grid(row=0, column=1, sticky="ns")
            else:
                bar.grid_remove()
                canvas.yview_moveto(0)

        inner.bind("<Configure>", refresh)
        canvas.bind("<Configure>", refresh)

        def wheel(e):
            if not bar.winfo_ismapped():
                return
            if e.num == 4 or e.delta > 0:
                canvas.yview_scroll(-3 if e.num in (4, 5) else -max(1, abs(e.delta) // 40), "units")
            else:
                canvas.yview_scroll(3 if e.num in (4, 5) else max(1, abs(e.delta) // 40), "units")

        def bind_wheel(_e):
            canvas.bind_all("<MouseWheel>", wheel)   # Windows, macOS
            canvas.bind_all("<Button-4>", wheel)     # Linux
            canvas.bind_all("<Button-5>", wheel)

        def unbind_wheel(_e):
            for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                canvas.unbind_all(seq)

        holder.bind("<Enter>", bind_wheel)
        holder.bind("<Leave>", unbind_wheel)
        return inner

    def _dropdown(self, parent, items, current, on_pick):
        """A button that opens a menu. items: [(label, value)]."""
        label = next((lb for lb, v in items if v == current), items[0][0])
        button = FlatButton(parent, f"{label}   \u25be", None, "secondary", self.f["body"])
        button.pack(anchor="w")
        menu = tk.Menu(self.root, tearoff=0, bg=CARD, fg=INK, activebackground=HOVER, activeforeground=INK,
                       relief="flat", bd=1, font=self.f["body"])
        for lb, value in items:
            mark = "\u2713  " if value == current else "     "
            menu.add_command(label=mark + lb, command=lambda v=value: on_pick(v))
        button._command = lambda: menu.tk_popup(button.winfo_rootx(), button.winfo_rooty() + button.winfo_height())
        return button

    def set_theme(self, name):
        if name == CHOICE:
            return
        if self.scan_state == "running":
            self.theme_note.configure(text=t("set.busy"), fg=RED)
            return
        self.cfg.theme = name
        self.cfg.save()
        apply_theme(name)
        self.root.configure(bg=PAPER)
        self._dark_title_bar()
        self._fonts()
        self._style()
        self.build()

    def _follow_system_theme(self):
        """With "auto", switch when the operating system flips between light and dark."""
        try:
            if CHOICE == "auto" and self.scan_state != "running" and resolve_theme("auto") != THEME:
                apply_theme("auto")
                self.root.configure(bg=PAPER)
                self._dark_title_bar()
                self._fonts()
                self._style()
                if self.cfg.setup_done:
                    self.build()
                else:
                    self.show_setup()
        finally:
            self.root.after(SYSTEM_THEME_CHECK_MS, self._follow_system_theme)

    def _dark_title_bar(self):
        """Windows 10/11 draw the title bar themselves; ask for a dark one in the dark themes."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            value = ctypes.c_int(1 if THEMES[THEME]["DARK"] else 0)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (newer, then older builds)
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), 4) == 0:
                    break
        except Exception:  # noqa: BLE001
            pass

    def set_language(self, code):
        if code == i18n.current():
            return
        if self.scan_state == "running":
            self.lang_note.configure(text=t("set.busy"), fg=RED)
            return
        self.cfg.lang = code
        self.cfg.save()
        i18n.set_lang(code)
        self._fonts()
        self._style()
        self.build()

    # ---------------------------------------------------------- shared
    def _db_counts(self):
        try:
            db = SignatureDB.default()
            return len(db.hashes), len(db.patterns)
        except (OSError, ValueError):
            return 0, 0

    def _update_header(self):
        n = self.db_counts[0]
        sigs = t("header.sigs", n=n)
        self.header_info.configure(text=f"{sigs}   ·   v{__version__}")

    def _update_footer(self):
        lines = [t("side.last_scan")]
        if self.cfg.last_scan:
            res = t("side.clean") if self.cfg.last_scan_result == "clean" else t("side.threats")
            sep = {"ja": "\u3001", "zh": "\uff0c"}.get(i18n.current(), ", ")
            lines.append(f"{_ago(self.cfg.last_scan)}{sep}{res}")
        else:
            lines.append(t("side.never"))
        lines.append("")
        lines.append(t("side.watch_on") if self.watch_stop is not None else t("side.watch_off"))
        self.side_footer.configure(text="\n".join(lines))

    def _update_badges(self):
        n = len(self.quarantine.list())
        self.nav["quarantine"][3].configure(text=str(n) if n else "")
        k = self._flagged_count()
        self.nav["scan"][3].configure(text=str(k) if k else "", fg=RED)

    def _drain(self):
        updated_path = None
        try:
            for _ in range(5000):
                ev = self.events.get_nowait()
                kind = ev[0]
                if kind == "file":
                    _, path, dets = ev
                    self.scan_files += 1
                    updated_path = path
                    if dets:
                        if self._auto_quarantine(Path(path), dets):
                            self.note.configure(text=t("note.auto"), fg=MUTED)
                            self._update_badges()
                        else:
                            for d in dets:
                                self._insert_detection(d)
                elif kind == "done":
                    res = ev[1]
                    if res.cancelled:
                        self.scan_state = "stopped"
                    else:
                        self.scan_state = "found" if self.detections else "clean"
                        self.cfg.last_scan = datetime.now(timezone.utc).isoformat(timespec="seconds")
                        self.cfg.last_scan_result = "threats" if res.detections else "clean"
                        self.cfg.save()
                    self.scan_stop = None
                    self._sort_findings()
                    self._render_scan_state()
                    self._update_footer()
                    self._update_badges()
                elif kind == "scan_error":
                    self.scan_state = "stopped"
                    self.scan_stop = None
                    self._render_scan_state()
                    self.note.configure(text=ev[1], fg=RED)
                elif kind == "watch_hit":
                    _, path, dets = ev
                    worst = max(dets, key=lambda d: SEV_RANK[d.severity])
                    moved = self._auto_quarantine(path, dets)
                    key = "watch.hit_moved" if moved else "watch.hit"
                    self._log(t(key, threat=worst.name, file=_short_path(str(path), 56)), "red")
                    if not moved:
                        for d in dets:
                            self._insert_detection(d)
                        if self.scan_state != "running":
                            self.scan_state = "found"
                            self._render_scan_state()
                    self._update_badges()
                elif kind == "watch_error":
                    self._log(ev[1], "red")
                    self.stop_watch()
                elif kind == "update_ok":
                    self.db_counts = self._db_counts()
                    self.update_btn.set_enabled(True)
                    self.update_note.configure(text=t("set.updated", new=ev[1], total=ev[2]), fg=GREEN)
                    self._update_sig_label()
                    self._update_header()
                elif kind == "update_error":
                    self.update_btn.set_enabled(True)
                    self.update_note.configure(text=t("set.update_failed", err=ev[1])[:120], fg=RED)
        except queue.Empty:
            pass
        if self.scan_state == "running":
            self.scan_s.configure(text=t("scan.running_s", n=self.scan_files))
            if updated_path:
                width = max(self.current.winfo_width(), 300)
                self.current.configure(text=_elide(_short_path(updated_path, 400), width // self.mono_char))
            count = len(self.detections)
            self.findings_count.configure(text=str(count) if count else "")
            if count:
                self.tree_empty.place_forget()
        self.root.after(POLL_MS, self._drain)
        self.root.after(SYSTEM_THEME_CHECK_MS, self._follow_system_theme)

    def close(self):
        if self.scan_stop:
            self.scan_stop.set()
        if self.watch_stop:
            self.watch_stop.set()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main() -> None:
    if tk is None:
        sys.exit("error: tkinter is not available. Install it (e.g. `sudo pacman -S tk`, "
                 "`sudo apt install python3-tk`) or use the command line.")
    App().run()


if __name__ == "__main__":
    main()
