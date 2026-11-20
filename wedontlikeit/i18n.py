"""Translations.

English is the default. Pick another language with --lang, the WEDONTLIKEIT_LANG
environment variable, or the Settings page in the app.

Each language is a JSON file in ``locales/``. A value is either a string or, for text
that depends on a number, an object with plural forms ("one", "few", "many", "other").
Integers passed to ``t()`` are formatted the way that language writes numbers.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from importlib import resources

# code -> name in its own language (this is also the order shown in the app)
LANGS = {
    "en": "English",
    "pt": "Português (Brasil)",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
    "it": "Italiano",
    "nl": "Nederlands",
    "pl": "Polski",
    "ru": "Русский",
    "tr": "Türkçe",
    "ja": "日本語",
    "ko": "한국어",
    "zh": "简体中文",
}
CJK = {"ja", "ko", "zh"}
HUMAN_TRANSLATED = {"en", "pt"}  # the others were machine translated; corrections welcome

_GROUP_SEP = {
    "en": ",", "ja": ",", "ko": ",", "zh": ",",
    "pt": ".", "es": ".", "de": ".", "it": ".", "nl": ".", "tr": ".",
    "fr": " ", "ru": " ", "pl": " ",
}

_current = "en"


@lru_cache(maxsize=None)
def _load(code: str) -> dict:
    path = resources.files("wedontlikeit") / "locales" / f"{code}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def plural_category(code: str, n: int) -> str:
    """CLDR plural rules for the languages we ship."""
    n = abs(int(n))
    if code in CJK:
        return "other"
    if code in ("fr", "pt"):
        return "one" if n in (0, 1) else "other"
    if code in ("ru", "pl"):
        if code == "pl" and n == 1:
            return "one"
        if code == "ru" and n % 10 == 1 and n % 100 != 11:
            return "one"
        if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
            return "few"
        return "many"
    return "one" if n == 1 else "other"


PLURAL_FORMS = {
    **{c: {"one", "other"} for c in LANGS},
    **{c: {"other"} for c in CJK},
    "ru": {"one", "few", "many"},
    "pl": {"one", "few", "many"},
}


def num(n: int, code: str | None = None) -> str:
    code = code or _current
    return f"{int(n):,}".replace(",", _GROUP_SEP.get(code, ","))


def upper(text: str, code: str | None = None) -> str:
    """str.upper() that gets the Turkish dotted i right."""
    if (code or _current) == "tr":
        text = text.replace("i", "İ")
    return text.upper()


def set_lang(code: str) -> None:
    global _current
    _current = code if code in LANGS else "en"


def current() -> str:
    return _current


def normalize(value: str | None) -> str | None:
    """'pt_BR.UTF-8', 'pt-br' and 'pt' all become 'pt'. Unknown languages become None."""
    if not value:
        return None
    value = value.strip().lower().replace("_", "-")
    if value in LANGS:
        return value
    base = value.split(".", 1)[0].split("-", 1)[0]
    return base if base in LANGS else None


def resolve(cli_value: str | None) -> str:
    """--lang beats the environment variable, which beats the saved setting. Default: English."""
    for value in (cli_value, os.environ.get("WEDONTLIKEIT_LANG")):
        code = normalize(value)
        if code:
            return code
    try:
        from .config import Config

        code = normalize(Config.load().lang)
        if code:
            return code
    except Exception:  # noqa: BLE001
        pass
    return "en"


def _lookup(key: str):
    value = _load(_current).get(key)
    if value is None and _current != "en":
        return _load("en").get(key), "en"
    return value, _current


def t(key: str, **kw) -> str:
    value, code = _lookup(key)
    if value is None:
        return key
    if isinstance(value, dict):
        count = kw.get("count", kw.get("n", 0))
        value = value.get(plural_category(code, count)) or value.get("other") or next(iter(value.values()))
    fmt = {k: (num(v, code) if isinstance(v, int) and not isinstance(v, bool) else v) for k, v in kw.items()}
    return value.format(**fmt) if fmt else value


def keys(code: str = "en") -> set[str]:
    return set(_load(code))


def raw(code: str) -> dict:
    return _load(code)
