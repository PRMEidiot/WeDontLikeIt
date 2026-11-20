"""User settings, stored as JSON in the data folder."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields

from . import platforms


@dataclass
class Config:
    lang: str = "en"
    heuristics: bool = True
    archives: bool = True
    auto_quarantine: bool = False          # quarantine high-severity detections
    quarantine_medium: bool = False        # ...and medium ones too
    watch_folders: list[str] = field(default_factory=list)
    last_scan: str = ""                    # ISO timestamp
    last_scan_result: str = ""             # "clean" | "threats" | ""
    abusech_key: str = ""

    @classmethod
    def load(cls) -> "Config":
        try:
            raw = json.loads(platforms.config_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in raw.items() if k in known})

    def save(self) -> None:
        path = platforms.config_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
