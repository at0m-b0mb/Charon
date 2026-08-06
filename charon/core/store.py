"""Persistence for saved sites and settings.

Both files are plain JSON and are written with owner-only permissions.  They
deliberately contain **no secret material** — a saved site records the username
and where its password lives, never the password — so leaking one of these files
exposes your server inventory, which is bad, but not your access to it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..paths import default_download_dir, harden, settings_file, sites_file
from .model import Site
from .policy import Policy
from .secretstore import StorageMode

log = logging.getLogger(__name__)

SCHEMA = 1


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    harden(tmp)
    tmp.replace(path)
    harden(path)


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError) as exc:
        log.warning("could not read %s (%s); starting from defaults", path.name, exc)
        return {}


class SiteStore:
    """The saved-connections list."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or sites_file()
        self.sites: list[Site] = []
        self.load()

    def load(self) -> None:
        data = _read_json(self.path)
        self.sites = []
        for raw in data.get("sites", []):
            try:
                self.sites.append(Site.from_json(raw))
            except (TypeError, ValueError) as exc:
                log.warning("skipping malformed saved site: %s", exc)

    def save(self) -> None:
        _write_json(self.path, {"schema": SCHEMA,
                                "sites": [s.to_json() for s in self.sites]})

    def add(self, site: Site) -> Site:
        self.sites = [s for s in self.sites if s.name != site.name]
        self.sites.append(site)
        self.save()
        return site

    def remove(self, name: str) -> bool:
        before = len(self.sites)
        self.sites = [s for s in self.sites if s.name != name]
        if len(self.sites) != before:
            self.save()
            return True
        return False

    def get(self, name: str) -> Optional[Site]:
        return next((s for s in self.sites if s.name == name), None)

    def by_recency(self) -> list[Site]:
        return sorted(self.sites, key=lambda s: (-s.last_used, s.name.lower()))


@dataclass
class Settings:
    """Everything the user can toggle, plus the security policy."""

    policy: Policy = field(default_factory=Policy)
    storage_mode: StorageMode = StorageMode.KEYCHAIN
    download_dir: str = ""
    show_hidden: bool = False
    private_downloads: bool = True
    confirm_delete: bool = True
    theme: str = "dark"
    window_geometry: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.storage_mode, str):
            self.storage_mode = StorageMode(self.storage_mode)
        if not self.download_dir:
            self.download_dir = str(default_download_dir())

    # ------------------------------------------------------------------ io

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Settings":
        path = path or settings_file()
        data = _read_json(path)
        try:
            settings = cls(
                policy=Policy.from_json(data.get("policy", {})),
                storage_mode=StorageMode(data.get("storage_mode", StorageMode.KEYCHAIN.value)),
                download_dir=data.get("download_dir", ""),
                show_hidden=bool(data.get("show_hidden", False)),
                private_downloads=bool(data.get("private_downloads", True)),
                confirm_delete=bool(data.get("confirm_delete", True)),
                theme=str(data.get("theme", "dark")),
                window_geometry=str(data.get("window_geometry", "")),
            )
        except ValueError as exc:
            log.warning("settings file is invalid (%s); using defaults", exc)
            settings = cls()
        settings._path = path  # type: ignore[attr-defined]
        return settings

    def save(self, path: Optional[Path] = None) -> None:
        path = path or getattr(self, "_path", None) or settings_file()
        _write_json(Path(path), {
            "schema": SCHEMA,
            "policy": self.policy.to_json(),
            "storage_mode": self.storage_mode.value,
            "download_dir": self.download_dir,
            "show_hidden": self.show_hidden,
            "private_downloads": self.private_downloads,
            "confirm_delete": self.confirm_delete,
            "theme": self.theme,
            "window_geometry": self.window_geometry,
        })
