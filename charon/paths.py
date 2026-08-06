"""Cross-platform locations for Charon's config, state and secrets.

Everything Charon writes lives under a single per-user directory that is created
with owner-only permissions (0700 on POSIX).  Nothing is ever written to a
world-readable location, and nothing is written outside the user's profile.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from .version import APP_ID

_WINDOWS = sys.platform.startswith("win")
_MACOS = sys.platform == "darwin"


def _base_dir() -> Path:
    override = os.environ.get("CHARON_HOME")
    if override:
        return Path(override).expanduser()
    if _WINDOWS:
        root = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(root) / "Charon"
    if _MACOS:
        return Path.home() / "Library" / "Application Support" / "Charon"
    root = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(root) / APP_ID


def harden(path: Path) -> Path:
    """Restrict *path* to the owner.  No-op on Windows (ACL inherited from the
    user profile directory, which is already owner-scoped)."""
    if _WINDOWS:
        return path
    try:
        if path.is_dir():
            os.chmod(path, stat.S_IRWXU)  # 0700
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass
    return path


def config_dir() -> Path:
    path = _base_dir()
    path.mkdir(parents=True, exist_ok=True)
    return harden(path)


def sites_file() -> Path:
    return config_dir() / "sites.json"


def settings_file() -> Path:
    return config_dir() / "settings.json"


def vault_file() -> Path:
    return config_dir() / "vault.charon"


def known_hosts_file() -> Path:
    return config_dir() / "known_hosts"


def pinned_certs_file() -> Path:
    return config_dir() / "pinned_certs.json"


def log_file() -> Path:
    return config_dir() / "charon.log"


def default_download_dir() -> Path:
    candidate = Path.home() / "Downloads"
    return candidate if candidate.is_dir() else Path.home()
