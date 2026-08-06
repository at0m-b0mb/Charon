"""Defensive handling of names and paths that come from a remote server.

A directory listing is *attacker-controlled data*.  A hostile or compromised
server can answer ``LIST`` with entries such as ``../../.ssh/authorized_keys``,
``/etc/cron.d/backdoor``, ``C:\\Windows\\System32\\evil.dll`` or a name
containing a NUL or a newline.  A client that joins those names straight onto a
local download directory writes outside it — this is the "zip-slip" class of
bug, and it is the single most common way a file-transfer client gets owned.

Every remote name that becomes part of a local path must pass through
:func:`safe_local_name`, and every resulting path through :func:`resolve_within`.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from pathlib import Path, PurePosixPath

__all__ = [
    "UnsafeNameError",
    "safe_local_name",
    "resolve_within",
    "normalise_remote",
    "remote_join",
    "is_hidden",
]


class UnsafeNameError(ValueError):
    """A remote-supplied name could not be made safe for local use."""


# Reserved device names on Windows.  Creating "CON" or "LPT1" on Windows does
# not create a file, it talks to a device, so these are rejected everywhere in
# order to keep behaviour identical across platforms.
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# Characters that are illegal in a Windows filename, plus the path separators
# and the C0 control range (which includes NUL, CR and LF).
_ILLEGAL = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_local_name(name: str) -> str:
    """Return *name* reduced to a single, safe local filename component.

    Raises :class:`UnsafeNameError` if nothing safe remains.  The result never
    contains a path separator, never resolves to a parent directory, and is
    always usable on Windows, macOS and Linux alike.
    """
    if not isinstance(name, str):
        raise UnsafeNameError("remote name is not a string")

    # Normalise first: a server can send "..%c0%af" style overlong or
    # decomposed forms that only become ".." after NFC composition.
    cleaned = unicodedata.normalize("NFC", name)

    # Strip any directory component the server tried to smuggle in, for both
    # separator conventions, before anything else looks at the value.
    cleaned = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = _ILLEGAL.sub("_", cleaned)

    # Trailing dots and spaces are silently dropped by Windows, which would let
    # "evil.exe." and "evil.exe" collide.  Drop them ourselves, visibly.
    cleaned = cleaned.strip().rstrip(". ")

    if cleaned in ("", ".", ".."):
        raise UnsafeNameError(f"remote name {name!r} is not a usable filename")
    if cleaned.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
        cleaned = "_" + cleaned
    if len(cleaned.encode("utf-8")) > 255:
        stem, dot, ext = cleaned.rpartition(".")
        head = (stem or cleaned).encode("utf-8")[:200].decode("utf-8", "ignore")
        cleaned = f"{head}.{ext}" if dot else head
    return cleaned


def resolve_within(base: Path, *parts: str) -> Path:
    """Join remote-supplied *parts* under *base* and prove the result stays there.

    Each part is passed through :func:`safe_local_name`, then the fully resolved
    path is re-checked against the resolved base — belt and braces, because
    symlinks already on disk can also redirect a write outside *base*.
    """
    base_resolved = Path(base).resolve()
    candidate = base_resolved
    for part in parts:
        candidate = candidate / safe_local_name(part)

    # strict=False: the leaf will not exist yet on a download.
    final = candidate.resolve(strict=False)
    if final != base_resolved and base_resolved not in final.parents:
        raise UnsafeNameError(
            f"path {'/'.join(parts)!r} escapes the destination directory"
        )
    return final


def normalise_remote(path: str) -> str:
    """Collapse a remote POSIX path without ever letting it climb above root."""
    if not path:
        return "/"
    collapsed = posixpath.normpath(path.replace("\\", "/"))
    if not collapsed.startswith("/"):
        collapsed = "/" + collapsed
    # normpath turns "/.." into "/" already, but "//foo" is implementation
    # defined in POSIX, so squash any leading double slash explicitly.
    while collapsed.startswith("//"):
        collapsed = collapsed[1:]
    return collapsed


def remote_join(base: str, name: str) -> str:
    """Append a single listing entry to a remote directory path.

    The name is stripped to one component first, so a server answering with
    ``../../etc`` cannot walk the *remote* cursor out of the directory the user
    thinks they are browsing.
    """
    leaf = name.replace("\\", "/").rsplit("/", 1)[-1]
    if leaf in ("", ".", ".."):
        raise UnsafeNameError(f"remote listing entry {name!r} is not browsable")
    return normalise_remote(str(PurePosixPath(normalise_remote(base)) / leaf))


def is_hidden(name: str) -> bool:
    return name.startswith(".")
