"""The copy/paste model — Charon's primary way of moving files.

Ctrl+C on the remote side does not copy bytes.  It records *references*: which
server, which session, which paths.  Ctrl+V on the local side then turns those
references into transfer jobs.  Nothing is fetched until you paste, so copying a
40 GB directory costs nothing and can be abandoned for free.

Two rules keep this honest:

* A clipboard entry is bound to the **session** it came from.  Copy from server
  A, disconnect, connect to server B, paste — and Charon refuses, rather than
  cheerfully fetching whatever happens to live at those paths on the new box.
* Pasting *into* the pane you copied from is rejected, so a stray Ctrl+V can
  never start a server-to-itself copy loop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .model import RemoteEntry

__all__ = ["Side", "Operation", "ClipItem", "TransferClipboard"]


class Side(str, Enum):
    REMOTE = "remote"
    LOCAL = "local"


class Operation(str, Enum):
    COPY = "copy"
    CUT = "cut"     # move: transfer, then delete the source once it verified


@dataclass(frozen=True)
class ClipItem:
    side: Side
    path: str                 # remote POSIX path, or a local filesystem path
    name: str
    is_dir: bool = False
    size: int = 0

    @classmethod
    def from_remote(cls, entry: RemoteEntry, remote_dir: str) -> "ClipItem":
        from .safety import remote_join

        return cls(Side.REMOTE, remote_join(remote_dir, entry.name),
                   entry.name, entry.is_dir, entry.size)

    @classmethod
    def from_local(cls, path: Path) -> "ClipItem":
        try:
            size = path.stat().st_size if path.is_file() else 0
        except OSError:
            size = 0
        return cls(Side.LOCAL, str(path), path.name, path.is_dir(), size)


@dataclass
class TransferClipboard:
    """What is currently "on the clipboard", and where it came from."""

    items: list[ClipItem] = field(default_factory=list)
    operation: Operation = Operation.COPY
    source_side: Side = Side.LOCAL
    session_id: str = ""      # identifies the connection remote items came from
    session_label: str = ""   # human-readable, for the paste banner
    stamped_at: float = 0.0

    # ------------------------------------------------------------- mutate

    def set(self, items: list[ClipItem], operation: Operation,
            session_id: str = "", session_label: str = "") -> None:
        self.items = list(items)
        self.operation = operation
        self.source_side = items[0].side if items else Side.LOCAL
        self.session_id = session_id
        self.session_label = session_label
        self.stamped_at = time.time()

    def clear(self) -> None:
        self.items = []
        self.session_id = ""
        self.session_label = ""
        self.stamped_at = 0.0

    # -------------------------------------------------------------- query

    @property
    def is_empty(self) -> bool:
        return not self.items

    @property
    def total_size(self) -> int:
        return sum(i.size for i in self.items)

    def summary(self) -> str:
        if self.is_empty:
            return "Clipboard is empty"
        verb = "Cut" if self.operation is Operation.CUT else "Copied"
        if len(self.items) == 1:
            return f"{verb} “{self.items[0].name}”"
        return f"{verb} {len(self.items)} items"

    def can_paste_into(self, target: Side, session_id: str) -> tuple[bool, str]:
        """Whether a paste into *target* is allowed, and why not if it isn't."""
        if self.is_empty:
            return False, "There is nothing on the clipboard."
        if self.source_side is target:
            return False, (
                "These items were copied from this same pane. Copy from the other "
                "side to transfer them."
            )
        if Side.REMOTE in (self.source_side, target):
            if not session_id:
                return False, "Connect to a server first."
            if self.source_side is Side.REMOTE and session_id != self.session_id:
                return False, (
                    f"Those items were copied from {self.session_label or 'another server'}, "
                    f"which is no longer the connected session. Copy them again from "
                    f"the current server."
                )
        return True, ""
