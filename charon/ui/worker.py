"""The background session worker.

Every call that can touch the network runs here, on its own thread, so the
window never freezes mid-handshake.  Results come back as Qt signals, which are
delivered to the GUI thread automatically.

The one rule this file exists to enforce: **no dialog is ever opened from the
worker thread.**  When a connection needs a human trust decision the worker
stops, emits :attr:`SessionWorker.trust_required`, and waits to be told what to
do.  Qt is not thread-safe for widgets, and — more to the point — a security
prompt that can be raised from a background thread is a security prompt that can
be raced.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from ..core.model import RemoteEntry
from ..core.safety import remote_join
from ..core.session import PolicyBlocked, Session
from ..core.transfer import Conflict, TransferJob
from ..core.transport import (
    AuthFailed,
    CertChanged,
    CertUnknown,
    HostKeyChanged,
    HostKeyUnknown,
    Transport,
    TransportError,
    TrustRequired,
)

log = logging.getLogger(__name__)


class SessionWorker(QObject):
    """Owns the browsing transport.  Lives on a worker thread."""

    connected = pyqtSignal(object, str)          # SecurityState, cwd
    disconnected = pyqtSignal()
    connect_failed = pyqtSignal(str, str)        # title, detail
    trust_required = pyqtSignal(object, str, str)  # HostIdentity, kind, message
    listed = pyqtSignal(str, object)             # path, list[RemoteEntry]
    failed = pyqtSignal(str)                     # user-facing error
    status = pyqtSignal(str)                     # transient status-bar line
    jobs_ready = pyqtSignal(object)              # list[TransferJob] queued
    busy = pyqtSignal(bool)

    def __init__(self) -> None:
        super().__init__()
        self._session: Optional[Session] = None
        self._transport: Optional[Transport] = None
        self._pending: Optional[Session] = None

    # ---------------------------------------------------------- properties

    @property
    def session(self) -> Optional[Session]:
        return self._session

    @property
    def pending(self) -> Optional[Session]:
        """The session waiting on a trust decision, if any.

        Read from the GUI thread only while a ``trust_required`` prompt is up —
        the worker is blocked on that answer, so the value cannot change under
        the reader.
        """
        return self._pending

    @property
    def is_connected(self) -> bool:
        return self._transport is not None and self._transport.is_connected

    @property
    def cwd(self) -> str:
        return self._transport.cwd if self._transport else "/"

    # ------------------------------------------------------------- connect

    @pyqtSlot(object)
    def do_connect(self, session: Session) -> None:
        self.busy.emit(True)
        try:
            self.do_disconnect()
            self._pending = session
            transport = session.open()
        except TrustRequired as exc:
            kind = {
                HostKeyUnknown: "host-key-new",
                HostKeyChanged: "host-key-changed",
                CertUnknown: "cert-new",
                CertChanged: "cert-changed",
            }.get(type(exc), "unknown")
            self.trust_required.emit(exc.identity, kind, str(exc))
            return
        except PolicyBlocked as exc:
            self._pending = None
            self.connect_failed.emit(exc.reason, exc.detail)
            return
        except AuthFailed as exc:
            self._pending = None
            self.connect_failed.emit("Sign-in refused", str(exc))
            return
        except TransportError as exc:
            self._pending = None
            self.connect_failed.emit("Could not connect", str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._pending = None
            log.exception("unexpected connect failure")
            self.connect_failed.emit("Could not connect", str(exc))
            return
        finally:
            self.busy.emit(False)

        self._session = session
        self._transport = transport
        self._pending = None
        self.connected.emit(transport.security, transport.cwd)
        self.do_list(transport.cwd)

    @pyqtSlot()
    def retry_pending(self) -> None:
        """Re-run a connection the user has just approved a trust decision for."""
        if self._pending is not None:
            self.do_connect(self._pending)

    @pyqtSlot()
    def abandon_pending(self) -> None:
        self._pending = None
        self.busy.emit(False)

    @pyqtSlot()
    def do_disconnect(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
        self._transport = None
        if self._session is not None:
            self._session.burn()
        self._session = None
        self.disconnected.emit()

    # ------------------------------------------------------------ browsing

    @pyqtSlot(str)
    def do_list(self, path: str) -> None:
        if self._transport is None:
            return
        self.busy.emit(True)
        try:
            entries = self._transport.listdir(path)
            self._transport.set_cwd(path)  # pane and transport agree on "here"
            self.listed.emit(path, entries)
        except TransportError as exc:
            self.failed.emit(str(exc))
        finally:
            self.busy.emit(False)

    @pyqtSlot()
    def do_refresh(self) -> None:
        if self._transport is not None:
            self.do_list(self._transport.cwd)

    @pyqtSlot(str)
    def do_mkdir(self, name: str) -> None:
        if self._transport is None:
            return
        try:
            self._transport.mkdir(remote_join(self._transport.cwd, name))
            self.status.emit(f"Created folder “{name}”")
            self.do_refresh()
        except (TransportError, ValueError) as exc:
            self.failed.emit(str(exc))

    @pyqtSlot(object)
    def do_delete(self, entries: object) -> None:
        if self._transport is None:
            return
        removed = 0
        for entry in list(entries):  # type: ignore[arg-type]
            path = remote_join(self._transport.cwd, entry.name)
            try:
                if entry.is_dir and not entry.is_symlink:
                    self._delete_tree(path)
                else:
                    self._transport.remove(path)
                removed += 1
            except TransportError as exc:
                self.failed.emit(str(exc))
                break
        if removed:
            self.status.emit(f"Deleted {removed} item{'s' if removed != 1 else ''}")
        self.do_refresh()

    def _delete_tree(self, path: str, depth: int = 0) -> None:
        assert self._transport is not None
        if depth > 32:
            raise TransportError(f"Refusing to recurse past 32 levels at {path}")
        for child in self._transport.listdir(path):
            if child.name in (".", ".."):
                continue
            child_path = remote_join(path, child.name)
            if child.is_dir and not child.is_symlink:
                self._delete_tree(child_path, depth + 1)
            else:
                self._transport.remove(child_path)
        self._transport.rmdir(path)

    @pyqtSlot(str, str)
    def do_rename(self, old_name: str, new_name: str) -> None:
        if self._transport is None:
            return
        try:
            base = self._transport.cwd
            self._transport.rename(remote_join(base, old_name), remote_join(base, new_name))
            self.status.emit(f"Renamed to “{new_name}”")
            self.do_refresh()
        except (TransportError, ValueError) as exc:
            self.failed.emit(str(exc))

    # ------------------------------------------------------------- pasting

    @pyqtSlot(object, str, str, object)
    def do_download(self, items: object, local_dir: str, conflict: str,
                    engine: object) -> None:
        """Expand remote selections into jobs and hand them to the engine."""
        if self._transport is None or engine is None:
            return
        self.busy.emit(True)
        jobs: list[TransferJob] = []
        try:
            target = Path(local_dir)
            target.mkdir(parents=True, exist_ok=True)
            for item in list(items):  # type: ignore[arg-type]
                entry = RemoteEntry(
                    name=item.name, size=item.size, is_dir=item.is_dir
                )
                parent = item.path.rsplit("/", 1)[0] or "/"
                jobs.extend(engine.expand_download(  # type: ignore[attr-defined]
                    self._transport, entry, parent, target, Conflict(conflict)
                ))
        except (TransportError, OSError, ValueError) as exc:
            self.failed.emit(f"Could not prepare the download: {exc}")
            return
        finally:
            self.busy.emit(False)

        if not jobs:
            self.failed.emit("Nothing to download — the selection was empty or unsafe.")
            return
        engine.submit(jobs)  # type: ignore[attr-defined]
        self.jobs_ready.emit(jobs)
        self.status.emit(f"Queued {len(jobs)} file{'s' if len(jobs) != 1 else ''} to download")

    @pyqtSlot(object, str, str, object)
    def do_upload(self, items: object, remote_dir: str, conflict: str,
                  engine: object) -> None:
        if self._transport is None or engine is None:
            return
        jobs: list[TransferJob] = []
        try:
            for item in list(items):  # type: ignore[arg-type]
                jobs.extend(engine.expand_upload(  # type: ignore[attr-defined]
                    Path(item.path), remote_dir, Conflict(conflict)
                ))
        except (OSError, ValueError) as exc:
            self.failed.emit(f"Could not prepare the upload: {exc}")
            return
        if not jobs:
            self.failed.emit("Nothing to upload — the selection was empty.")
            return
        engine.submit(jobs)  # type: ignore[attr-defined]
        self.jobs_ready.emit(jobs)
        self.status.emit(f"Queued {len(jobs)} item{'s' if len(jobs) != 1 else ''} to upload")

    @pyqtSlot()
    def do_keepalive(self) -> None:
        if self._transport is not None:
            self._transport.keepalive()
