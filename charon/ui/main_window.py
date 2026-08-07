"""The main window: two panes, a clipboard, and a security badge that never lies.

Read this file as three collaborations:

* **Window → worker thread.**  Anything that can block on a socket is a signal
  emitted at the worker, never a direct call.  The window stays responsive
  through a 30-second handshake, and no dialog can be opened from a background
  thread.
* **Window → transfer engine.**  The engine runs on a third thread with its own
  connection, and reports back through :class:`EngineBridge`, which throttles
  progress so a fast local network cannot flood the event loop.
* **Clipboard → transfers.**  Ctrl+C records references, Ctrl+V turns them into
  jobs.  All of the "may this paste happen" logic lives in
  :meth:`~charon.core.clipboard.TransferClipboard.can_paste_into`, so the two
  panes cannot drift apart in what they allow.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence, QCloseEvent
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..core.clipboard import ClipItem, Operation, Side, TransferClipboard
from ..core.model import Credentials, Grade, Protocol, SecurityState, Site
from ..core.policy import Verdict, check_connection
from ..core.secretstore import SecretStore, StorageMode, secret_id
from ..core.session import Session
from ..core.store import Settings, SiteStore
from ..core.transfer import (
    Conflict,
    Direction,
    JobState,
    TransferEngine,
    TransferJob,
)
from ..core.trust import CertPinStore, HostKeyStore, sha256_fingerprint
from ..core.vault import Vault, VaultError, WrongPassword
from ..paths import vault_file
from ..version import APP_NAME, APP_TAGLINE, __version__
from .dialogs import (
    ConnectDialog,
    InsecureConnectionDialog,
    PasteDialog,
    SettingsDialog,
    TrustDialog,
    TrustStoreDialog,
    VaultDialog,
)
from .icons import clear_cache as clear_icon_cache
from .icons import icon
from .panes import LocalPane, RemotePane
from .queue_view import TransferQueueView
from .theme import palette as get_palette
from .theme import stylesheet
from .util import human_size
from .worker import SessionWorker

log = logging.getLogger(__name__)

PROGRESS_INTERVAL = 0.12  # seconds between progress repaints for one job


class EngineBridge(QWidget):
    """Marshals transfer-engine callbacks onto the GUI thread.

    The engine calls in from its own thread; Qt delivers these signals queued
    because the bridge lives on the GUI thread.  Progress is rate-limited here
    rather than in the engine, so throttling never slows the transfer itself.
    """

    job_changed = pyqtSignal(object)
    went_idle = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setVisible(False)
        self._last: dict[int, tuple[float, str]] = {}

    def on_change(self, job: TransferJob) -> None:
        now = time.monotonic()
        last_time, last_state = self._last.get(job.id, (0.0, ""))
        if job.state.value == last_state and now - last_time < PROGRESS_INTERVAL:
            return
        self._last[job.id] = (now, job.state.value)
        self.job_changed.emit(job)

    def on_idle(self) -> None:
        self.went_idle.emit()


class SecurityBadge(QFrame):
    """The status-bar pill.  Its colour is derived from the live connection."""

    def __init__(self, palette, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.p = palette
        self.state: Optional[SecurityState] = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 3, 12, 3)
        layout.setSpacing(7)
        self.glyph = QLabel()
        layout.addWidget(self.glyph)
        self.label = QLabel("Not connected")
        layout.addWidget(self.label)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_state(None)

    def set_palette(self, palette) -> None:
        self.p = palette
        self.set_state(self.state)

    def set_state(self, state: Optional[SecurityState]) -> None:
        self.state = state
        if state is None:
            colour, text, glyph = self.p.text_muted, "Not connected", "unlock"
        else:
            colour = {
                Grade.STRONG: self.p.secure,
                Grade.OK: self.p.secure,
                Grade.WEAK: self.p.caution,
                Grade.UNSAFE: self.p.danger,
            }[state.grade]
            text = state.headline
            glyph = "warning" if state.grade is Grade.UNSAFE else "lock"
        self.glyph.setPixmap(icon(glyph, colour, 15).pixmap(15, 15))
        self.label.setText(text)
        self.label.setStyleSheet(f"color: {colour}; font-weight: 600;")
        self.setStyleSheet(
            f"QFrame {{ border: 1px solid {colour}; border-radius: 11px; "
            f"background: transparent; }}"
        )
        self.setToolTip("Click for connection security details"
                        if state else "Not connected to a server")

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if self.state is None:
            return
        box = QMessageBox(self)
        box.setWindowTitle("Connection security")
        box.setText(self.state.headline)
        box.setInformativeText("\n".join(self.state.detail_lines()))
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.exec()


class MainWindow(QMainWindow):
    # --- requests sent to the worker thread ---------------------------------
    request_connect = pyqtSignal(object)
    request_disconnect = pyqtSignal()
    request_list = pyqtSignal(str)
    request_refresh = pyqtSignal()
    request_mkdir = pyqtSignal(str)
    request_delete = pyqtSignal(object)
    request_rename = pyqtSignal(str, str)
    request_download = pyqtSignal(object, str, str, object)
    request_upload = pyqtSignal(object, str, str, object)
    request_retry = pyqtSignal()
    request_abandon = pyqtSignal()
    request_keepalive = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.settings = Settings.load()
        self.sites = SiteStore()
        self.hostkeys = HostKeyStore()
        self.pins = CertPinStore()
        self.vault = Vault(path=vault_file())
        self.secrets = SecretStore(mode=self.settings.storage_mode, vault=self.vault)
        self.clipboard = TransferClipboard()
        self.p = get_palette(self.settings.theme)

        self.engine: Optional[TransferEngine] = None
        self.bridge = EngineBridge(self)
        self._pending_site: Optional[Site] = None
        self._pending_creds = Credentials()
        self._pending_save = False
        self._move_batch: Optional[tuple[list[ClipItem], set[int]]] = None
        self._last_activity = time.monotonic()

        self.setWindowTitle(f"{APP_NAME} — {APP_TAGLINE}")
        self.resize(1280, 820)
        self.setMinimumSize(940, 600)
        self._apply_theme()

        self._build_ui()
        self._start_worker()
        self._wire()

        self.local_pane.show_hidden = self.settings.show_hidden
        self.local_pane.load(self.settings.download_dir)
        self._update_actions()

        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._tick)
        self._idle_timer.start(20_000)

        # Debounces local directory rescans while a batch is landing.
        self._local_refresh = QTimer(self)
        self._local_refresh.setSingleShot(True)
        self._local_refresh.setInterval(400)
        self._local_refresh.timeout.connect(
            lambda: self.local_pane.load(self.local_pane.current_path))

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(toolbar)

        self.act_connect = QAction(icon("connect", self.p.accent), "Connect", self)
        self.act_connect.setShortcut(QKeySequence("Ctrl+N"))
        self.act_connect.triggered.connect(self.open_connect_dialog)
        toolbar.addAction(self.act_connect)

        self.act_disconnect = QAction(icon("stop", self.p.text_muted), "Disconnect", self)
        self.act_disconnect.triggered.connect(self.disconnect_session)
        toolbar.addAction(self.act_disconnect)

        toolbar.addSeparator()

        self.act_download = QAction(icon("download", self.p.accent), "Download", self)
        self.act_download.setToolTip("Copy the selected server items to this device")
        self.act_download.triggered.connect(self.download_selection)
        toolbar.addAction(self.act_download)

        self.act_upload = QAction(icon("upload", self.p.accent), "Upload", self)
        self.act_upload.setToolTip("Copy the selected local items to the server")
        self.act_upload.triggered.connect(self.upload_selection)
        toolbar.addAction(self.act_upload)

        toolbar.addSeparator()

        self.act_trust = QAction(icon("shield", self.p.text_muted), "Trusted servers", self)
        self.act_trust.setToolTip("Review and revoke the server keys you have pinned")
        self.act_trust.triggered.connect(self.open_trust_store)
        toolbar.addAction(self.act_trust)

        self.act_settings = QAction(icon("gear", self.p.text_muted), "Settings", self)
        self.act_settings.triggered.connect(self.open_settings)
        toolbar.addAction(self.act_settings)

        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().horizontalPolicy().Expanding,
                             spacer.sizePolicy().verticalPolicy().Preferred)
        toolbar.addWidget(spacer)

        self.act_about = QAction("About", self)
        self.act_about.triggered.connect(self.show_about)
        toolbar.addAction(self.act_about)

        # ---- insecure banner --------------------------------------------
        self.banner = QLabel("")
        self.banner.setWordWrap(True)
        self.banner.setVisible(False)
        self.banner.setStyleSheet(
            f"background: {self.p.danger}; color: #180404; font-weight: 700; "
            f"padding: 7px 14px;"
        )

        # ---- panes -------------------------------------------------------
        self.local_pane = LocalPane(self.p)
        self.remote_pane = RemotePane(self.p)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.local_pane)
        self.splitter.addWidget(self.remote_pane)
        self.splitter.setSizes([620, 620])
        self.splitter.setChildrenCollapsible(False)

        self.queue = TransferQueueView(self.p)
        self.queue.setMinimumHeight(150)

        vertical = QSplitter(Qt.Orientation.Vertical)
        vertical.addWidget(self.splitter)
        vertical.addWidget(self.queue)
        vertical.setSizes([560, 200])
        vertical.setChildrenCollapsible(False)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)
        layout.addWidget(self.banner)
        layout.addWidget(vertical, 1)
        self.setCentralWidget(central)

        # ---- status bar --------------------------------------------------
        bar = QStatusBar()
        self.setStatusBar(bar)
        self.status_label = QLabel("Ready")
        bar.addWidget(self.status_label, 1)
        self.clip_label = QLabel("")
        self.clip_label.setStyleSheet(f"color: {self.p.text_muted};")
        bar.addPermanentWidget(self.clip_label)
        self.badge = SecurityBadge(self.p)
        bar.addPermanentWidget(self.badge)

    # -------------------------------------------------------------- thread

    def _start_worker(self) -> None:
        self.thread = QThread(self)
        self.worker = SessionWorker()
        self.worker.moveToThread(self.thread)
        self.thread.start()

        self.request_connect.connect(self.worker.do_connect)
        self.request_disconnect.connect(self.worker.do_disconnect)
        self.request_list.connect(self.worker.do_list)
        self.request_refresh.connect(self.worker.do_refresh)
        self.request_mkdir.connect(self.worker.do_mkdir)
        self.request_delete.connect(self.worker.do_delete)
        self.request_rename.connect(self.worker.do_rename)
        self.request_download.connect(self.worker.do_download)
        self.request_upload.connect(self.worker.do_upload)
        self.request_retry.connect(self.worker.retry_pending)
        self.request_abandon.connect(self.worker.abandon_pending)
        self.request_keepalive.connect(self.worker.do_keepalive)

        self.worker.connected.connect(self.on_connected)
        self.worker.disconnected.connect(self.on_disconnected)
        self.worker.connect_failed.connect(self.on_connect_failed)
        self.worker.trust_required.connect(self.on_trust_required)
        self.worker.listed.connect(self.on_listed)
        self.worker.failed.connect(self.on_failed)
        self.worker.status.connect(self.set_status)
        self.worker.busy.connect(self.on_busy)
        self.worker.jobs_ready.connect(self.on_jobs_queued)

    def _wire(self) -> None:
        for pane in (self.local_pane, self.remote_pane):
            pane.copy_requested.connect(self.on_copy)
            pane.paste_requested.connect(lambda p=pane: self.on_paste(p.side))
            pane.items_dropped.connect(lambda items, p=pane: self.on_drop(p.side, items))
            pane.rename_requested.connect(self.on_rename)

        self.local_pane.delete_requested.connect(self.on_local_delete)
        self.local_pane.mkdir_requested.connect(self.on_local_mkdir)
        self.local_pane.external_paths_dropped.connect(self.on_local_external_drop)

        self.remote_pane.navigate.connect(self.request_list)
        self.remote_pane.refresh_button.clicked.connect(self.request_refresh)
        self.remote_pane.delete_requested.connect(self.on_remote_delete)
        self.remote_pane.mkdir_requested.connect(self.on_remote_mkdir)
        self.remote_pane.external_paths_dropped.connect(self.on_remote_external_drop)

        self.bridge.job_changed.connect(self.on_job_changed)
        self.bridge.went_idle.connect(self.on_engine_idle)

        self.queue.cancel_all_requested.connect(self.on_cancel_all)
        self.queue.cancel_one_requested.connect(self.on_cancel_one)
        self.queue.clear_requested.connect(self.on_clear_finished)
        self.queue.retry_requested.connect(self.on_retry)
        self.queue.reveal_requested.connect(self.on_reveal)

    # ------------------------------------------------------------- connect

    def open_connect_dialog(self) -> None:
        self._touch()
        dialog = ConnectDialog(self.sites, self.settings, self.p, self)
        if dialog.exec() != ConnectDialog.DialogCode.Accepted:
            return
        site = dialog.result_site
        creds = dialog.result_credentials
        if site is None:
            return
        self._pending_save = dialog.save_site
        self.start_connection(site, creds)

    def start_connection(self, site: Site, creds: Credentials) -> None:
        # A saved password fills in only when the user left the field blank.
        if not creds.password and not creds.passphrase and site.save_password:
            stored = self._load_secret(site)
            if stored:
                if site.auth.value == "key":
                    creds.passphrase = stored
                else:
                    creds.password = stored

        verdict = check_connection(site, self.settings.policy)
        if verdict.verdict is Verdict.BLOCK:
            self.on_connect_failed(verdict.reason, verdict.detail)
            return
        if verdict.verdict is Verdict.CONFIRM:
            dialog = InsecureConnectionDialog(site, verdict.reason, verdict.detail,
                                              self.p, self)
            if dialog.exec() != InsecureConnectionDialog.DialogCode.Accepted:
                self.set_status("Connection cancelled")
                return
            if dialog.remember_choice:
                site.accept_insecure_ftp = True

        self._pending_site = site
        self._pending_creds = creds
        session = Session(site=site, policy=self.settings.policy, credentials=creds,
                          hostkeys=self.hostkeys, pins=self.pins)
        self.set_status(f"Connecting to {site.host}…")
        self.request_connect.emit(session)

    def on_connected(self, security: SecurityState, cwd: str) -> None:
        self.badge.set_state(security)
        site = self._pending_site
        if site is not None:
            if self._pending_save:
                self.sites.add(site.touched())
            self._save_secret(site, self._pending_creds)

        if security.protocol is Protocol.FTP:
            self.banner.setText(
                "UNENCRYPTED SESSION — your password and every file in this session "
                "cross the network in readable text."
            )
            self.banner.setVisible(True)
        else:
            self.banner.setVisible(False)

        self._start_engine()
        self.setWindowTitle(f"{APP_NAME} — {site.label if site else cwd}")
        self.set_status(f"Connected · {security.headline}")
        self._update_actions()

    def on_connect_failed(self, title: str, detail: str) -> None:
        self.badge.set_state(None)
        box = QMessageBox(self)
        box.setWindowTitle("Connection failed")
        box.setText(title)
        box.setInformativeText(detail)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()
        self.set_status(title)
        self._update_actions()

    def on_trust_required(self, identity, kind: str, message: str) -> None:
        if kind.endswith("-new") and not self.settings.policy.allow_tofu:
            self.request_abandon.emit()
            self.on_connect_failed(
                "Unrecognised server",
                "Trust-on-first-use is switched off in Settings, so Charon will only "
                "connect to servers whose key is already pinned. Add this server's key "
                "to the trust store, or re-enable the setting.",
            )
            return

        dialog = TrustDialog(identity, kind, message, self.p, self)
        if dialog.exec() != TrustDialog.DialogCode.Accepted:
            self.request_abandon.emit()
            self.set_status("Connection refused — server not trusted")
            self._update_actions()
            return

        # Pin exactly the bytes the dialog displayed.  The identity carries the
        # key it was fingerprinted from, so there is no window between "the user
        # approved this fingerprint" and "this key was written to the store".
        if not identity.blob:
            self.request_abandon.emit()
            self.on_connect_failed(
                "Could not pin that key",
                "The server's key did not arrive intact. Try connecting again.",
            )
            return
        if not verify_identity(identity):
            self.request_abandon.emit()
            self.on_connect_failed(
                "Fingerprint mismatch",
                "The fingerprint shown does not match the key it came with. Nothing "
                "has been trusted. This should never happen — do not retry against "
                "an untrusted network.",
            )
            return
        if identity.key_type == "TLS certificate":
            self.pins.trust(identity.host, identity.port, identity.blob)
        else:
            self.hostkeys.trust(identity.host, identity.port,
                                identity.key_type, identity.blob)
        self.set_status(f"Trusted {identity.label} — reconnecting…")
        self.request_retry.emit()

    def disconnect_session(self) -> None:
        self._stop_engine()
        self.request_disconnect.emit()

    def on_disconnected(self) -> None:
        self.badge.set_state(None)
        self.banner.setVisible(False)
        self.remote_pane.clear("Not connected")
        self.setWindowTitle(f"{APP_NAME} — {APP_TAGLINE}")
        if self.clipboard.source_side is Side.REMOTE:
            self.clipboard.clear()
            self._update_clip_label()
        self.set_status("Disconnected")
        self._update_actions()

    # ------------------------------------------------------------- listing

    def on_listed(self, path: str, entries) -> None:
        self.remote_pane.show_entries(path, entries, self.settings.show_hidden)
        self._update_actions()

    def on_failed(self, message: str) -> None:
        self.set_status(message)
        QMessageBox.warning(self, "Charon", message)

    def on_busy(self, busy: bool) -> None:
        self.setCursor(Qt.CursorShape.BusyCursor if busy else Qt.CursorShape.ArrowCursor)

    # ----------------------------------------------------------- clipboard

    def on_copy(self, items: list, is_cut: bool) -> None:
        self._touch()
        if not items:
            return
        side = items[0].side
        session = self.worker.session
        self.clipboard.set(
            items,
            Operation.CUT if is_cut else Operation.COPY,
            session_id=session.id if session else "",
            session_label=session.label if session else "",
        )
        self._update_clip_label()
        target = "the server" if side is Side.LOCAL else "this device"
        self.set_status(f"{self.clipboard.summary()} — paste into {target} to transfer")
        self._update_actions()

    def on_paste(self, target: Side) -> None:
        self._touch()
        session = self.worker.session
        ok, why = self.clipboard.can_paste_into(target, session.id if session else "")
        if not ok:
            self.set_status(why)
            QMessageBox.information(self, "Nothing to paste", why)
            return
        if target is Side.LOCAL:
            self._begin_download(self.clipboard.items, self.local_pane.current_path)
        else:
            self._begin_upload(self.clipboard.items, self.remote_pane.current_path)

    def on_drop(self, target: Side, items: list) -> None:
        self._touch()
        if not items:
            return
        if target is Side.LOCAL:
            self._begin_download(items, self.local_pane.current_path)
        else:
            self._begin_upload(items, self.remote_pane.current_path)

    def on_local_external_drop(self, paths: list) -> None:
        """Files dragged in from the OS file manager land in the local pane."""
        self.set_status(f"{len(paths)} item(s) dropped — drag them onto the server "
                        f"pane to upload")

    def on_remote_external_drop(self, paths: list) -> None:
        items = [ClipItem.from_local(Path(p)) for p in paths]
        self._begin_upload(items, self.remote_pane.current_path)

    def download_selection(self) -> None:
        items = self.remote_pane.tree.selected_clip_items()
        if items:
            self._begin_download(items, self.local_pane.current_path)

    def upload_selection(self) -> None:
        items = self.local_pane.tree.selected_clip_items()
        if items:
            self._begin_upload(items, self.remote_pane.current_path)

    def _begin_download(self, items: list, destination: str) -> None:
        if self.engine is None:
            self.set_status("Connect to a server first")
            return
        if not destination:
            destination = self.settings.download_dir
        dialog = PasteDialog(len(items), sum(i.size for i in items), destination,
                             "Download", self.p, self)
        if dialog.exec() != PasteDialog.DialogCode.Accepted:
            return
        self.request_download.emit(items, destination, dialog.conflict.value, self.engine)
        self._arm_move(items)

    def _begin_upload(self, items: list, destination: str) -> None:
        if self.engine is None or not destination:
            self.set_status("Connect to a server first")
            return
        dialog = PasteDialog(len(items), sum(i.size for i in items), destination,
                             "Upload", self.p, self)
        if dialog.exec() != PasteDialog.DialogCode.Accepted:
            return
        self.request_upload.emit(items, destination, dialog.conflict.value, self.engine)
        self._arm_move(items)

    def _arm_move(self, items: list) -> None:
        """Remember a cut so the sources can be removed once — and only once —
        every job *in this batch* has finished and verified."""
        if self.clipboard.operation is Operation.CUT and items is self.clipboard.items:
            self._move_batch = (list(items), set())
        else:
            self._move_batch = None

    def on_jobs_queued(self, jobs: list) -> None:
        """Record which job ids belong to the pending move.

        Without this the completion check looks at every job the engine has
        ever run, so one unrelated failure earlier in the session would block
        every later move for good.
        """
        if self._move_batch is None:
            return
        sources, ids = self._move_batch
        ids.update(j.id for j in jobs)

    # ------------------------------------------------------------- engine

    def _start_engine(self) -> None:
        self._stop_engine()
        session = self.worker.session
        if session is None:
            return
        self.engine = TransferEngine(
            connect=session.open,
            on_change=self.bridge.on_change,
            on_idle=self.bridge.on_idle,
            private_downloads=self.settings.private_downloads,
            verify=self.settings.policy.verify_downloads,
        )

    def _stop_engine(self) -> None:
        if self.engine is not None:
            self.engine.shutdown()
            self.engine = None

    def on_job_changed(self, job: TransferJob) -> None:
        self.queue.upsert(job)
        if self.engine is not None:
            self.queue.summarise(self.engine.jobs)
        if job.state is JobState.DONE and job.direction is Direction.DOWNLOAD:
            # Coalesced: a 500-file batch would otherwise rescan the folder 500
            # times, and on a slow disk that costs more than the transfer.
            self._local_refresh.start()

    def on_engine_idle(self) -> None:
        if self.engine is None:
            return
        jobs = self.engine.jobs
        self.queue.summarise(jobs)
        self.request_refresh.emit()
        self.local_pane.load(self.local_pane.current_path)
        self._finish_move(jobs)

    def _finish_move(self, jobs: list[TransferJob]) -> None:
        """Complete a cut/paste by removing the sources — never before every
        byte has landed and verified."""
        if self._move_batch is None:
            return
        sources, batch_ids = self._move_batch
        if not batch_ids:
            return  # the jobs have not been queued yet
        batch = [j for j in jobs if j.id in batch_ids]
        if not batch or any(not j.state.is_final for j in batch):
            return

        failed = [j for j in batch if j.state is not JobState.DONE]
        if failed:
            self._move_batch = None
            self.set_status(
                f"Move stopped — {len(failed)} of {len(batch)} transfers did not "
                f"complete, so nothing was deleted"
            )
            return

        self._move_batch = None
        remote_sources = [s for s in sources if s.side is Side.REMOTE]
        local_sources = [s for s in sources if s.side is Side.LOCAL]
        where = "the server" if remote_sources else "this device"
        originals = remote_sources or local_sources
        if not originals:
            return

        names = ", ".join(s.name for s in originals[:3])
        if len(originals) > 3:
            names += f", and {len(originals) - 3} more"
        box = QMessageBox(self)
        box.setWindowTitle("Finish the move?")
        box.setText(f"Delete the originals on {where}?")
        box.setInformativeText(
            f"{names}\n\nAll {len(batch)} file(s) transferred and verified. "
            f"Deleting the originals completes the move; keeping them turns it "
            f"into a copy."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Cancel |
                               QMessageBox.StandardButton.Yes)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() == QMessageBox.StandardButton.Yes:
            if remote_sources:
                # By absolute path: the user may well have browsed elsewhere
                # while the transfer ran.
                self.request_delete.emit(
                    [(s.path, s.is_dir, False) for s in remote_sources])
            else:
                self._delete_local_paths([Path(s.path) for s in local_sources])
        self.clipboard.clear()
        self._update_clip_label()

    def _delete_local_paths(self, paths: list[Path]) -> None:
        import shutil

        removed = 0
        for path in paths:
            try:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                removed += 1
            except OSError as exc:
                QMessageBox.warning(self, "Could not delete", str(exc))
                break
        if removed:
            self.set_status(f"Move complete — removed {removed} original(s)")
        self.local_pane.load(self.local_pane.current_path)

    def on_cancel_all(self) -> None:
        if self.engine is not None:
            self.engine.cancel_all()
            self.set_status("Stopping transfers…")

    def on_cancel_one(self, job_id: int) -> None:
        if self.engine is not None:
            self.engine.cancel(job_id)

    def on_retry(self, jobs: list) -> None:
        """Queue failed transfers again as fresh jobs.

        New jobs rather than resurrected ones: a job carries the state of the
        attempt that failed (bytes moved, error text, timings), and reusing it
        would leave the queue showing a half-truth about what just happened.
        """
        if self.engine is None or not jobs:
            return
        retries = [
            TransferJob(
                direction=job.direction,
                remote_path=job.remote_path,
                local_path=job.local_path,
                size=max(0, job.size),
                # Resume rather than start over: a failure part-way through a
                # large file usually leaves a .charon-part worth continuing.
                conflict=Conflict.RESUME,
            )
            for job in jobs
        ]
        self.engine.submit(retries)
        self.set_status(f"Retrying {len(retries)} transfer(s)")

    def on_reveal(self, job: TransferJob) -> None:
        """Show a finished download in the platform's file manager."""
        path = Path(job.local_path)
        if not path.exists():
            self.set_status(f"{path.name} is no longer there")
            return
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(path)])
            elif sys.platform.startswith("win"):
                subprocess.Popen(["explorer", "/select,", str(path)])
            else:
                # Freedesktop file managers vary; opening the parent folder is
                # the one behaviour they all agree on.
                subprocess.Popen(["xdg-open", str(path.parent)])
        except OSError as exc:
            self.set_status(f"Could not open a file manager: {exc}")

    def on_clear_finished(self) -> None:
        if self.engine is None:
            return
        self.engine.clear_finished()
        self.queue.forget_finished({j.id for j in self.engine.jobs})
        self.queue.summarise(self.engine.jobs)

    # ----------------------------------------------------- file operations

    def on_local_mkdir(self) -> None:
        name, ok = QInputDialog.getText(self, "New folder", "Folder name")
        if not ok or not name.strip():
            return
        try:
            (Path(self.local_pane.current_path) / name.strip()).mkdir(parents=True)
            self.local_pane.load(self.local_pane.current_path)
        except OSError as exc:
            QMessageBox.warning(self, "Could not create folder", str(exc))

    def on_remote_mkdir(self) -> None:
        if self.worker.session is None:
            return
        name, ok = QInputDialog.getText(self, "New folder on server", "Folder name")
        if ok and name.strip():
            self.request_mkdir.emit(name.strip())

    def on_local_delete(self, items: list) -> None:
        if not items or not self._confirm_delete(items, "this device"):
            return
        self._delete_local_paths([Path(i.path) for i in items])

    def on_remote_delete(self, items: list) -> None:
        if not items or not self._confirm_delete(items, "the server"):
            return
        # Absolute paths captured now, before the confirmation dialog gave the
        # user a chance to navigate somewhere else.
        self.request_delete.emit([(i.path, i.is_dir, False) for i in items])

    def _confirm_delete(self, items: list, where: str) -> bool:
        if not self.settings.confirm_delete:
            return True
        names = ", ".join(i.name for i in items[:4])
        if len(items) > 4:
            names += f", and {len(items) - 4} more"
        folders = sum(1 for i in items if i.is_dir)
        box = QMessageBox(self)
        box.setWindowTitle("Delete")
        box.setText(f"Permanently delete {len(items)} item"
                    f"{'s' if len(items) != 1 else ''} from {where}?")
        box.setInformativeText(
            names + ("\n\nFolders are deleted with everything inside them. "
                     "This cannot be undone." if folders else
                     "\n\nThis cannot be undone.")
        )
        box.setStandardButtons(QMessageBox.StandardButton.Cancel |
                               QMessageBox.StandardButton.Yes)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        return box.exec() == QMessageBox.StandardButton.Yes

    def on_rename(self, item: ClipItem, old_name: str) -> None:
        new_name, ok = QInputDialog.getText(self, "Rename", "New name", text=old_name)
        if not ok or not new_name.strip() or new_name == old_name:
            return
        if item.side is Side.REMOTE:
            self.request_rename.emit(old_name, new_name.strip())
        else:
            try:
                Path(item.path).rename(Path(item.path).with_name(new_name.strip()))
                self.local_pane.load(self.local_pane.current_path)
            except OSError as exc:
                QMessageBox.warning(self, "Could not rename", str(exc))

    # ------------------------------------------------------------ secrets

    def _secret_key(self, site: Site) -> str:
        kind = "passphrase" if site.auth.value == "key" else "password"
        return secret_id(site.protocol.value, site.host, site.port,
                         site.username or "anonymous", kind)

    def _load_secret(self, site: Site) -> Optional[str]:
        if self.secrets.needs_unlock and not self._unlock_vault():
            return None
        return self.secrets.get(self._secret_key(site))

    def _save_secret(self, site: Site, creds: Credentials) -> None:
        secret = creds.passphrase if site.auth.value == "key" else creds.password
        if not creds.remember or not secret or not self.secrets.can_store:
            return
        if self.secrets.mode is StorageMode.VAULT and not self.vault.is_unlocked:
            if not self._unlock_vault(create_if_missing=True):
                return
        try:
            self.secrets.set(self._secret_key(site), secret)
        except Exception as exc:
            log.warning("could not save the password: %s", exc)
            self.set_status(f"Connected, but the password could not be saved: {exc}")

    def _unlock_vault(self, create_if_missing: bool = False) -> bool:
        creating = not self.vault.exists
        if creating and not create_if_missing:
            return False
        for _ in range(3):
            dialog = VaultDialog(creating, self.p, self)
            if dialog.exec() != VaultDialog.DialogCode.Accepted:
                return False
            try:
                if creating:
                    self.vault.create(dialog.password)
                else:
                    self.vault.unlock(dialog.password)
                return True
            except WrongPassword:
                QMessageBox.warning(self, "Vault", "That master password is not correct.")
            except VaultError as exc:
                QMessageBox.warning(self, "Vault", str(exc))
                return False
        return False

    # -------------------------------------------------------------- chrome

    def open_settings(self) -> None:
        previous_theme = self.settings.theme
        dialog = SettingsDialog(self.settings, self.p, self)
        if dialog.exec() != SettingsDialog.DialogCode.Accepted:
            return
        self.secrets.mode = self.settings.storage_mode
        self.local_pane.show_hidden = self.settings.show_hidden
        self.local_pane.load(self.local_pane.current_path)
        if self.worker.is_connected:
            self.request_refresh.emit()
        if self.settings.theme != previous_theme:
            self.p = get_palette(self.settings.theme)
            self._apply_theme()
        self.set_status("Settings saved")

    def open_trust_store(self) -> None:
        self._touch()
        TrustStoreDialog(self.hostkeys, self.pins, self.p, self).exec()

    def show_about(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle(f"About {APP_NAME}")
        box.setText(f"{APP_NAME} {__version__}")
        box.setInformativeText(
            f"{APP_TAGLINE}.\n\n"
            "SFTP over SSH and FTP over explicit TLS, with host keys and "
            "certificates pinned on first use, credentials kept in the OS keychain "
            "or an AES-256-GCM vault, and every transfer hashed on arrival.\n\n"
            "No telemetry. Nothing leaves this machine except the files you move."
        )
        box.exec()

    def _apply_theme(self) -> None:
        """Style the whole application, not just this window.

        Security prompts are the dialogs that matter most, and a dialog that
        renders in the default system look while the window behind it is dark
        reads as a browser popup — exactly the wrong instinct to train. Setting
        the sheet on the QApplication keeps every dialog inside Charon's skin.
        """
        clear_icon_cache()
        app = QApplication.instance()
        target = app if app is not None else self
        target.setStyleSheet(stylesheet(self.p))

        # Widgets hold their own QIcon references, so clearing the cache is
        # not enough — each one has to be handed a freshly tinted glyph.
        for action, glyph, tint in (
            (getattr(self, "act_connect", None), "connect", self.p.accent),
            (getattr(self, "act_disconnect", None), "stop", self.p.text_muted),
            (getattr(self, "act_download", None), "download", self.p.accent),
            (getattr(self, "act_upload", None), "upload", self.p.accent),
            (getattr(self, "act_settings", None), "gear", self.p.text_muted),
            (getattr(self, "act_trust", None), "shield", self.p.text_muted),
        ):
            if action is not None:
                action.setIcon(icon(glyph, tint))
        for pane in (getattr(self, "local_pane", None), getattr(self, "remote_pane", None)):
            if pane is not None:
                pane.set_palette(self.p)
        if getattr(self, "queue", None) is not None:
            self.queue.set_palette(self.p)
        if getattr(self, "badge", None) is not None:
            self.badge.set_palette(self.p)

    def set_status(self, message: str) -> None:
        self.status_label.setText(message)

    def _update_clip_label(self) -> None:
        if self.clipboard.is_empty:
            self.clip_label.setText("")
            return
        size = human_size(self.clipboard.total_size)
        self.clip_label.setText(f"{self.clipboard.summary()}"
                                + (f" · {size}" if self.clipboard.total_size else ""))

    def _update_actions(self) -> None:
        connected = self.worker.is_connected
        self.act_disconnect.setEnabled(connected)
        self.act_download.setEnabled(connected)
        self.act_upload.setEnabled(connected)
        self.remote_pane.newfolder_button.setEnabled(connected)
        self.remote_pane.setEnabled(True)

    def _touch(self) -> None:
        self._last_activity = time.monotonic()

    def _tick(self) -> None:
        """Idle handling: keep a live session warm, or close it if abandoned."""
        limit = self.settings.policy.lock_after_minutes
        idle_for = time.monotonic() - self._last_activity
        busy = self.engine is not None and self.engine.active > 0
        if busy:
            self._touch()
            return
        if limit and idle_for > limit * 60:
            if self.worker.is_connected:
                self.disconnect_session()
                self.set_status(f"Disconnected after {limit} minutes idle")
            self.secrets.lock()
            self._touch()
        elif self.worker.is_connected:
            self.request_keepalive.emit()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self.engine is not None and self.engine.active:
            box = QMessageBox(self)
            box.setWindowTitle("Transfers in progress")
            box.setText(f"{self.engine.active} transfer(s) are still running.")
            box.setInformativeText("Quitting now stops them. Partly-copied files are "
                                   "left as “.charon-part” and can be resumed later.")
            box.setStandardButtons(QMessageBox.StandardButton.Cancel |
                                   QMessageBox.StandardButton.Yes)
            box.setDefaultButton(QMessageBox.StandardButton.Cancel)
            if box.exec() != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self._stop_engine()
        self.request_disconnect.emit()
        self.secrets.lock()
        self.thread.quit()
        self.thread.wait(3000)
        self.settings.save()
        event.accept()


def verify_identity(identity) -> bool:
    """Re-derive the fingerprint from the key and check it matches what was shown.

    Cheap, and it closes the gap where a bug elsewhere could put one key's bytes
    next to another key's fingerprint in the approval dialog.
    """
    return sha256_fingerprint(identity.blob) == identity.fingerprint
