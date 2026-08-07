"""The transfer queue: what is moving, how fast, and whether it verified.

The last column is the one that matters.  Plenty of clients show a progress bar
and call it done at 100%; Charon shows what it actually checked — a SHA-256
match against the server when the server can hash, and an honest "size verified"
when it cannot.  A green tick that means "we assume so" is worse than no tick.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QRect, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QPainter
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QStyledItemDelegate,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.transfer import Direction, JobState, TransferJob
from .icons import icon
from .theme import Palette
from .util import human_eta, human_rate, human_size

PROGRESS_COLUMN = 2
_STATE_ROLE = Qt.ItemDataRole.UserRole + 1
_PERCENT_ROLE = Qt.ItemDataRole.UserRole + 2


class _ProgressDelegate(QStyledItemDelegate):
    """Paints the progress column as a bar, tinted by the job's outcome."""

    def __init__(self, palette: Palette, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.p = palette

    def paint(self, painter: QPainter, option, index) -> None:
        if index.column() != PROGRESS_COLUMN:
            super().paint(painter, option, index)
            return

        percent = index.data(_PERCENT_ROLE) or 0
        state = index.data(_STATE_ROLE) or JobState.QUEUED.value
        colour = {
            JobState.DONE.value: self.p.secure,
            JobState.FAILED.value: self.p.danger,
            JobState.CANCELLED.value: self.p.text_muted,
            JobState.SKIPPED.value: self.p.text_muted,
        }.get(state, self.p.accent)

        rect = option.rect.adjusted(6, 0, -6, 0)
        bar = QRect(rect.x(), rect.center().y() - 5, rect.width(), 10)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self.p.border))
        painter.drawRoundedRect(bar, 5, 5)
        if percent > 0:
            filled = QRect(bar)
            filled.setWidth(max(10, int(bar.width() * percent / 100)))
            painter.setBrush(QColor(colour))
            painter.drawRoundedRect(filled, 5, 5)
        painter.restore()


class TransferQueueView(QFrame):
    """The dock at the bottom of the window."""

    cancel_requested = pyqtSignal(int)
    cancel_all_requested = pyqtSignal()
    cancel_one_requested = pyqtSignal(int)  # a single job id to stop
    clear_requested = pyqtSignal()
    retry_requested = pyqtSignal(object)   # list[TransferJob] to run again
    reveal_requested = pyqtSignal(object)  # a finished job to show on disk

    def __init__(self, palette: Palette, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.p = palette
        self.setProperty("role", "pane")
        self._rows: dict[int, QTreeWidgetItem] = {}
        self._failed: list[TransferJob] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QFrame()
        header.setProperty("role", "paneHeader")
        head = QHBoxLayout(header)
        head.setContentsMargins(12, 8, 10, 8)
        head.setSpacing(10)
        title = QLabel("TRANSFERS")
        title.setProperty("role", "section")
        head.addWidget(title)
        self.status = QLabel("Idle")
        self.status.setProperty("role", "subtitle")
        head.addWidget(self.status)
        head.addStretch(1)

        self.cancel_button = QPushButton("Stop all")
        self.cancel_button.setProperty("role", "ghost")
        self.cancel_button.setIcon(icon("stop", palette.danger))
        self.cancel_button.clicked.connect(self.cancel_all_requested.emit)
        head.addWidget(self.cancel_button)

        self.retry_button = QPushButton("Retry failed")
        self.retry_button.setProperty("role", "ghost")
        self.retry_button.setIcon(icon("refresh", palette.caution))
        self.retry_button.setEnabled(False)
        self.retry_button.clicked.connect(self._retry_failed)
        head.addWidget(self.retry_button)

        self.clear_button = QPushButton("Clear finished")
        self.clear_button.setProperty("role", "ghost")
        self.clear_button.clicked.connect(self.clear_requested.emit)
        head.addWidget(self.clear_button)
        root.addWidget(header)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["File", "Size", "Progress", "Rate", "Result"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setItemDelegate(_ProgressDelegate(palette, self.tree))
        head_view = self.tree.header()
        head_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        head_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        head_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        head_view.resizeSection(2, 150)
        head_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        head_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        self.tree.itemActivated.connect(self._activated)
        root.addWidget(self.tree, 1)

    # ------------------------------------------------------------- updates

    def upsert(self, job: TransferJob) -> None:
        item = self._rows.get(job.id)
        if item is None:
            item = QTreeWidgetItem()
            glyph = "download" if job.direction is Direction.DOWNLOAD else "upload"
            item.setIcon(0, icon(glyph, self.p.accent))
            item.setText(0, job.name)
            item.setToolTip(0, f"{job.remote_path}\n{job.local_path}")
            self.tree.addTopLevelItem(item)
            self._rows[job.id] = item
            self.tree.scrollToItem(item)
        item.setData(0, Qt.ItemDataRole.UserRole, job)

        item.setText(1, human_size(job.size) if job.size > 0 else "")
        item.setData(PROGRESS_COLUMN, _PERCENT_ROLE, job.percent)
        item.setData(PROGRESS_COLUMN, _STATE_ROLE, job.state.value)

        if job.state is JobState.RUNNING:
            rate = human_rate(job.speed)
            eta = human_eta(job.eta)
            item.setText(3, " · ".join(x for x in (rate, eta) if x))
            item.setText(4, f"{job.percent}%")
            item.setForeground(4, QColor(self.p.text_muted))
        elif job.state is JobState.DONE:
            item.setText(3, human_rate(job.speed))
            item.setText(4, job.integrity or "complete")
            item.setForeground(4, QColor(self.p.secure))
        elif job.state is JobState.FAILED:
            item.setText(3, "")
            item.setText(4, job.error or "failed")
            item.setForeground(4, QColor(self.p.danger))
        elif job.state is JobState.CANCELLED:
            item.setText(3, "")
            item.setText(4, "cancelled")
            item.setForeground(4, QColor(self.p.text_muted))
        elif job.state is JobState.SKIPPED:
            item.setText(3, "")
            item.setText(4, "skipped — already there")
            item.setForeground(4, QColor(self.p.text_muted))
        else:
            item.setText(3, "")
            item.setText(4, "waiting")
            item.setForeground(4, QColor(self.p.text_muted))

        self.tree.viewport().update()

    def summarise(self, jobs: list[TransferJob]) -> None:
        active = [j for j in jobs if not j.state.is_final]
        done = sum(1 for j in jobs if j.state is JobState.DONE)
        failed = sum(1 for j in jobs if j.state is JobState.FAILED)
        if active:
            rate = sum(j.speed for j in active if j.state is JobState.RUNNING)
            remaining = human_size(sum(max(0, j.size - j.transferred) for j in active))
            bits = [f"{len(active)} in progress", remaining + " left"]
            if rate:
                bits.append(human_rate(rate))
            self.status.setText(" · ".join(bits))
        elif failed:
            self.status.setText(f"{done} complete, {failed} failed")
        elif done:
            self.status.setText(f"{done} complete")
        else:
            self.status.setText("Idle")
        self.cancel_button.setEnabled(bool(active))
        self._failed = [j for j in jobs if j.state is JobState.FAILED]
        self.retry_button.setEnabled(bool(self._failed) and not active)
        self.retry_button.setToolTip(
            f"Queue the {len(self._failed)} failed transfer(s) again"
            if self._failed else "Nothing has failed")

    def set_palette(self, palette: Palette) -> None:
        self.p = palette
        self.tree.setItemDelegate(_ProgressDelegate(palette, self.tree))
        self.cancel_button.setIcon(icon("stop", palette.danger))
        self.retry_button.setIcon(icon("refresh", palette.caution))
        self.tree.viewport().update()

    # ------------------------------------------------------------- actions

    def _retry_failed(self) -> None:
        if self._failed:
            self.retry_requested.emit(list(self._failed))

    def _selected_jobs(self) -> list[TransferJob]:
        out = []
        for item in self.tree.selectedItems():
            job = item.data(0, Qt.ItemDataRole.UserRole)
            if job is not None:
                out.append(job)
        return out

    def _activated(self, item, _column: int) -> None:
        job = item.data(0, Qt.ItemDataRole.UserRole)
        if job is not None and job.state is JobState.DONE:
            self.reveal_requested.emit(job)

    def _context_menu(self, point) -> None:
        jobs = self._selected_jobs()
        if not jobs:
            return
        menu = QMenu(self)

        finished = [j for j in jobs if j.state is JobState.DONE
                    and j.direction is Direction.DOWNLOAD]
        act_reveal = QAction(icon("folder", self.p.text), "Show in file manager", self)
        act_reveal.setEnabled(bool(finished))
        act_reveal.triggered.connect(
            lambda: self.reveal_requested.emit(finished[0]) if finished else None)
        menu.addAction(act_reveal)

        retryable = [j for j in jobs if j.state is JobState.FAILED]
        act_retry = QAction(icon("refresh", self.p.text), "Try again", self)
        act_retry.setEnabled(bool(retryable))
        act_retry.triggered.connect(lambda: self.retry_requested.emit(retryable))
        menu.addAction(act_retry)

        running = [j for j in jobs if not j.state.is_final]
        act_stop = QAction(icon("stop", self.p.danger), "Stop", self)
        act_stop.setEnabled(bool(running))
        act_stop.triggered.connect(
            lambda: [self.cancel_one_requested.emit(j.id) for j in running])
        menu.addAction(act_stop)

        failed = [j for j in jobs if j.state is JobState.FAILED and j.error]
        if failed:
            menu.addSeparator()
            act_copy = QAction("Copy error message", self)
            act_copy.triggered.connect(
                lambda: QApplication.clipboard().setText(
                    "\n".join(f"{j.name}: {j.error}" for j in failed)))
            menu.addAction(act_copy)

        menu.exec(self.tree.viewport().mapToGlobal(point))

    def forget_finished(self, keep_ids: set[int]) -> None:
        for job_id in list(self._rows):
            if job_id in keep_ids:
                continue
            item = self._rows.pop(job_id)
            index = self.tree.indexOfTopLevelItem(item)
            if index >= 0:
                self.tree.takeTopLevelItem(index)
