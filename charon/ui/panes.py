"""The two file panes — local on the left, server on the right.

Both are the same widget with a different data source, which is what makes
copy/paste symmetrical: Ctrl+C in either pane produces the same kind of
clipboard entry, and Ctrl+V in the other turns it into a transfer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Optional

from PyQt6.QtCore import QMimeData, QPoint, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QDrag, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.clipboard import ClipItem, Side
from ..core.model import RemoteEntry
from ..core.safety import normalise_remote
from .icons import icon
from .theme import Palette
from .util import human_size, human_time

MIME = "application/x-charon-items"


class _Item(QTreeWidgetItem):
    """Sorts folders above files, then by the column's natural order."""

    def __init__(self, is_dir: bool, size: int, mtime: float) -> None:
        super().__init__()
        self.is_dir = is_dir
        self.raw_size = size
        self.raw_mtime = mtime

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _Item):
            return super().__lt__(other)  # type: ignore[arg-type]
        if self.is_dir != other.is_dir:
            tree = self.treeWidget()
            ascending = (
                tree.header().sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
                if tree else True
            )
            return self.is_dir if ascending else not self.is_dir
        column = self.treeWidget().sortColumn() if self.treeWidget() else 0
        if column == 1:
            return self.raw_size < other.raw_size
        if column == 2:
            return self.raw_mtime < other.raw_mtime
        return self.text(column).lower() < other.text(column).lower()


class FileTree(QTreeWidget):
    """Tree with drag-out, drop-in, and the keyboard verbs users expect."""

    copy_requested = pyqtSignal()
    cut_requested = pyqtSignal()
    paste_requested = pyqtSignal()
    delete_requested = pyqtSignal()
    rename_requested = pyqtSignal()
    go_up = pyqtSignal()
    items_dropped = pyqtSignal(object)   # list[ClipItem] from the other pane
    external_paths_dropped = pyqtSignal(object)  # list[str] from the OS

    def __init__(self, side: Side, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.side = side
        self.setColumnCount(4)
        self.setHeaderLabels(["Name", "Size", "Modified", "Permissions"])
        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        header = self.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

    # ------------------------------------------------------------ keyboard

    def keyPressEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        key, mods = event.key(), event.modifiers()
        ctrl = Qt.KeyboardModifier.ControlModifier
        meta = Qt.KeyboardModifier.MetaModifier  # ⌘ on macOS
        combo = mods & (ctrl | meta)

        if combo and key == Qt.Key.Key_C:
            self.copy_requested.emit()
            return
        if combo and key == Qt.Key.Key_X:
            self.cut_requested.emit()
            return
        if combo and key == Qt.Key.Key_V:
            self.paste_requested.emit()
            return
        if key in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete) and combo:
            self.delete_requested.emit()
            return
        if key == Qt.Key.Key_Delete:
            self.delete_requested.emit()
            return
        if key == Qt.Key.Key_F2:
            self.rename_requested.emit()
            return
        if key == Qt.Key.Key_Backspace:
            self.go_up.emit()
            return
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            item = self.currentItem()
            if item is not None:
                self.itemActivated.emit(item, 0)
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------ dragging

    def startDrag(self, actions) -> None:  # noqa: N802
        items = self.selected_clip_items()
        if not items:
            return
        mime = QMimeData()
        mime.setData(MIME, json.dumps({
            "side": self.side.value,
            "items": [
                {"path": i.path, "name": i.name, "is_dir": i.is_dir, "size": i.size}
                for i in items
            ],
        }).encode("utf-8"))
        mime.setText("\n".join(i.path for i in items))
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.exec(Qt.DropAction.CopyAction)

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        self._maybe_accept(event)

    def dragMoveEvent(self, event) -> None:  # noqa: N802
        self._maybe_accept(event)

    def _maybe_accept(self, event) -> None:
        mime = event.mimeData()
        if mime.hasFormat(MIME):
            payload = self._decode(mime)
            # Dropping a pane's own items back into itself is a no-op, so the
            # drop is refused rather than silently starting a transfer to self.
            if payload and payload.get("side") != self.side.value:
                event.setDropAction(Qt.DropAction.CopyAction)
                event.accept()
                return
        elif mime.hasUrls() and self.side is Side.REMOTE:
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
            return
        event.ignore()

    def dropEvent(self, event) -> None:  # noqa: N802
        mime = event.mimeData()
        if mime.hasFormat(MIME):
            payload = self._decode(mime)
            if not payload or payload.get("side") == self.side.value:
                event.ignore()
                return
            source = Side(payload["side"])
            items = [
                ClipItem(source, d["path"], d["name"], bool(d["is_dir"]), int(d["size"]))
                for d in payload.get("items", [])
            ]
            if items:
                self.items_dropped.emit(items)
                event.acceptProposedAction()
                return
        elif mime.hasUrls() and self.side is Side.REMOTE:
            paths = [u.toLocalFile() for u in mime.urls() if u.isLocalFile()]
            if paths:
                self.external_paths_dropped.emit(paths)
                event.acceptProposedAction()
                return
        event.ignore()

    @staticmethod
    def _decode(mime: QMimeData) -> Optional[dict]:
        try:
            return json.loads(bytes(mime.data(MIME)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    # ------------------------------------------------------------- helpers

    def selected_clip_items(self) -> list[ClipItem]:
        out = []
        for item in self.selectedItems():
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(data, ClipItem):
                out.append(data)
        return out


class FilePane(QFrame):
    """A titled pane: path bar, file tree, and a one-line summary footer."""

    navigate = pyqtSignal(str)
    copy_requested = pyqtSignal(object, bool)   # items, is_cut
    paste_requested = pyqtSignal()
    delete_requested = pyqtSignal(object)
    rename_requested = pyqtSignal(object, str)
    items_dropped = pyqtSignal(object)
    external_paths_dropped = pyqtSignal(object)
    mkdir_requested = pyqtSignal()

    def __init__(self, title: str, side: Side, palette: Palette,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.side = side
        self.palette_ = palette
        self.setProperty("role", "pane")
        self.current_path = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QFrame()
        header.setProperty("role", "paneHeader")
        head = QVBoxLayout(header)
        head.setContentsMargins(12, 9, 12, 9)
        head.setSpacing(7)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        self.title_label = QLabel(title)
        self.title_label.setProperty("role", "section")
        title_row.addWidget(self.title_label)
        title_row.addStretch(1)
        self.badge = QLabel("")
        self.badge.setProperty("role", "subtitle")
        title_row.addWidget(self.badge)
        head.addLayout(title_row)

        path_row = QHBoxLayout()
        path_row.setSpacing(6)
        self.up_button = self._tool("up", "Go up one folder  (Backspace)")
        self.home_button = self._tool("home", "Go to the starting folder")
        self.refresh_button = self._tool("refresh", "Refresh  (F5)")
        self.newfolder_button = self._tool("newfolder", "New folder")
        path_row.addWidget(self.up_button)
        path_row.addWidget(self.home_button)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Not connected" if side is Side.REMOTE else "")
        self.path_edit.returnPressed.connect(self._path_entered)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.newfolder_button)
        path_row.addWidget(self.refresh_button)
        head.addLayout(path_row)
        root.addWidget(header)

        self.tree = FileTree(side, self)
        root.addWidget(self.tree, 1)

        footer = QFrame()
        foot = QHBoxLayout(footer)
        foot.setContentsMargins(12, 7, 12, 7)
        self.summary = QLabel("")
        self.summary.setProperty("role", "subtitle")
        foot.addWidget(self.summary)
        foot.addStretch(1)
        self.hint = QLabel("")
        self.hint.setProperty("role", "subtitle")
        foot.addWidget(self.hint)
        root.addWidget(footer)

        self.up_button.clicked.connect(self.go_up)
        self.home_button.clicked.connect(self.go_home)
        self.newfolder_button.clicked.connect(self.mkdir_requested.emit)
        self.tree.go_up.connect(self.go_up)
        self.tree.copy_requested.connect(lambda: self._emit_copy(False))
        self.tree.cut_requested.connect(lambda: self._emit_copy(True))
        self.tree.paste_requested.connect(self.paste_requested.emit)
        self.tree.delete_requested.connect(
            lambda: self.delete_requested.emit(self.tree.selected_clip_items()))
        self.tree.rename_requested.connect(self._begin_rename)
        self.tree.items_dropped.connect(self.items_dropped.emit)
        self.tree.external_paths_dropped.connect(self.external_paths_dropped.emit)
        self.tree.itemActivated.connect(self._activated)
        self.tree.itemSelectionChanged.connect(self._selection_changed)
        self.tree.customContextMenuRequested.connect(self._context_menu)

        QShortcut(QKeySequence.StandardKey.Refresh, self, self.refresh_button.click)

    # ---------------------------------------------------------------- setup

    def _tool(self, glyph: str, tip: str) -> QToolButton:
        button = QToolButton()
        button.setIcon(icon(glyph, self.palette_.text_muted))
        button.setToolTip(tip)
        button.setAutoRaise(True)
        return button

    # ------------------------------------------------------------ populate

    def show_entries(self, path: str, entries: Iterable[RemoteEntry],
                     show_hidden: bool) -> None:
        self.current_path = path
        self.path_edit.setText(path)
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        files = dirs = 0
        total = 0
        for entry in entries:
            if not show_hidden and entry.name.startswith(".") and entry.name not in (".", ".."):
                continue
            if entry.name in (".", ".."):
                continue
            item = _Item(entry.is_dir, entry.size, entry.mtime)
            item.setText(0, entry.name)
            item.setText(1, "" if entry.is_dir else human_size(entry.size))
            item.setText(2, human_time(entry.mtime))
            item.setText(3, entry.mode)
            glyph = "link" if entry.is_symlink else ("folder" if entry.is_dir else "file")
            tint = (self.palette_.caution if entry.is_symlink
                    else self.palette_.accent if entry.is_dir
                    else self.palette_.text_muted)
            item.setIcon(0, icon(glyph, tint))
            if entry.is_symlink:
                item.setToolTip(0, "Symbolic link — Charon does not follow these "
                                   "when copying folders.")
            item.setData(0, Qt.ItemDataRole.UserRole,
                         self._clip_item(path, entry))
            self.tree.addTopLevelItem(item)
            if entry.is_dir:
                dirs += 1
            else:
                files += 1
                total += entry.size
        self.tree.setSortingEnabled(True)
        bits = []
        if dirs:
            bits.append(f"{dirs} folder{'s' if dirs != 1 else ''}")
        if files:
            bits.append(f"{files} file{'s' if files != 1 else ''} · {human_size(total)}")
        self.summary.setText(" · ".join(bits) if bits else "Empty folder")

    def _clip_item(self, path: str, entry: RemoteEntry) -> ClipItem:
        if self.side is Side.REMOTE:
            return ClipItem.from_remote(entry, path)
        return ClipItem(Side.LOCAL, str(Path(path) / entry.name),
                        entry.name, entry.is_dir, entry.size)

    def clear(self, message: str = "") -> None:
        self.tree.clear()
        self.path_edit.setText("")
        self.summary.setText(message)
        self.current_path = ""

    # ----------------------------------------------------------- behaviour

    def _activated(self, item: QTreeWidgetItem, _column: int) -> None:
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(data, ClipItem) and data.is_dir:
            self.navigate.emit(data.path)

    def _path_entered(self) -> None:
        text = self.path_edit.text().strip()
        if text:
            self.navigate.emit(
                normalise_remote(text) if self.side is Side.REMOTE
                else str(Path(text).expanduser())
            )

    def go_up(self) -> None:
        if not self.current_path:
            return
        if self.side is Side.REMOTE:
            parent = normalise_remote(self.current_path.rsplit("/", 1)[0] or "/")
        else:
            parent = str(Path(self.current_path).parent)
        if parent != self.current_path:
            self.navigate.emit(parent)

    def go_home(self) -> None:
        self.navigate.emit("~" if self.side is Side.LOCAL else "/")

    def _emit_copy(self, is_cut: bool) -> None:
        items = self.tree.selected_clip_items()
        if items:
            self.copy_requested.emit(items, is_cut)

    def _selection_changed(self) -> None:
        items = self.tree.selected_clip_items()
        if not items:
            self.hint.setText("")
            return
        total = sum(i.size for i in items)
        label = f"{len(items)} selected"
        if total:
            label += f" · {human_size(total)}"
        self.hint.setText(label)

    def _begin_rename(self) -> None:
        items = self.tree.selected_clip_items()
        if len(items) == 1:
            self.rename_requested.emit(items[0], items[0].name)

    def _context_menu(self, point: QPoint) -> None:
        items = self.tree.selected_clip_items()
        menu = QMenu(self)
        p = self.palette_

        act_copy = QAction(icon("copy", p.text), "Copy", self)
        act_copy.setShortcut(QKeySequence.StandardKey.Copy)
        act_copy.setEnabled(bool(items))
        act_copy.triggered.connect(lambda: self._emit_copy(False))
        menu.addAction(act_copy)

        act_paste = QAction(icon("paste", p.text), "Paste here", self)
        act_paste.setShortcut(QKeySequence.StandardKey.Paste)
        act_paste.triggered.connect(self.paste_requested.emit)
        menu.addAction(act_paste)

        menu.addSeparator()
        act_new = QAction(icon("newfolder", p.text), "New folder…", self)
        act_new.triggered.connect(self.mkdir_requested.emit)
        menu.addAction(act_new)

        act_rename = QAction("Rename…", self)
        act_rename.setEnabled(len(items) == 1)
        act_rename.triggered.connect(self._begin_rename)
        menu.addAction(act_rename)

        act_delete = QAction(icon("trash", p.danger), "Delete", self)
        act_delete.setEnabled(bool(items))
        act_delete.triggered.connect(lambda: self.delete_requested.emit(items))
        menu.addAction(act_delete)

        menu.addSeparator()
        act_refresh = QAction(icon("refresh", p.text), "Refresh", self)
        act_refresh.triggered.connect(self.refresh_button.click)
        menu.addAction(act_refresh)
        menu.exec(self.tree.viewport().mapToGlobal(point))


class LocalPane(FilePane):
    """The device side.  Reads the filesystem directly on the GUI thread —
    a local ``listdir`` is microseconds, unlike a network round trip."""

    def __init__(self, palette: Palette, parent: Optional[QWidget] = None) -> None:
        super().__init__("THIS DEVICE", Side.LOCAL, palette, parent)
        self.path_edit.setPlaceholderText("Local folder")
        self.navigate.connect(self.load)
        self.refresh_button.clicked.connect(lambda: self.load(self.current_path))
        self.show_hidden = False

    def load(self, path: str) -> None:
        target = Path(path).expanduser() if path else Path.home()
        if not target.is_dir():
            target = Path.home()
        entries = []
        try:
            for child in os.scandir(target):
                try:
                    stat = child.stat(follow_symlinks=False)
                    is_dir = child.is_dir(follow_symlinks=True)
                except OSError:
                    continue
                entries.append(RemoteEntry(
                    name=child.name,
                    size=0 if is_dir else stat.st_size,
                    mtime=stat.st_mtime,
                    is_dir=is_dir,
                    is_symlink=child.is_symlink(),
                    mode=_mode_string(stat.st_mode),
                ))
        except PermissionError:
            self.clear(f"Permission denied: {target}")
            self.current_path = str(target)
            self.path_edit.setText(str(target))
            return
        except OSError as exc:
            self.clear(str(exc))
            return
        self.show_entries(str(target), entries, self.show_hidden)


class RemotePane(FilePane):
    """The server side.  Every action is a request to the worker thread."""

    def __init__(self, palette: Palette, parent: Optional[QWidget] = None) -> None:
        super().__init__("SERVER", Side.REMOTE, palette, parent)
        self.clear("Not connected")


def _mode_string(mode: int) -> str:
    import stat as stat_mod

    try:
        return stat_mod.filemode(mode)
    except (TypeError, ValueError):
        return ""
