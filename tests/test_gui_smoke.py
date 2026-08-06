"""GUI smoke tests, run offscreen.

These do not try to be a UI test suite.  They prove the window builds, that the
security badge tells the truth about each grade, and that the panes render a
directory listing — enough that a broken widget cannot ship unnoticed.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from charon.core.clipboard import Side  # noqa: E402
from charon.core.model import Grade, Protocol, RemoteEntry, SecurityState  # noqa: E402


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    monkeypatch.setenv("CHARON_HOME", str(tmp_path / "config"))
    from charon.ui.main_window import MainWindow

    win = MainWindow()
    yield win
    win.thread.quit()
    win.thread.wait(2000)
    win.close()


def test_the_window_builds_and_starts_disconnected(window):
    assert window.badge.label.text() == "Not connected"
    assert window.banner.isHidden()
    assert not window.act_download.isEnabled()
    assert not window.act_upload.isEnabled()


def test_the_local_pane_lists_real_files(window, tmp_path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "one.txt").write_text("a")
    (folder / "two.bin").write_bytes(b"bb")
    (folder / "sub").mkdir()

    window.local_pane.load(str(folder))
    names = {window.local_pane.tree.topLevelItem(i).text(0)
             for i in range(window.local_pane.tree.topLevelItemCount())}
    assert names == {"one.txt", "two.bin", "sub"}


def test_hidden_files_are_hidden_until_asked_for(window, tmp_path):
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / ".ssh_config").write_text("x")
    (folder / "visible.txt").write_text("x")

    window.local_pane.show_hidden = False
    window.local_pane.load(str(folder))
    assert window.local_pane.tree.topLevelItemCount() == 1

    window.local_pane.show_hidden = True
    window.local_pane.load(str(folder))
    assert window.local_pane.tree.topLevelItemCount() == 2


def test_the_remote_pane_renders_a_listing(window):
    entries = [
        RemoteEntry(name="report.pdf", size=2048, mtime=1_710_000_000, mode="-rw-r--r--"),
        RemoteEntry(name="archive", is_dir=True, mode="drwxr-xr-x"),
    ]
    window.on_listed("/srv/data", entries)
    assert window.remote_pane.path_edit.text() == "/srv/data"
    assert window.remote_pane.tree.topLevelItemCount() == 2
    assert "1 folder" in window.remote_pane.summary.text()


@pytest.mark.parametrize("state, expected", [
    (SecurityState(protocol=Protocol.SFTP, encrypted=True, identity_verified=True),
     "Secure"),
    (SecurityState(protocol=Protocol.FTPS, encrypted=True, identity_verified=False),
     "Encrypted, identity unconfirmed"),
    (SecurityState(protocol=Protocol.FTP, encrypted=False), "NOT SECURE"),
])
def test_the_badge_reports_the_live_grade(window, state, expected):
    window.badge.set_state(state)
    assert window.badge.label.text() == expected


def test_a_plaintext_session_raises_the_red_banner(window):
    window.on_connected(SecurityState(protocol=Protocol.FTP, encrypted=False), "/")
    assert not window.banner.isHidden()
    assert "UNENCRYPTED" in window.banner.text()


def test_an_encrypted_session_shows_no_banner(window):
    window.on_connected(
        SecurityState(protocol=Protocol.SFTP, encrypted=True, identity_verified=True),
        "/home/kai")
    assert window.banner.isHidden()


def test_copying_updates_the_clipboard_and_the_status_bar(window):
    window.on_listed("/srv/data", [RemoteEntry(name="report.pdf", size=2048)])
    items = [window.remote_pane.tree.topLevelItem(0).data(0, Qt.ItemDataRole.UserRole)]
    window.on_copy(items, is_cut=False)
    assert not window.clipboard.is_empty
    assert "report.pdf" in window.clip_label.text()
    assert "this device" in window.status_label.text()


def test_pasting_into_the_wrong_pane_is_refused_without_a_transfer(window, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    window.on_listed("/srv/data", [RemoteEntry(name="report.pdf", size=2048)])
    items = [window.remote_pane.tree.topLevelItem(0).data(0, Qt.ItemDataRole.UserRole)]
    window.on_copy(items, is_cut=False)

    window.on_paste(Side.REMOTE)  # same side the items came from
    assert window.engine is None, "no transfer engine should have been started"
