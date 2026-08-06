"""Copy/paste rules — Charon's main way of moving files."""

from __future__ import annotations

from pathlib import Path

from charon.core.clipboard import ClipItem, Operation, Side, TransferClipboard
from charon.core.model import RemoteEntry


def remote(name="report.pdf", size=100, is_dir=False) -> ClipItem:
    return ClipItem.from_remote(
        RemoteEntry(name=name, size=size, is_dir=is_dir), "/data")


def local(tmp_path, name="notes.txt") -> ClipItem:
    path = tmp_path / name
    path.write_text("x")
    return ClipItem.from_local(path)


def test_copying_from_the_server_builds_a_full_remote_path():
    item = remote()
    assert item.side is Side.REMOTE
    assert item.path == "/data/report.pdf"


def test_a_remote_listing_entry_cannot_escape_its_directory():
    """Even at clipboard time, a hostile listing name is confined."""
    item = ClipItem.from_remote(RemoteEntry(name="../../etc/passwd"), "/data")
    assert item.path == "/data/passwd"


def test_pasting_remote_items_into_the_local_pane_is_allowed():
    clip = TransferClipboard()
    clip.set([remote()], Operation.COPY, session_id="s1", session_label="nas")
    ok, why = clip.can_paste_into(Side.LOCAL, "s1")
    assert ok, why


def test_pasting_back_into_the_pane_they_came_from_is_refused():
    """A stray Ctrl+V must never start a server-to-itself copy."""
    clip = TransferClipboard()
    clip.set([remote()], Operation.COPY, session_id="s1")
    ok, why = clip.can_paste_into(Side.REMOTE, "s1")
    assert not ok
    assert "same pane" in why


def test_items_copied_from_another_server_are_refused():
    """Copy from server A, reconnect to server B, paste — those paths mean
    something different now, so the paste must not silently proceed."""
    clip = TransferClipboard()
    clip.set([remote()], Operation.COPY, session_id="session-A", session_label="nas")
    ok, why = clip.can_paste_into(Side.LOCAL, "session-B")
    assert not ok
    assert "nas" in why


def test_pasting_with_no_connection_is_refused(tmp_path):
    clip = TransferClipboard()
    clip.set([local(tmp_path)], Operation.COPY)
    ok, why = clip.can_paste_into(Side.REMOTE, "")
    assert not ok
    assert "Connect" in why


def test_an_empty_clipboard_pastes_nothing():
    ok, why = TransferClipboard().can_paste_into(Side.LOCAL, "s1")
    assert not ok
    assert "nothing" in why.lower()


def test_uploading_local_items_is_allowed_when_connected(tmp_path):
    clip = TransferClipboard()
    clip.set([local(tmp_path)], Operation.COPY)
    ok, why = clip.can_paste_into(Side.REMOTE, "s1")
    assert ok, why


def test_summary_reads_naturally():
    clip = TransferClipboard()
    clip.set([remote()], Operation.COPY, session_id="s1")
    assert clip.summary() == "Copied “report.pdf”"
    clip.set([remote("a"), remote("b")], Operation.CUT, session_id="s1")
    assert clip.summary() == "Cut 2 items"


def test_clearing_drops_the_session_binding():
    clip = TransferClipboard()
    clip.set([remote()], Operation.COPY, session_id="s1")
    clip.clear()
    assert clip.is_empty
    assert clip.session_id == ""


def test_total_size_adds_up():
    clip = TransferClipboard()
    clip.set([remote("a", 100), remote("b", 250)], Operation.COPY, session_id="s1")
    assert clip.total_size == 350
