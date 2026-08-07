"""Deletion must target the path the user picked, not a name re-resolved later.

The worker's delete slot used to take bare filenames and join them onto the
transport's *current* directory.  That is fine right up until the delete is
queued behind a long transfer, or waits under a confirmation dialog, while the
user browses somewhere else — at which point it erases a same-named file in a
directory they never selected.
"""

from __future__ import annotations

import pytest

from charon.core.model import Credentials, RemoteEntry, Site
from charon.core.policy import Policy
from charon.core.transport import Transport, TransportError


class RecordingTransport(Transport):
    """Remembers exactly which paths were asked to be removed."""

    def __init__(self, tree: dict[str, list[RemoteEntry]] | None = None) -> None:
        super().__init__(Site(name="fake", host="fake"), Policy())
        self.removed: list[str] = []
        self.removed_dirs: list[str] = []
        self.tree = tree or {}
        self._cwd = "/home/kai"

    def connect(self, creds: Credentials) -> None: ...

    def close(self) -> None: ...

    @property
    def is_connected(self) -> bool:
        return True

    def home(self) -> str:
        return "/home/kai"

    def listdir(self, path: str) -> list[RemoteEntry]:
        return self.tree.get(path, [])

    def stat(self, path: str) -> RemoteEntry:
        raise TransportError("no")

    def mkdir(self, path: str) -> None: ...

    def remove(self, path: str) -> None:
        self.removed.append(path)

    def rmdir(self, path: str) -> None:
        self.removed_dirs.append(path)

    def rename(self, old: str, new: str) -> None: ...

    def download(self, remote, sink, **kw): return 0

    def upload(self, source, remote, **kw): return 0


@pytest.fixture
def worker(monkeypatch, tmp_path):
    monkeypatch.setenv("CHARON_HOME", str(tmp_path / "config"))
    pytest.importorskip("PyQt6.QtCore")
    from charon.ui.worker import SessionWorker

    return SessionWorker()


def test_delete_uses_the_absolute_path_it_was_given(worker):
    transport = RecordingTransport()
    worker._transport = transport

    worker.do_delete([("/archive/2019/old.log", False, False)])

    assert transport.removed == ["/archive/2019/old.log"]


def test_navigating_away_cannot_redirect_a_pending_delete(worker):
    """The bug this file exists for.

    The user selects /archive/2019/notes.txt, the confirmation sits on screen,
    and meanwhile the pane moves to /home/kai — which happens to hold its own
    notes.txt.  The delete must still hit the file that was selected.
    """
    transport = RecordingTransport()
    worker._transport = transport
    targets = [("/archive/2019/notes.txt", False, False)]

    transport.set_cwd("/home/kai")  # user browsed elsewhere in the meantime
    worker.do_delete(targets)

    assert transport.removed == ["/archive/2019/notes.txt"]
    assert "/home/kai/notes.txt" not in transport.removed


def test_a_directory_is_removed_depth_first(worker):
    transport = RecordingTransport(tree={
        "/data/logs": [RemoteEntry(name="a.log"), RemoteEntry(name="sub", is_dir=True)],
        "/data/logs/sub": [RemoteEntry(name="b.log")],
    })
    worker._transport = transport

    worker.do_delete([("/data/logs", True, False)])

    assert transport.removed == ["/data/logs/a.log", "/data/logs/sub/b.log"]
    assert transport.removed_dirs == ["/data/logs/sub", "/data/logs"]


def test_a_symlinked_directory_is_unlinked_not_walked(worker):
    """Recursing into a remote symlink would delete whatever it points at."""
    transport = RecordingTransport(tree={"/data/link": [RemoteEntry(name="victim")]})
    worker._transport = transport

    worker.do_delete([("/data/link", True, True)])

    assert transport.removed == ["/data/link"]
    assert transport.removed_dirs == []


def test_paths_are_normalised_before_use(worker):
    transport = RecordingTransport()
    worker._transport = transport

    worker.do_delete([("/data//logs/../notes.txt", False, False)])

    assert transport.removed == ["/data/notes.txt"]
