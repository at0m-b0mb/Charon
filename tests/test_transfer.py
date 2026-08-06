"""Transfer-engine behaviour, driven by a fake transport.

The fake server is deliberately hostile in places: it serves a directory entry
called ``../../../../etc/passwd`` and a symlink loop, because that is what the
engine's guards exist for.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from charon.core.model import Credentials, RemoteEntry, Site
from charon.core.policy import Policy
from charon.core.transfer import (
    Conflict,
    Direction,
    JobState,
    TransferEngine,
    TransferJob,
    sha256_file,
    unique_path,
)
from charon.core.transport import TransferCancelled, Transport, TransportError

CONTENT = b"charon test payload " * 500


class FakeTransport(Transport):
    """An in-memory server, including the nasty listings a real one can send."""

    def __init__(self, files: dict[str, bytes] | None = None,
                 tree: dict[str, list[RemoteEntry]] | None = None,
                 hash_support: bool = False) -> None:
        super().__init__(Site(name="fake", host="fake"), Policy())
        self.files = files if files is not None else {"/data/report.pdf": CONTENT}
        self.tree = tree or {}
        self.hash_support = hash_support
        self.closed = False
        self.made_dirs: list[str] = []
        self.stall = 0.0

    def connect(self, creds: Credentials) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    @property
    def is_connected(self) -> bool:
        return not self.closed

    def home(self) -> str:
        return "/data"

    def listdir(self, path: str) -> list[RemoteEntry]:
        return self.tree.get(path, [])

    def stat(self, path: str) -> RemoteEntry:
        if path not in self.files:
            raise TransportError(f"no such file: {path}")
        return RemoteEntry(name=path.rsplit("/", 1)[-1], size=len(self.files[path]))

    def mkdir(self, path: str) -> None:
        self.made_dirs.append(path)

    def remove(self, path: str) -> None:
        self.files.pop(path, None)

    def rmdir(self, path: str) -> None:
        pass

    def rename(self, old: str, new: str) -> None:
        self.files[new] = self.files.pop(old)

    def download(self, remote, sink, *, offset=0, size=0, progress=None, cancel=None):
        data = self.files.get(remote)
        if data is None:
            raise TransportError(f"no such file: {remote}")
        data = data[offset:]
        done = offset
        for i in range(0, len(data), 4096):
            if cancel is not None and cancel.is_set():
                raise TransferCancelled()
            if self.stall:
                time.sleep(self.stall)
            block = data[i:i + 4096]
            sink.write(block)
            done += len(block)
            if progress:
                progress(done, size)
        return done

    def upload(self, source, remote, *, offset=0, size=0, progress=None, cancel=None):
        chunks = []
        done = offset
        while True:
            if cancel is not None and cancel.is_set():
                raise TransferCancelled()
            block = source.read(4096)
            if not block:
                break
            chunks.append(block)
            done += len(block)
            if progress:
                progress(done, size)
        self.files[remote] = b"".join(chunks)
        return done

    def remote_sha256(self, path: str):
        if not self.hash_support or path not in self.files:
            return None
        return hashlib.sha256(self.files[path]).hexdigest()


@pytest.fixture
def engine_for():
    engines = []

    def build(transport, **kwargs):
        engine = TransferEngine(connect=lambda: transport, **kwargs)
        engines.append(engine)
        return engine

    yield build
    for engine in engines:
        engine.shutdown()


def wait_for(predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


# ------------------------------------------------------------------ download

def test_a_download_lands_intact_and_verifies(tmp_path, engine_for):
    transport = FakeTransport(hash_support=True)
    engine = engine_for(transport)
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "report.pdf",
                      size=len(CONTENT))
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final), job.error
    assert job.state is JobState.DONE, job.error
    assert (tmp_path / "report.pdf").read_bytes() == CONTENT
    assert "SHA-256 verified" in job.integrity


def test_an_honest_message_when_the_server_cannot_hash(tmp_path, engine_for):
    """Most servers (OpenSSH included) have no remote-hash extension. Charon
    must not claim a content match it never made."""
    engine = engine_for(FakeTransport(hash_support=False))
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "r.pdf",
                      size=len(CONTENT))
    engine.submit([job])
    assert wait_for(lambda: job.state.is_final)
    assert job.state is JobState.DONE
    assert "size verified" in job.integrity
    assert "server offers no hash" in job.integrity


def test_a_corrupted_download_is_discarded(tmp_path, engine_for):
    """The server's hash disagrees with the bytes that arrived: the file must
    not survive."""
    transport = FakeTransport(hash_support=True)
    real_hash = transport.remote_sha256
    transport.remote_sha256 = lambda path: "0" * 64  # type: ignore[assignment]
    engine = engine_for(transport)
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "r.pdf",
                      size=len(CONTENT))
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final)
    assert job.state is JobState.FAILED
    assert "SHA-256 mismatch" in job.error
    assert not (tmp_path / "r.pdf").exists()
    assert not list(tmp_path.glob("*.charon-part")), "the bad partial was left behind"
    assert real_hash is not None


def test_a_truncated_download_is_discarded(tmp_path, engine_for):
    transport = FakeTransport(files={"/data/x.bin": CONTENT[:100]})
    engine = engine_for(transport)
    job = TransferJob(Direction.DOWNLOAD, "/data/x.bin", tmp_path / "x.bin",
                      size=len(CONTENT))  # server will send fewer bytes
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final)
    assert job.state is JobState.FAILED
    assert "Size mismatch" in job.error
    assert not (tmp_path / "x.bin").exists()


def test_a_partial_download_is_never_mistaken_for_a_complete_file(tmp_path, engine_for):
    transport = FakeTransport()
    transport.stall = 0.05
    engine = engine_for(transport)
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "report.pdf",
                      size=len(CONTENT))
    engine.submit([job])

    assert wait_for(lambda: job.state is JobState.RUNNING and job.transferred > 0)
    # Mid-flight, the real filename must not exist yet — only the .part sidecar.
    assert not (tmp_path / "report.pdf").exists()
    assert (tmp_path / "report.pdf.charon-part").exists()
    engine.cancel(job.id)
    assert wait_for(lambda: job.state.is_final)
    assert job.state is JobState.CANCELLED
    assert not (tmp_path / "report.pdf").exists()


def test_an_interrupted_download_can_be_resumed(tmp_path, engine_for):
    part = tmp_path / "report.pdf.charon-part"
    part.write_bytes(CONTENT[:2000])
    engine = engine_for(FakeTransport())
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "report.pdf",
                      size=len(CONTENT), conflict=Conflict.RESUME)
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final), job.error
    assert job.state is JobState.DONE, job.error
    assert (tmp_path / "report.pdf").read_bytes() == CONTENT


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permissions")
def test_downloads_are_private_by_default(tmp_path, engine_for):
    engine = engine_for(FakeTransport())
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "r.pdf",
                      size=len(CONTENT))
    engine.submit([job])
    assert wait_for(lambda: job.state.is_final)
    assert stat.S_IMODE(os.stat(tmp_path / "r.pdf").st_mode) == 0o600


# ----------------------------------------------------------------- conflicts

def test_the_default_conflict_rule_never_destroys_an_existing_file(tmp_path, engine_for):
    existing = tmp_path / "report.pdf"
    existing.write_bytes(b"the file that was already here")
    engine = engine_for(FakeTransport())
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", existing,
                      size=len(CONTENT))  # Conflict.RENAME is the default
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final)
    assert existing.read_bytes() == b"the file that was already here"
    assert (tmp_path / "report (2).pdf").read_bytes() == CONTENT


def test_skip_leaves_the_existing_file_alone(tmp_path, engine_for):
    existing = tmp_path / "report.pdf"
    existing.write_bytes(b"keep me")
    engine = engine_for(FakeTransport())
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", existing,
                      size=len(CONTENT), conflict=Conflict.SKIP)
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final)
    assert job.state is JobState.SKIPPED
    assert existing.read_bytes() == b"keep me"


def test_overwrite_replaces_it(tmp_path, engine_for):
    existing = tmp_path / "report.pdf"
    existing.write_bytes(b"old")
    engine = engine_for(FakeTransport())
    job = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", existing,
                      size=len(CONTENT), conflict=Conflict.OVERWRITE)
    engine.submit([job])
    assert wait_for(lambda: job.state.is_final)
    assert existing.read_bytes() == CONTENT


def test_unique_path_numbers_upwards(tmp_path):
    target = tmp_path / "a.txt"
    assert unique_path(target) == target
    target.write_text("x")
    assert unique_path(target).name == "a (2).txt"
    (tmp_path / "a (2).txt").write_text("x")
    assert unique_path(target).name == "a (3).txt"


# ------------------------------------------------------------------- uploads

def test_an_upload_arrives_intact(tmp_path, engine_for):
    source = tmp_path / "notes.txt"
    source.write_bytes(CONTENT)
    transport = FakeTransport(files={})
    engine = engine_for(transport)
    job = TransferJob(Direction.UPLOAD, "/data/notes.txt", source, size=len(CONTENT))
    engine.submit([job])

    assert wait_for(lambda: job.state.is_final), job.error
    assert job.state is JobState.DONE, job.error
    assert transport.files["/data/notes.txt"] == CONTENT


# ------------------------------------------------------- hostile directories

def test_a_malicious_listing_cannot_escape_the_download_folder(tmp_path, engine_for):
    """The zip-slip case. A server answers with an entry named
    ``../../../../etc/passwd``; the bytes must land inside the chosen folder."""
    engine = engine_for(FakeTransport(
        files={"/evil/../../../../etc/passwd": b"root:x:0:0"},
        tree={"/evil": [RemoteEntry(name="../../../../etc/passwd", size=10)]},
    ))
    transport = FakeTransport(tree={"/evil": [
        RemoteEntry(name="../../../../etc/passwd", size=10)]})
    dest = tmp_path / "downloads"
    dest.mkdir()

    jobs = engine.expand_download(
        transport, RemoteEntry(name="evil", is_dir=True), "/", dest)

    assert jobs, "the entry should still be downloadable, just not where it asked"
    for job in jobs:
        assert dest.resolve() in job.local_path.resolve().parents
        assert ".." not in job.local_path.parts


def test_remote_symlinks_are_not_followed_when_copying_a_folder(engine_for, tmp_path):
    """A symlink in a directory listing is how "download this folder" becomes
    "download all of /etc"."""
    transport = FakeTransport(tree={"/data": [
        RemoteEntry(name="real.txt", size=10),
        RemoteEntry(name="sneaky", is_dir=True, is_symlink=True),
    ]})
    engine = engine_for(transport)
    jobs = engine.expand_download(
        transport, RemoteEntry(name="data", is_dir=True), "/", tmp_path)
    assert [j.local_path.name for j in jobs] == ["real.txt"]


def test_recursion_is_depth_capped(engine_for, tmp_path):
    """A directory that contains itself must not hang the client."""
    loop = {"/loop": [RemoteEntry(name="loop", is_dir=True)]}
    transport = FakeTransport(tree=loop)
    engine = engine_for(transport)
    jobs = engine.expand_download(
        transport, RemoteEntry(name="loop", is_dir=True), "/", tmp_path)
    assert jobs == []  # bottomed out at the depth cap rather than recursing forever


# -------------------------------------------------------------------- queue

def test_queued_jobs_can_be_cancelled_before_they_start(tmp_path, engine_for):
    transport = FakeTransport(files={f"/data/f{i}": CONTENT for i in range(4)})
    transport.stall = 0.05
    engine = engine_for(transport)
    jobs = engine.submit([
        TransferJob(Direction.DOWNLOAD, f"/data/f{i}", tmp_path / f"f{i}",
                    size=len(CONTENT))
        for i in range(4)
    ])
    engine.cancel_all()
    assert wait_for(lambda: all(j.state.is_final for j in jobs))
    assert any(j.state is JobState.CANCELLED for j in jobs)


def test_one_failure_does_not_poison_the_rest_of_the_queue(tmp_path, engine_for):
    engine = engine_for(FakeTransport())
    bad = TransferJob(Direction.DOWNLOAD, "/data/missing", tmp_path / "missing",
                      size=10)
    good = TransferJob(Direction.DOWNLOAD, "/data/report.pdf", tmp_path / "ok.pdf",
                       size=len(CONTENT))
    engine.submit([bad, good])

    assert wait_for(lambda: bad.state.is_final and good.state.is_final)
    assert bad.state is JobState.FAILED
    assert good.state is JobState.DONE, good.error


def test_sha256_file_matches_hashlib(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(CONTENT)
    assert sha256_file(path) == hashlib.sha256(CONTENT).hexdigest()
