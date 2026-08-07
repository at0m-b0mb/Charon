"""The transfer engine: a queue, a worker thread, and the rules for writing files.

Three properties matter more than throughput here:

**A partial download must never look like a complete file.**  Bytes land in a
``.charon-part`` sidecar and are moved into place with a single ``os.replace``
only after the whole transfer verified.  Pull the network cable and you are left
with an obvious ``.part`` file, not a truncated document that opens fine and is
quietly missing its last chapter.

**A remote server must never choose a local path.**  Every filename from a
listing goes through :mod:`charon.core.safety` before it touches the filesystem,
so a server answering with ``../../.ssh/authorized_keys`` writes a file called
``.ssh_authorized_keys`` inside the download folder, and nothing else.

**Nothing is overwritten by accident.**  The default conflict rule invents a new
name.  Destroying an existing local file takes a deliberate choice.
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

from .model import RemoteEntry
from .safety import UnsafeNameError, remote_join, resolve_within
from .transport import TransferCancelled, Transport, TransportError

log = logging.getLogger(__name__)

PART_SUFFIX = ".charon-part"

__all__ = [
    "Direction", "JobState", "Conflict", "TransferJob", "TransferEngine",
    "unique_path", "sha256_file",
]


class Direction(str, Enum):
    DOWNLOAD = "download"
    UPLOAD = "upload"


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"

    @property
    def is_final(self) -> bool:
        return self in (JobState.DONE, JobState.FAILED, JobState.CANCELLED, JobState.SKIPPED)


class Conflict(str, Enum):
    """What to do when the destination already exists."""

    RENAME = "rename"        # default: write "report (2).pdf" — never destroys data
    OVERWRITE = "overwrite"
    SKIP = "skip"
    RESUME = "resume"        # continue a matching .charon-part, else start fresh


@dataclass
class TransferJob:
    direction: Direction
    remote_path: str
    local_path: Path
    size: int = 0
    conflict: Conflict = Conflict.RENAME
    state: JobState = JobState.QUEUED
    transferred: int = 0
    error: str = ""
    integrity: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    id: int = 0

    @property
    def name(self) -> str:
        return self.local_path.name

    @property
    def percent(self) -> int:
        if self.state is JobState.DONE:
            return 100
        if not self.size:
            return 0
        return min(100, int(self.transferred * 100 / self.size))

    @property
    def speed(self) -> float:
        """Bytes per second, averaged over the life of the job."""
        end = self.finished_at or time.time()
        elapsed = end - self.started_at
        return self.transferred / elapsed if self.started_at and elapsed > 0.05 else 0.0

    @property
    def eta(self) -> float:
        rate = self.speed
        remaining = max(0, self.size - self.transferred)
        return remaining / rate if rate > 0 and self.size else 0.0


def unique_path(path: Path) -> Path:
    """``report.pdf`` → ``report (2).pdf`` → ``report (3).pdf`` …"""
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for n in range(2, 10_000):
        candidate = parent / f"{stem} ({n}){suffix}"
        if not candidate.exists():
            return candidate
    raise OSError(f"cannot find a free filename next to {path}")


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


class TransferEngine:
    """Runs queued jobs on a private thread against its own transport.

    The engine owns a *second* connection to the server so that a large upload
    never blocks directory browsing — the transports themselves are single
    socket state machines and are not safe to share between threads.
    """

    def __init__(
        self,
        connect: Callable[[], Transport],
        on_change: Callable[[TransferJob], None] = lambda job: None,
        on_idle: Callable[[], None] = lambda: None,
        private_downloads: bool = True,
        verify: bool = True,
    ) -> None:
        self._connect = connect
        self._on_change = on_change
        self._on_idle = on_idle
        self.private_downloads = private_downloads
        self.verify = verify

        self._queue: "queue.Queue[Optional[TransferJob]]" = queue.Queue()
        self._jobs: list[TransferJob] = []
        self._lock = threading.Lock()
        self._cancel_current = threading.Event()
        self._stopping = threading.Event()
        self._transport: Optional[Transport] = None
        self._next_id = 1
        self._thread = threading.Thread(target=self._run, name="charon-transfer", daemon=True)
        self._thread.start()

    # -------------------------------------------------------------- public

    @property
    def jobs(self) -> list[TransferJob]:
        with self._lock:
            return list(self._jobs)

    @property
    def active(self) -> int:
        return sum(1 for j in self.jobs if not j.state.is_final)

    def submit(self, jobs: Iterable[TransferJob]) -> list[TransferJob]:
        added = []
        with self._lock:
            for job in jobs:
                job.id = self._next_id
                self._next_id += 1
                self._jobs.append(job)
                added.append(job)
        for job in added:
            self._queue.put(job)
            self._on_change(job)
        return added

    def cancel(self, job_id: int) -> None:
        for job in self.jobs:
            if job.id != job_id:
                continue
            if job.state is JobState.RUNNING:
                self._cancel_current.set()
            elif job.state is JobState.QUEUED:
                job.state = JobState.CANCELLED
                self._on_change(job)
            return

    def cancel_all(self) -> None:
        for job in self.jobs:
            if job.state is JobState.QUEUED:
                job.state = JobState.CANCELLED
                self._on_change(job)
        self._cancel_current.set()

    def clear_finished(self) -> None:
        with self._lock:
            self._jobs = [j for j in self._jobs if not j.state.is_final]

    def shutdown(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        self._cancel_current.set()
        self._queue.put(None)
        self._thread.join(timeout=timeout)
        self._drop_transport()

    # ------------------------------------------------------ directory walk

    def expand_download(
        self,
        transport: Transport,
        entry: RemoteEntry,
        remote_dir: str,
        local_dir: Path,
        conflict: Conflict = Conflict.RENAME,
        _depth: int = 0,
    ) -> list[TransferJob]:
        """Turn a selected remote item into concrete file jobs.

        Runs on the *caller's* transport (the browsing one) because it only
        lists directories.  Symlinks are not followed and the recursion is
        depth-capped: a server can serve a directory tree that links to itself,
        and a client that walks it naively never returns.
        """
        if _depth > 32:
            log.warning("refusing to descend past 32 levels at %s", remote_dir)
            return []

        remote_path = remote_join(remote_dir, entry.name)
        if entry.is_symlink:
            # Following a remote symlink is how a "download this folder" turns
            # into "download all of /etc". Copy the link's own listing entry
            # only if it resolves to a regular file inside the tree.
            log.info("skipping symlink %s", remote_path)
            return []

        if not entry.is_dir:
            target = resolve_within(local_dir, entry.name)
            return [TransferJob(Direction.DOWNLOAD, remote_path, target,
                                size=entry.size, conflict=conflict)]

        sub_local = resolve_within(local_dir, entry.name)
        sub_local.mkdir(parents=True, exist_ok=True)
        jobs: list[TransferJob] = []
        for child in transport.listdir(remote_path):
            if child.name in (".", ".."):
                continue
            try:
                jobs.extend(self.expand_download(transport, child, remote_path,
                                                 sub_local, conflict, _depth + 1))
            except UnsafeNameError as exc:
                log.warning("dropping unsafe remote entry %r: %s", child.name, exc)
        return jobs

    def expand_upload(
        self,
        local_path: Path,
        remote_dir: str,
        conflict: Conflict = Conflict.RENAME,
        _depth: int = 0,
    ) -> list[TransferJob]:
        if _depth > 32 or local_path.is_symlink():
            return []
        if local_path.is_file():
            remote = remote_join(remote_dir, local_path.name)
            return [TransferJob(Direction.UPLOAD, remote, local_path,
                                size=local_path.stat().st_size, conflict=conflict)]
        if not local_path.is_dir():
            return []
        sub_remote = remote_join(remote_dir, local_path.name)
        jobs = [TransferJob(Direction.UPLOAD, sub_remote, local_path,
                            size=-1, conflict=conflict)]  # size -1 marks "mkdir"
        for child in sorted(local_path.iterdir()):
            jobs.extend(self.expand_upload(child, sub_remote, conflict, _depth + 1))
        return jobs

    # -------------------------------------------------------------- worker

    def _run(self) -> None:
        while not self._stopping.is_set():
            job = self._queue.get()
            if job is None:
                break
            if job.state is not JobState.QUEUED:
                continue
            self._cancel_current.clear()
            self._execute(job)
            if self._queue.empty():
                self._on_idle()
        self._drop_transport()

    def _transport_or_connect(self) -> Transport:
        if self._transport is not None and not self._transport.is_connected:
            self._drop_transport()
        if self._transport is None:
            self._transport = self._connect()
        return self._transport

    def _drop_transport(self) -> None:
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None

    def _execute(self, job: TransferJob) -> None:
        job.state = JobState.RUNNING
        job.started_at = time.time()
        job.transferred = 0
        self._on_change(job)

        try:
            transport = self._transport_or_connect()
            if job.direction is Direction.DOWNLOAD:
                self._download(transport, job)
            else:
                self._upload(transport, job)
        except TransferCancelled:
            job.state = JobState.CANCELLED
        except (TransportError, OSError, UnsafeNameError) as exc:
            job.state = JobState.FAILED
            job.error = str(exc)
            log.warning("job %s failed: %s", job.remote_path, exc)
            # A broken transport must not poison every job behind it.
            self._drop_transport()
        except Exception as exc:  # pragma: no cover - defensive
            job.state = JobState.FAILED
            job.error = f"Unexpected error: {exc}"
            log.exception("unexpected failure on %s", job.remote_path)
            self._drop_transport()
        finally:
            if job.state is JobState.RUNNING:
                job.state = JobState.DONE
            job.finished_at = time.time()
            self._on_change(job)

    # ------------------------------------------------------------ download

    def _download(self, transport: Transport, job: TransferJob) -> None:
        dest = job.local_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(dest.name + PART_SUFFIX)

        # Can this actually resume?  Only if there is a partial file to continue
        # from *and* the protocol supports an offset.
        resumable = (
            job.conflict is Conflict.RESUME
            and part.exists()
            and transport.supports_resume()
        )

        if dest.exists():
            if job.conflict is Conflict.SKIP:
                job.state = JobState.SKIPPED
                return
            # "Resume" with nothing to resume is just a plain download, and the
            # destination is already a complete file.  Overwriting it here would
            # destroy data the user never agreed to lose, so it falls back to
            # keep-both — the same promise the default conflict rule makes.
            if job.conflict is Conflict.RENAME or (
                job.conflict is Conflict.RESUME and not resumable
            ):
                dest = unique_path(dest)
                job.local_path = dest
                part = dest.with_name(dest.name + PART_SUFFIX)

        offset = 0
        if resumable and part.exists():
            offset = part.stat().st_size
            if job.size and offset > job.size:
                offset = 0  # server's copy shrank; start over rather than guess
        if offset == 0 and part.exists():
            part.unlink()

        digest = hashlib.sha256()
        if offset:
            with part.open("rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(block)

        # 0600 from the very first byte: a download is not world-readable for
        # even the instant between creation and a later chmod.
        #
        # O_BINARY matters just as much. Without it Windows opens the descriptor
        # in text mode and turns every 0x0A in the incoming file into 0x0D 0x0A,
        # silently corrupting every download that is not pure text — and the
        # size check would then reject the ones that are. The constant does not
        # exist on POSIX, hence the getattr.
        flags = (os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
                 | (os.O_APPEND if offset else os.O_TRUNC))
        fd = os.open(part, flags, 0o600)
        try:
            with os.fdopen(fd, "ab" if offset else "wb", closefd=True) as sink:
                written = _HashingSink(sink, digest)
                job.transferred = transport.download(
                    job.remote_path, written,
                    offset=offset, size=job.size,
                    progress=lambda done, total: self._progress(job, done, total),
                    cancel=self._cancel_current,
                )
        except BaseException:
            # Leave the .part behind on failure so a resume is possible; it is
            # visibly incomplete, which is the whole point.
            raise

        self._verify_download(transport, job, part, digest)

        if dest.exists() and job.conflict is Conflict.OVERWRITE:
            dest.unlink()
        os.replace(part, dest)
        if not self.private_downloads:
            os.chmod(dest, 0o666 & ~_umask())
        job.local_path = dest

    def _verify_download(self, transport: Transport, job: TransferJob,
                         part: Path, digest) -> None:
        actual_size = part.stat().st_size
        if job.size and actual_size != job.size:
            part.unlink(missing_ok=True)
            raise TransportError(
                f"Size mismatch: expected {job.size} bytes, received {actual_size}. "
                f"The transfer was truncated and has been discarded."
            )
        if not self.verify:
            job.integrity = "not checked"
            return

        local_hash = digest.hexdigest()
        remote_hash = transport.remote_sha256(job.remote_path)
        if remote_hash:
            if remote_hash.lower() != local_hash:
                part.unlink(missing_ok=True)
                raise TransportError(
                    "SHA-256 mismatch: the bytes that arrived are not the bytes the "
                    "server has. The file has been discarded."
                )
            job.integrity = f"SHA-256 verified ({local_hash[:16]}…)"
        else:
            # Be honest: most servers (OpenSSH included) cannot hash remotely.
            job.integrity = f"size verified; SHA-256 {local_hash[:16]}… (server offers no hash)"

    # -------------------------------------------------------------- upload

    def _upload(self, transport: Transport, job: TransferJob) -> None:
        if job.size == -1:  # directory marker
            try:
                transport.mkdir(job.remote_path)
            except TransportError:
                pass  # already there is fine
            job.integrity = "folder created"
            return

        source_path = job.local_path
        if not source_path.is_file():
            raise TransportError(f"{source_path} is not a file")

        remote = job.remote_path
        if job.conflict is not Conflict.OVERWRITE:
            try:
                existing = transport.stat(remote)
            except TransportError:
                existing = None
            if existing is not None:
                if job.conflict is Conflict.SKIP:
                    job.state = JobState.SKIPPED
                    return
                # RESUME is treated as RENAME here: an upload cannot be
                # continued reliably (the server's partial length is not proof
                # of what it holds), so the safe reading of "resume" is the one
                # that does not clobber the file already on the server.
                if job.conflict in (Conflict.RENAME, Conflict.RESUME):
                    remote = _unique_remote(transport, remote)
                    job.remote_path = remote

        job.size = source_path.stat().st_size
        digest = hashlib.sha256()

        # Upload to a sidecar name and rename into place, mirroring what
        # downloads do. Without this, pulling the plug mid-upload leaves a
        # truncated file sitting at the real filename on the server, looking
        # for all the world like a complete one.
        staging = remote + PART_SUFFIX
        try:
            with source_path.open("rb") as raw:
                source = _HashingSource(raw, digest)
                job.transferred = transport.upload(
                    source, staging, size=job.size,
                    progress=lambda done, total: self._progress(job, done, total),
                    cancel=self._cancel_current,
                )
            self._promote_upload(transport, job, staging, remote)
        except BaseException:
            # Never leave a stray .charon-part behind on the server.
            try:
                transport.remove(staging)
            except Exception:
                pass
            raise

        remote_hash = transport.remote_sha256(remote) if self.verify else None
        local_hash = digest.hexdigest()
        if remote_hash and remote_hash.lower() != local_hash:
            raise TransportError(
                "SHA-256 mismatch after upload: the server's copy differs from the "
                "file on disk."
            )
        job.integrity = (f"SHA-256 verified ({local_hash[:16]}…)" if remote_hash
                         else f"sent {job.transferred} bytes; SHA-256 {local_hash[:16]}…")

    def _promote_upload(self, transport: Transport, job: TransferJob,
                        staging: str, remote: str) -> None:
        """Check the staged upload, then move it onto the real name."""
        try:
            staged = transport.stat(staging)
        except TransportError:
            staged = None
        if staged is not None and job.size and staged.size != job.size:
            raise TransportError(
                f"Size mismatch after upload: sent {job.size} bytes, the server "
                f"stored {staged.size}. The partial file has been removed."
            )

        # Most servers refuse to rename onto an existing name, so clear the way
        # first. This is the one moment the destination is briefly absent, and
        # it only happens once the new copy is already on the server intact.
        try:
            if transport.stat(remote) is not None:
                transport.remove(remote)
        except TransportError:
            pass
        transport.rename(staging, remote)

    # --------------------------------------------------------------- inner

    def _progress(self, job: TransferJob, done: int, total: int) -> None:
        job.transferred = done
        if total and not job.size:
            job.size = total
        self._on_change(job)


class _HashingSink:
    """File-like wrapper that digests everything written through it, so the
    integrity check costs one pass over the data instead of two."""

    __slots__ = ("_fh", "_digest")

    def __init__(self, fh, digest) -> None:
        self._fh, self._digest = fh, digest

    def write(self, data: bytes) -> int:
        self._digest.update(data)
        return self._fh.write(data)

    def flush(self) -> None:
        self._fh.flush()


class _HashingSource:
    __slots__ = ("_fh", "_digest")

    def __init__(self, fh, digest) -> None:
        self._fh, self._digest = fh, digest

    def read(self, size: int = -1) -> bytes:
        data = self._fh.read(size)
        self._digest.update(data)
        return data


def _unique_remote(transport: Transport, remote: str) -> str:
    base, _, name = remote.rpartition("/")
    stem, dot, ext = name.rpartition(".")
    for n in range(2, 1000):
        candidate = f"{base}/{stem} ({n}).{ext}" if dot else f"{base}/{name} ({n})"
        try:
            transport.stat(candidate)
        except TransportError:
            return candidate
    raise TransportError(f"cannot find a free name next to {remote}")


def _umask() -> int:
    """Read the process umask without permanently changing it."""
    current = os.umask(0o022)
    os.umask(current)
    return current
