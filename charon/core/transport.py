"""The transport interface every protocol backend implements.

Trust decisions are *raised, not prompted*.  A backend that meets an unknown
host key stops and raises :class:`HostKeyUnknown`; it never asks a question
itself.  That keeps every blocking dialog on the GUI thread, and — more
importantly — it means a backend physically cannot be written to auto-accept:
there is no "accept" path inside it at all.  The caller pins the key and retries.
"""

from __future__ import annotations

import abc
import threading
from typing import Callable, Iterable, Optional

from .model import Credentials, RemoteEntry, SecurityState, Site
from .policy import Policy
from .trust import HostIdentity

__all__ = [
    "Transport",
    "TransportError",
    "TransferCancelled",
    "AuthFailed",
    "TrustRequired",
    "HostKeyUnknown",
    "HostKeyChanged",
    "CertUnknown",
    "CertChanged",
    "ProgressFn",
]

# (bytes_done, bytes_total) — total is 0 when the size is unknown.
ProgressFn = Callable[[int, int], None]


class TransportError(Exception):
    """Any transport-level failure that is safe to show to the user."""


class TransferCancelled(Exception):
    """Raised out of a transfer loop when the user cancels.

    Not a subclass of :class:`TransportError`: a cancellation is a normal
    outcome, and must never be reported to the user as a failure.
    """


class AuthFailed(TransportError):
    """Server rejected the credentials."""


class TrustRequired(TransportError):
    """The caller must make a trust decision before this connection can proceed."""

    def __init__(self, identity: HostIdentity, message: str) -> None:
        super().__init__(message)
        self.identity = identity


class HostKeyUnknown(TrustRequired):
    """First contact with this SSH host — show the fingerprint and ask."""


class HostKeyChanged(TrustRequired):
    """The SSH host key does not match the pinned one.  Refuse by default."""


class CertUnknown(TrustRequired):
    """FTPS certificate is not CA-valid and not pinned."""


class CertChanged(TrustRequired):
    """FTPS certificate does not match the pinned fingerprint."""


class Transport(abc.ABC):
    """One live connection to one server.

    Instances are **not** thread-safe; each owns a socket and a protocol state
    machine.  Charon gives the browser and the transfer engine one transport
    each so a long upload never freezes directory navigation.
    """

    def __init__(self, site: Site, policy: Policy) -> None:
        self.site = site
        self.policy = policy
        self.security = SecurityState(protocol=site.protocol)
        self._cwd = "/"

    # ---------------------------------------------------------- lifecycle

    @abc.abstractmethod
    def connect(self, creds: Credentials) -> None:
        """Open the connection and authenticate, or raise."""

    @abc.abstractmethod
    def close(self) -> None:
        """Tear the connection down.  Must be safe to call twice."""

    @property
    @abc.abstractmethod
    def is_connected(self) -> bool: ...

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ browsing

    @property
    def cwd(self) -> str:
        return self._cwd

    def set_cwd(self, path: str) -> None:
        """Record where the user has navigated to, after a successful listing."""
        self._cwd = path

    @abc.abstractmethod
    def listdir(self, path: str) -> list[RemoteEntry]: ...

    @abc.abstractmethod
    def home(self) -> str:
        """The directory to open on connect."""

    @abc.abstractmethod
    def stat(self, path: str) -> RemoteEntry: ...

    # ------------------------------------------------------------ mutation

    @abc.abstractmethod
    def mkdir(self, path: str) -> None: ...

    @abc.abstractmethod
    def remove(self, path: str) -> None: ...

    @abc.abstractmethod
    def rmdir(self, path: str) -> None: ...

    @abc.abstractmethod
    def rename(self, old: str, new: str) -> None: ...

    # ------------------------------------------------------------ transfer

    @abc.abstractmethod
    def download(
        self,
        remote: str,
        sink,
        *,
        offset: int = 0,
        size: int = 0,
        progress: Optional[ProgressFn] = None,
        cancel: Optional[threading.Event] = None,
    ) -> int:
        """Stream *remote* into the binary file object *sink*.  Returns bytes written."""

    @abc.abstractmethod
    def upload(
        self,
        source,
        remote: str,
        *,
        offset: int = 0,
        size: int = 0,
        progress: Optional[ProgressFn] = None,
        cancel: Optional[threading.Event] = None,
    ) -> int:
        """Stream the binary file object *source* to *remote*.  Returns bytes sent."""

    # -------------------------------------------------------------- extras

    def remote_sha256(self, path: str) -> Optional[str]:
        """Ask the server for a SHA-256 of *path*, if it can produce one.

        Returns ``None`` when the server has no such extension — Charon then
        says "size verified" rather than pretending the content was checked.
        """
        return None

    def supports_resume(self) -> bool:
        return True

    def keepalive(self) -> None:
        """Cheap no-op request to keep an idle control channel from timing out."""


def chunked(source, size: int = 262_144) -> Iterable[bytes]:
    while True:
        block = source.read(size)
        if not block:
            return
        yield block
