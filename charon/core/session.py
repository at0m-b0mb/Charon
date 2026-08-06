"""Assembling a connection: pick a backend, apply the policy, keep the identity.

Nothing here talks to the GUI.  A caller connects, and either gets a live
:class:`~charon.core.transport.Transport` back or an exception describing
exactly what needs a human decision.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .ftp import FTPTransport
from .model import Credentials, Protocol, Site
from .policy import Policy, Verdict, check_connection
from .transport import Transport, TransportError
from .trust import CertPinStore, HostKeyStore

log = logging.getLogger(__name__)

__all__ = ["Session", "make_transport", "PolicyBlocked"]


class PolicyBlocked(TransportError):
    """The security policy refused this connection outright."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def make_transport(
    site: Site,
    policy: Policy,
    hostkeys: Optional[HostKeyStore] = None,
    pins: Optional[CertPinStore] = None,
) -> Transport:
    """Build (but do not connect) the right backend for *site*."""
    if site.protocol is Protocol.SFTP:
        from .sftp import SFTPTransport

        return SFTPTransport(site, policy, hostkeys=hostkeys)
    return FTPTransport(site, policy, pins=pins)


@dataclass
class Session:
    """One logical connection to one server, shared by the browser and the
    transfer engine (which each hold their own socket to it)."""

    site: Site
    policy: Policy
    credentials: Credentials = field(default_factory=Credentials)
    hostkeys: HostKeyStore = field(default_factory=HostKeyStore)
    pins: CertPinStore = field(default_factory=CertPinStore)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def preflight(self) -> None:
        """Run the policy check.  Raises :class:`PolicyBlocked` on a refusal.

        ``CONFIRM`` verdicts are *not* raised here — the caller is expected to
        have already shown the warning and got a click, and calling this a
        second time must not re-prompt.
        """
        result = check_connection(self.site, self.policy)
        if result.verdict is Verdict.BLOCK:
            raise PolicyBlocked(result.reason, result.detail)

    def open(self) -> Transport:
        """Open one connected transport.  Called once for browsing and once for
        the transfer engine, so a big upload never blocks navigation."""
        self.preflight()
        transport = make_transport(self.site, self.policy, self.hostkeys, self.pins)
        transport.connect(self.credentials)
        return transport

    @property
    def label(self) -> str:
        return self.site.label

    def burn(self) -> None:
        self.credentials.burn()
