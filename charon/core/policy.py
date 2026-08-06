"""The security policy — the one place that says *no*.

Charon's rule is that a refusal must be a single, testable function, not a
condition scattered across dialog code where a future edit can quietly drop it.
Everything that could downgrade the user's security goes through
:func:`check_connection` before a socket is opened, and the GUI renders whatever
comes back rather than making its own judgement.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from enum import Enum

from .model import Protocol, Site

__all__ = ["Verdict", "PolicyResult", "Policy", "check_connection", "build_tls_context"]


class Verdict(str, Enum):
    ALLOW = "allow"        # proceed
    CONFIRM = "confirm"    # proceed only after an explicit, informed click
    BLOCK = "block"        # do not connect


@dataclass(frozen=True)
class PolicyResult:
    verdict: Verdict
    reason: str = ""
    detail: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict is not Verdict.BLOCK


@dataclass
class Policy:
    """User-adjustable security settings.  Defaults are the strict ones."""

    allow_plaintext_ftp: bool = False   # the global unlock for plain FTP
    require_tls_1_2: bool = True
    allow_tofu: bool = True             # trust-on-first-use with a prompt
    lock_after_minutes: int = 15        # idle auto-disconnect + vault re-lock
    verify_downloads: bool = True       # SHA-256 the bytes we wrote

    def to_json(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_json(cls, data: dict) -> "Policy":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def check_connection(site: Site, policy: Policy) -> PolicyResult:
    """Decide whether *site* may be connected to under *policy*."""
    if site.protocol is Protocol.FTP:
        if not policy.allow_plaintext_ftp:
            return PolicyResult(
                Verdict.BLOCK,
                "Plain FTP is disabled",
                "FTP sends your username, your password and every byte of every file "
                "across the network in the clear — anyone on the same Wi-Fi, VPN or "
                "ISP path can read them and log in as you afterwards.\n\n"
                "Use SFTP (port 22) or FTPS instead. If this server genuinely speaks "
                "nothing else, turn on “Allow plaintext FTP” in Settings → Security "
                "and accept that risk deliberately.",
            )
        if not site.accept_insecure_ftp:
            return PolicyResult(
                Verdict.CONFIRM,
                "This connection is not encrypted",
                "Your password and files will cross the network in readable form.",
            )
        return PolicyResult(
            Verdict.CONFIRM,
            "This connection is not encrypted",
            "Plaintext FTP was explicitly enabled for this site.",
        )

    if site.protocol is Protocol.FTPS and not site.verify_tls:
        return PolicyResult(
            Verdict.CONFIRM,
            "Certificate verification is off for this site",
            "Charon will encrypt the connection but cannot prove the server is the "
            "one you meant — an attacker in the middle would be invisible. Prefer "
            "leaving verification on and pinning the certificate on first connect.",
        )

    return PolicyResult(Verdict.ALLOW)


def build_tls_context(policy: Policy, verify: bool) -> ssl.SSLContext:
    """A hardened TLS context for FTPS.

    ``create_default_context`` already gives certificate + hostname checking and
    a sane cipher list; the additions here are the floor on protocol version and
    the refusal to renegotiate down to TLS 1.0/1.1, which several elderly FTP
    servers will still happily offer.
    """
    ctx = ssl.create_default_context()
    ctx.minimum_version = (
        ssl.TLSVersion.TLSv1_2 if policy.require_tls_1_2 else ssl.TLSVersion.TLSv1
    )
    ctx.options |= ssl.OP_NO_COMPRESSION      # sidestep CRIME-style compression oracles
    ctx.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

    if not verify:
        # Only reachable when the user turned verification off for one site and
        # confirmed the CONFIRM verdict above.  The connection is still
        # encrypted; it is the identity check that is gone.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx
