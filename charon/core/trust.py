"""Server identity: SSH host keys and TLS certificate pinning.

This is the file that decides whether you are talking to your server or to
somebody sitting between you and it.  Encryption without identity verification
stops passive eavesdropping and nothing else — an active attacker simply
terminates your TLS/SSH session, presents their own key, and relays.

Charon therefore refuses to auto-accept anything:

* **First sight (TOFU)** — the fingerprint is shown to the user and must be
  approved by hand before it is written to the trust store.
* **Known and matching** — connect silently.
* **Known and *changed*** — hard stop.  Not a warning, not a "continue anyway"
  default: the dialog defaults to refusing, because a changed key on a server
  you did not just rebuild is the exact signature of an interception attack.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from ..paths import harden, known_hosts_file, pinned_certs_file

log = logging.getLogger(__name__)

__all__ = [
    "TrustDecision",
    "HostIdentity",
    "HostKeyStore",
    "CertPinStore",
    "sha256_fingerprint",
    "md5_fingerprint",
]


class TrustDecision(str, Enum):
    KNOWN = "known"          # pinned and matching — proceed
    UNKNOWN = "unknown"      # never seen — ask the user (TOFU)
    CHANGED = "changed"      # pinned and DIFFERENT — refuse loudly


def sha256_fingerprint(blob: bytes) -> str:
    """OpenSSH-style ``SHA256:base64`` fingerprint (no padding)."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def md5_fingerprint(blob: bytes) -> str:
    """Legacy colon-hex MD5 form, shown only so users can cross-check against
    old server documentation.  It is never used for a trust decision."""
    digest = hashlib.md5(blob).hexdigest()
    return "MD5:" + ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


@dataclass(frozen=True)
class HostIdentity:
    """What the server presented, rendered for a human to eyeball.

    Carries the raw key/certificate alongside its fingerprint so that approving
    a prompt can pin *exactly the bytes that were shown*.  Re-fetching the key
    after the user clicks would open a window in which a different key could be
    substituted — the user would approve one fingerprint and pin another.
    """

    host: str
    port: int
    key_type: str          # e.g. "ssh-ed25519", or "TLS certificate"
    fingerprint: str       # SHA256:...
    blob: bytes = b""      # the key/certificate the fingerprint was taken over
    legacy_fingerprint: str = ""
    bits: int = 0
    subject: str = ""      # TLS only
    issuer: str = ""       # TLS only
    not_after: str = ""    # TLS only

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


def _hostport(host: str, port: int, default_port: int) -> str:
    """OpenSSH writes a bare hostname for the default port and ``[host]:port``
    otherwise.  Matching that means Charon's known_hosts stays readable with
    ordinary ssh tooling."""
    return host if port == default_port else f"[{host}]:{port}"


class HostKeyStore:
    """A minimal, OpenSSH-compatible ``known_hosts`` reader/writer.

    paramiko ships one of these, but its ``AutoAddPolicy`` is the trap that
    makes most Python SFTP code silently accept any key.  Charon keeps its own
    so that "accept" is always a deliberate call from a user-facing dialog.
    """

    DEFAULT_PORT = 22

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or known_hosts_file()

    # ------------------------------------------------------------------ io

    def _entries(self) -> list[tuple[str, str, str]]:
        """(hostspec, keytype, base64key) triples; comments/blank lines dropped."""
        if not self.path.exists():
            return []
        out: list[tuple[str, str, str]] = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            out.append((parts[0], parts[1], parts[2]))
        return out

    # -------------------------------------------------------------- lookup

    def check(self, host: str, port: int, key_type: str, key_blob: bytes) -> TrustDecision:
        spec = _hostport(host, port, self.DEFAULT_PORT)
        presented = base64.b64encode(key_blob).decode("ascii")
        for hostspec, ktype, b64 in self._entries():
            if hostspec == spec and ktype == key_type:
                # Constant-time compare is not required (both values are
                # public), but exactness is.
                return TrustDecision.KNOWN if b64 == presented else TrustDecision.CHANGED
        # Either the host is new, or it is pinned only under a different key
        # algorithm — which is what happens when a server adds an ed25519 key
        # beside its old RSA one, so that is TOFU, not a key change.
        return TrustDecision.UNKNOWN

    def pinned_for(self, host: str, port: int) -> list[tuple[str, str]]:
        spec = _hostport(host, port, self.DEFAULT_PORT)
        return [(k, b) for h, k, b in self._entries() if h == spec]

    # --------------------------------------------------------------- writes

    def trust(self, host: str, port: int, key_type: str, key_blob: bytes) -> None:
        """Pin a key.  Only ever called after an explicit user approval."""
        spec = _hostport(host, port, self.DEFAULT_PORT)
        b64 = base64.b64encode(key_blob).decode("ascii")
        self.forget(host, port, key_type)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(f"{spec} {key_type} {b64}\n")
        harden(self.path)

    def forget(self, host: str, port: int, key_type: str | None = None) -> int:
        """Drop pinned keys for a host.  Returns how many lines were removed."""
        if not self.path.exists():
            return 0
        spec = _hostport(host, port, self.DEFAULT_PORT)
        kept, removed = [], 0
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == spec and (key_type is None or parts[1] == key_type):
                removed += 1
                continue
            kept.append(line)
        self.path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        harden(self.path)
        return removed

    def identity(self, host: str, port: int, key_type: str, key_blob: bytes, bits: int = 0) -> HostIdentity:
        return HostIdentity(
            host=host,
            port=port,
            key_type=key_type,
            fingerprint=sha256_fingerprint(key_blob),
            blob=key_blob,
            legacy_fingerprint=md5_fingerprint(key_blob),
            bits=bits,
        )


class CertPinStore:
    """TOFU pinning for FTPS server certificates.

    Certificates that already chain to a system-trusted CA do not need a pin —
    the CA has vouched for them and the hostname was checked.  This store is
    what makes self-signed FTPS (overwhelmingly common on NAS boxes and
    internal servers) safe *without* the usual advice of "just turn off
    verification", which throws away identity entirely.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or pinned_certs_file()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (ValueError, OSError):
            log.warning("pinned cert store is unreadable; treating as empty")
            return {}

    def _save(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        harden(self.path)

    def check(self, host: str, port: int, der: bytes) -> TrustDecision:
        pinned = self._load().get(f"{host}:{port}")
        if pinned is None:
            return TrustDecision.UNKNOWN
        return TrustDecision.KNOWN if pinned == sha256_fingerprint(der) else TrustDecision.CHANGED

    def trust(self, host: str, port: int, der: bytes) -> None:
        data = self._load()
        data[f"{host}:{port}"] = sha256_fingerprint(der)
        self._save(data)

    def forget(self, host: str, port: int) -> bool:
        data = self._load()
        if data.pop(f"{host}:{port}", None) is None:
            return False
        self._save(data)
        return True

    @staticmethod
    def identity(host: str, port: int, der: bytes, cert_dict: dict | None = None) -> HostIdentity:
        subject = issuer = not_after = ""
        if cert_dict:
            subject = _rdn(cert_dict.get("subject"))
            issuer = _rdn(cert_dict.get("issuer"))
            not_after = str(cert_dict.get("notAfter", ""))
        return HostIdentity(
            host=host,
            port=port,
            key_type="TLS certificate",
            fingerprint=sha256_fingerprint(der),
            blob=der,
            legacy_fingerprint=binascii.hexlify(hashlib.sha1(der).digest()).decode(),
            subject=subject,
            issuer=issuer,
            not_after=not_after,
        )


def _rdn(seq) -> str:
    """Flatten ssl's nested RDN tuples into a readable one-liner."""
    if not seq:
        return ""
    bits = []
    for rdn in seq:
        for pair in rdn:
            if len(pair) == 2:
                bits.append(f"{pair[0]}={pair[1]}")
    return ", ".join(bits)
