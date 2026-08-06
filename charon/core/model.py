"""The data Charon passes around: sites, credentials, listings, security state."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional

__all__ = [
    "Protocol",
    "AuthMethod",
    "Site",
    "Credentials",
    "RemoteEntry",
    "SecurityState",
    "Grade",
]


class Protocol(str, Enum):
    SFTP = "sftp"      # SSH File Transfer Protocol — encrypted by construction
    FTPS = "ftps"      # FTP over explicit TLS (AUTH TLS, RFC 4217)
    FTP = "ftp"        # plain FTP — cleartext, disabled unless explicitly unlocked

    @property
    def default_port(self) -> int:
        return {Protocol.SFTP: 22, Protocol.FTPS: 21, Protocol.FTP: 21}[self]

    @property
    def is_encrypted(self) -> bool:
        return self is not Protocol.FTP

    @property
    def display(self) -> str:
        return {
            Protocol.SFTP: "SFTP (SSH)",
            Protocol.FTPS: "FTPS (FTP over TLS)",
            Protocol.FTP: "FTP (plaintext)",
        }[self]


class AuthMethod(str, Enum):
    PASSWORD = "password"
    KEY = "key"          # private key file, optionally passphrase-protected
    AGENT = "agent"      # ssh-agent / Pageant — the key never enters Charon


class Grade(str, Enum):
    """How safe the *live* connection actually is, not how it was configured."""

    STRONG = "strong"    # encrypted, server identity pinned or CA-verified
    OK = "ok"            # encrypted and verified, but something is dated
    WEAK = "weak"        # encrypted, identity only trusted on first use this session
    UNSAFE = "unsafe"    # credentials or data in the clear


@dataclass
class Site:
    """A saved connection.  Contains no secret material — only where the secret
    lives.  This file is written as plain JSON, so nothing sensitive may enter."""

    name: str
    host: str
    protocol: Protocol = Protocol.SFTP
    port: int = 0
    username: str = ""
    auth: AuthMethod = AuthMethod.PASSWORD
    key_path: str = ""
    remote_dir: str = ""
    local_dir: str = ""
    save_password: bool = True
    verify_tls: bool = True          # FTPS: require a CA-valid chain or a pin
    passive: bool = True             # FTPS/FTP: PASV rather than PORT
    accept_insecure_ftp: bool = False  # per-site override, requires global unlock
    last_used: float = 0.0

    def __post_init__(self) -> None:
        if isinstance(self.protocol, str):
            self.protocol = Protocol(self.protocol)
        if isinstance(self.auth, str):
            self.auth = AuthMethod(self.auth)
        if not self.port:
            self.port = self.protocol.default_port

    @property
    def label(self) -> str:
        user = f"{self.username}@" if self.username else ""
        return f"{self.protocol.value}://{user}{self.host}:{self.port}"

    def touched(self) -> "Site":
        return replace(self, last_used=time.time())

    def to_json(self) -> dict:
        data = self.__dict__.copy()
        data["protocol"] = self.protocol.value
        data["auth"] = self.auth.value
        return data

    @classmethod
    def from_json(cls, data: dict) -> "Site":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Credentials:
    """Live secret material for one connection attempt.

    Held only for as long as a session needs it.  :meth:`burn` overwrites the
    strings' backing buffers where CPython lets us, and drops the references
    either way, so a heap dump taken later is less likely to yield a password.
    """

    password: Optional[str] = None
    passphrase: Optional[str] = None
    remember: bool = False

    def burn(self) -> None:
        self.password = None
        self.passphrase = None


@dataclass(frozen=True)
class RemoteEntry:
    """One line of a remote directory listing."""

    name: str
    size: int = 0
    mtime: float = 0.0
    is_dir: bool = False
    is_symlink: bool = False
    mode: str = ""
    owner: str = ""

    @property
    def kind(self) -> str:
        if self.is_symlink:
            return "link"
        return "folder" if self.is_dir else "file"


@dataclass
class SecurityState:
    """A plain-language summary of the live channel, shown in the status bar.

    Populated by each transport from what actually got negotiated — never from
    what was requested.
    """

    protocol: Protocol = Protocol.SFTP
    encrypted: bool = False
    cipher: str = ""
    kex: str = ""
    mac: str = ""
    host_key_type: str = ""
    fingerprint: str = ""
    identity_verified: bool = False
    verified_how: str = ""
    data_channel_encrypted: bool = True
    tls_version: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def grade(self) -> Grade:
        if not self.encrypted or not self.data_channel_encrypted:
            return Grade.UNSAFE
        if not self.identity_verified:
            return Grade.WEAK
        return Grade.OK if self.warnings else Grade.STRONG

    @property
    def headline(self) -> str:
        return {
            Grade.STRONG: "Secure",
            Grade.OK: "Secure, with notes",
            Grade.WEAK: "Encrypted, identity unconfirmed",
            Grade.UNSAFE: "NOT SECURE",
        }[self.grade]

    def detail_lines(self) -> list[str]:
        lines = [f"Protocol: {self.protocol.display}"]
        if self.tls_version:
            lines.append(f"TLS: {self.tls_version}")
        if self.kex:
            lines.append(f"Key exchange: {self.kex}")
        if self.cipher:
            lines.append(f"Cipher: {self.cipher}")
        if self.mac:
            lines.append(f"MAC: {self.mac}")
        if self.host_key_type:
            lines.append(f"Host key: {self.host_key_type}")
        if self.fingerprint:
            lines.append(f"Fingerprint: {self.fingerprint}")
        lines.append(
            f"Server identity: {self.verified_how}" if self.identity_verified
            else "Server identity: NOT verified"
        )
        if self.protocol is not Protocol.SFTP:
            lines.append(
                "Data channel: encrypted (PROT P)" if self.data_channel_encrypted
                else "Data channel: CLEARTEXT"
            )
        lines.extend(f"! {w}" for w in self.warnings)
        return lines
