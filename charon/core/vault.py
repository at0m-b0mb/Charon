"""An encrypted-at-rest secret vault: AES-256-GCM with an scrypt-derived key.

Format of ``vault.charon`` (all big-endian, no padding):

    offset  size  field
    0       8     magic  b"CHARON\\x01\\x00"
    8       1     kdf id (1 = scrypt)
    9       4     scrypt log2(N)  r  p  reserved   (one byte each)
    13      16    salt
    29      12    nonce
    41      ..    AES-256-GCM ciphertext || 16-byte tag

The 13-byte header is passed to GCM as additional authenticated data, so an
attacker cannot weaken the KDF parameters of a stolen vault and have the client
accept it — tampering with the cost factor invalidates the tag.

The plaintext is a JSON object mapping an opaque secret id to a string.  It is
only ever held decrypted while the vault is unlocked, and :meth:`Vault.lock`
overwrites the derived key and the cached values in place before dropping them.
"""

from __future__ import annotations

import json
import os
import secrets
import struct
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..paths import harden

__all__ = ["Vault", "VaultError", "VaultLocked", "WrongPassword", "KDF_PARAMS"]

MAGIC = b"CHARON\x01\x00"
KDF_SCRYPT = 1
HEADER_LEN = 13
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# log2(N)=16 → N=65536, r=8, p=1 → ~64 MiB and ~0.1 s per guess.  That is the
# whole point: it makes an offline dictionary attack against a stolen vault
# file cost real memory bandwidth, not just CPU.
KDF_PARAMS = (16, 8, 1)


class VaultError(Exception):
    """Base class for vault failures."""


class VaultLocked(VaultError):
    """An operation needed the vault to be unlocked, and it was not."""


class WrongPassword(VaultError):
    """The master password did not decrypt the vault."""


def _zero(buf: bytearray | None) -> None:
    """Best-effort wipe.  CPython gives no guarantee that no copy was made, but
    overwriting the buffer we control is strictly better than not doing so."""
    if buf:
        for i in range(len(buf)):
            buf[i] = 0


def _derive(password: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=1 << log_n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _header(log_n: int, r: int, p: int) -> bytes:
    return MAGIC + bytes((KDF_SCRYPT, log_n, r, p, 0))


@dataclass
class Vault:
    """A password-protected store for site passwords and key passphrases."""

    path: Path
    _key: bytearray | None = field(default=None, repr=False, compare=False)
    _data: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    _params: tuple[int, int, int] = field(default=KDF_PARAMS, repr=False)
    _salt: bytes = field(default=b"", repr=False, compare=False)

    # ---------------------------------------------------------------- state

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    # ------------------------------------------------------------ lifecycle

    def create(self, password: str) -> None:
        """Initialise a brand-new vault.  Refuses to clobber an existing one."""
        if self.exists:
            raise VaultError("a vault already exists at this location")
        if len(password) < 8:
            raise VaultError("master password must be at least 8 characters")
        log_n, r, p = KDF_PARAMS
        self._params = (log_n, r, p)
        self._salt = secrets.token_bytes(SALT_LEN)
        self._key = bytearray(_derive(password, self._salt, log_n, r, p))
        self._data = {}
        self._write()

    def unlock(self, password: str) -> None:
        """Decrypt the vault with *password*.

        Raises :class:`WrongPassword` on a bad password **and** on a tampered
        file — GCM cannot tell the two apart, and neither should the caller.
        """
        raw = self.path.read_bytes()
        if len(raw) < HEADER_LEN + SALT_LEN + NONCE_LEN + 16:
            raise VaultError("vault file is truncated or corrupt")
        if raw[:8] != MAGIC:
            raise VaultError("not a Charon vault file")

        kdf_id, log_n, r, p, _ = struct.unpack("BBBBB", raw[8:HEADER_LEN])
        if kdf_id != KDF_SCRYPT:
            raise VaultError(f"unsupported key-derivation id {kdf_id}")
        if not (10 <= log_n <= 22) or not (1 <= r <= 32) or not (1 <= p <= 16):
            # Reject absurd parameters before spending 30 GiB deriving a key
            # from a file someone dropped in the config directory.
            raise VaultError("vault declares out-of-range KDF parameters")

        header = raw[:HEADER_LEN]
        salt = raw[HEADER_LEN:HEADER_LEN + SALT_LEN]
        nonce = raw[HEADER_LEN + SALT_LEN:HEADER_LEN + SALT_LEN + NONCE_LEN]
        blob = raw[HEADER_LEN + SALT_LEN + NONCE_LEN:]

        key = bytearray(_derive(password, salt, log_n, r, p))
        try:
            plaintext = AESGCM(bytes(key)).decrypt(nonce, blob, header)
        except InvalidTag:
            _zero(key)
            raise WrongPassword("wrong master password, or the vault was modified")

        try:
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            _zero(key)
            raise VaultError("vault contents are not valid Charon data")

        self._params = (log_n, r, p)
        self._salt = salt
        self._key = key
        self._data = {str(k): str(v) for k, v in data.items()}

    def lock(self) -> None:
        """Forget the derived key and every decrypted secret."""
        _zero(self._key)
        for k in list(self._data):
            self._data[k] = "\x00" * len(self._data[k])
        self._data.clear()
        self._key = None

    def change_password(self, old: str, new: str) -> None:
        self.unlock(old)
        if len(new) < 8:
            raise VaultError("master password must be at least 8 characters")
        data = dict(self._data)
        log_n, r, p = KDF_PARAMS
        self._params = (log_n, r, p)
        # A new password gets a new salt, so two vaults that happen to share a
        # password never share a derived key.
        self._salt = secrets.token_bytes(SALT_LEN)
        _zero(self._key)
        self._key = bytearray(_derive(new, self._salt, log_n, r, p))
        self._data = data
        self._write()

    # --------------------------------------------------------------- access

    def get(self, key: str) -> str | None:
        self._require_unlocked()
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._require_unlocked()
        self._data[key] = value
        self._rewrite()

    def delete(self, key: str) -> None:
        self._require_unlocked()
        if self._data.pop(key, None) is not None:
            self._rewrite()

    def keys(self) -> list[str]:
        self._require_unlocked()
        return sorted(self._data)

    # ---------------------------------------------------------------- inner

    def _require_unlocked(self) -> None:
        if self._key is None:
            raise VaultLocked("the vault is locked")

    def _rewrite(self) -> None:
        self._write()

    def _write(self) -> None:
        """Encrypt the current contents and replace the vault file atomically.

        The salt stays fixed for the life of the key (it is what the key was
        derived from), but a **fresh nonce is drawn on every single write**.
        Reusing a nonce under one AES-GCM key is the one mistake that breaks
        the cipher outright, so it is drawn here and nowhere else.
        """
        assert self._key is not None
        log_n, r, p = self._params
        header = _header(log_n, r, p)
        salt = self._salt
        nonce = secrets.token_bytes(NONCE_LEN)
        plaintext = json.dumps(self._data, separators=(",", ":")).encode("utf-8")
        blob = AESGCM(bytes(self._key)).encrypt(nonce, plaintext, header)

        # Write to a sibling temp file with 0600 already applied, then rename:
        # a crash mid-write must never leave a half-vault where the real one was.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, header + salt + nonce + blob)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        harden(self.path)
