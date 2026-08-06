"""Where a saved password actually goes.

Three storage modes, chosen per install and switchable in Settings:

``keychain``   the OS credential store — macOS Keychain, Windows Credential
               Manager, or the Secret Service / KWallet on Linux.  The OS owns
               the encryption key and gates access on the user's login session.
``vault``      Charon's own AES-256-GCM file, unlocked by a master password.
               Portable, and the only option on a headless Linux box with no
               Secret Service running.
``never``      nothing is written to disk at all; every connection prompts.

The keychain backend is *probed*, not assumed: ``keyring`` happily imports on a
machine with no working backend and then fails at first use, so
:func:`keychain_available` performs a real round-trip before Charon offers it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..paths import vault_file
from .vault import Vault, VaultError, VaultLocked

log = logging.getLogger(__name__)

SERVICE = "Charon Secure Transfer"


class StorageMode(str, Enum):
    KEYCHAIN = "keychain"
    VAULT = "vault"
    NEVER = "never"


def secret_id(protocol: str, host: str, port: int, username: str, kind: str = "password") -> str:
    """A stable, non-secret identifier for one stored credential."""
    return f"{protocol}://{username}@{host}:{port}#{kind}"


def keychain_available() -> bool:
    """True only if a real keyring backend answers a set/get/delete cycle."""
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except Exception:  # pragma: no cover - keyring missing entirely
        return False
    try:
        backend = keyring.get_keyring()
        if isinstance(backend, FailKeyring):
            return False
        probe = "charon-self-test"
        keyring.set_password(SERVICE, probe, "ok")
        ok = keyring.get_password(SERVICE, probe) == "ok"
        keyring.delete_password(SERVICE, probe)
        return ok
    except Exception as exc:
        log.debug("keychain probe failed: %s", exc)
        return False


@dataclass
class SecretStore:
    """Facade over the selected backend.  Never logs a secret value."""

    mode: StorageMode = StorageMode.KEYCHAIN
    vault: Optional[Vault] = None

    def __post_init__(self) -> None:
        if self.vault is None:
            self.vault = Vault(path=vault_file())

    # ------------------------------------------------------------- queries

    @property
    def needs_unlock(self) -> bool:
        """True when the user must supply the master password before saved
        credentials can be read."""
        return (
            self.mode is StorageMode.VAULT
            and self.vault is not None
            and self.vault.exists
            and not self.vault.is_unlocked
        )

    @property
    def can_store(self) -> bool:
        return self.mode is not StorageMode.NEVER

    # -------------------------------------------------------------- access

    def get(self, key: str) -> str | None:
        if self.mode is StorageMode.NEVER:
            return None
        if self.mode is StorageMode.KEYCHAIN:
            try:
                import keyring

                return keyring.get_password(SERVICE, key)
            except Exception as exc:
                log.warning("keychain read failed for %s: %s", key, exc)
                return None
        assert self.vault is not None
        try:
            return self.vault.get(key)
        except VaultLocked:
            return None

    def set(self, key: str, value: str) -> None:
        if self.mode is StorageMode.NEVER:
            return
        if self.mode is StorageMode.KEYCHAIN:
            import keyring

            keyring.set_password(SERVICE, key, value)
            return
        assert self.vault is not None
        self.vault.set(key, value)

    def delete(self, key: str) -> None:
        if self.mode is StorageMode.NEVER:
            return
        if self.mode is StorageMode.KEYCHAIN:
            try:
                import keyring

                keyring.delete_password(SERVICE, key)
            except Exception:
                pass
            return
        assert self.vault is not None
        try:
            self.vault.delete(key)
        except (VaultLocked, VaultError):
            pass

    def lock(self) -> None:
        if self.vault is not None and self.vault.is_unlocked:
            self.vault.lock()

    def describe(self) -> str:
        if self.mode is StorageMode.KEYCHAIN:
            return "OS keychain"
        if self.mode is StorageMode.VAULT:
            state = "unlocked" if self.vault and self.vault.is_unlocked else "locked"
            return f"encrypted vault ({state})"
        return "not stored"
