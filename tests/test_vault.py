"""Vault tests: round-trip, wrong password, tampering, and file permissions."""

from __future__ import annotations

import os
import stat
import sys

import pytest

from charon.core.vault import (
    HEADER_LEN,
    MAGIC,
    NONCE_LEN,
    SALT_LEN,
    Vault,
    VaultError,
    VaultLocked,
    WrongPassword,
)

PASSWORD = "correct horse battery staple"


@pytest.fixture
def vault(tmp_path):
    return Vault(path=tmp_path / "vault.charon")


def test_create_store_lock_and_reopen(vault):
    vault.create(PASSWORD)
    vault.set("sftp://kai@example.com:22#password", "hunter2")
    vault.lock()

    assert not vault.is_unlocked
    reopened = Vault(path=vault.path)
    reopened.unlock(PASSWORD)
    assert reopened.get("sftp://kai@example.com:22#password") == "hunter2"


def test_wrong_password_is_rejected(vault):
    vault.create(PASSWORD)
    vault.lock()
    with pytest.raises(WrongPassword):
        Vault(path=vault.path).unlock("not the password")


def test_locked_vault_refuses_reads(vault):
    vault.create(PASSWORD)
    vault.set("k", "v")
    vault.lock()
    with pytest.raises(VaultLocked):
        vault.get("k")


def test_the_file_never_contains_the_plaintext(vault):
    vault.create(PASSWORD)
    vault.set("site", "a-very-distinctive-secret")
    raw = vault.path.read_bytes()
    assert b"a-very-distinctive-secret" not in raw
    assert b"site" not in raw
    assert raw.startswith(MAGIC)


def test_flipping_one_ciphertext_bit_is_detected(vault):
    vault.create(PASSWORD)
    vault.set("site", "secret")
    raw = bytearray(vault.path.read_bytes())
    raw[-1] ^= 0x01  # inside the GCM tag
    vault.path.write_bytes(bytes(raw))
    with pytest.raises(WrongPassword):
        Vault(path=vault.path).unlock(PASSWORD)


def test_downgrading_the_kdf_cost_is_detected(vault):
    """The header is authenticated, so an attacker cannot weaken the KDF of a
    stolen vault and have the client accept the file."""
    vault.create(PASSWORD)
    vault.set("site", "secret")
    raw = bytearray(vault.path.read_bytes())
    raw[9] = 12  # log2(N): 16 → 12, a 16x cheaper brute force
    vault.path.write_bytes(bytes(raw))
    with pytest.raises(WrongPassword):
        Vault(path=vault.path).unlock(PASSWORD)


def test_absurd_kdf_parameters_are_refused_before_deriving(vault):
    vault.create(PASSWORD)
    raw = bytearray(vault.path.read_bytes())
    raw[9] = 40  # 2**40 blocks would ask for terabytes of memory
    vault.path.write_bytes(bytes(raw))
    with pytest.raises(VaultError, match="out-of-range"):
        Vault(path=vault.path).unlock(PASSWORD)


def test_a_foreign_file_is_not_mistaken_for_a_vault(tmp_path):
    path = tmp_path / "vault.charon"
    path.write_bytes(b"this is not a vault" * 10)
    with pytest.raises(VaultError):
        Vault(path=path).unlock(PASSWORD)


def test_truncated_file_is_rejected(tmp_path):
    path = tmp_path / "vault.charon"
    path.write_bytes(MAGIC + b"\x01" * 4)
    with pytest.raises(VaultError, match="truncated"):
        Vault(path=path).unlock(PASSWORD)


def test_create_refuses_to_clobber_an_existing_vault(vault):
    vault.create(PASSWORD)
    with pytest.raises(VaultError, match="already exists"):
        Vault(path=vault.path).create("another password")


def test_short_master_passwords_are_refused(vault):
    with pytest.raises(VaultError, match="at least 8"):
        vault.create("short")


def test_every_write_uses_a_fresh_nonce(vault):
    """Reusing a nonce under one AES-GCM key breaks the cipher outright."""
    vault.create(PASSWORD)
    nonces = set()
    for i in range(12):
        vault.set(f"key{i}", "value")
        raw = vault.path.read_bytes()
        nonces.add(raw[HEADER_LEN + SALT_LEN:HEADER_LEN + SALT_LEN + NONCE_LEN])
    assert len(nonces) == 12


def test_changing_the_password_keeps_the_contents(vault):
    vault.create(PASSWORD)
    vault.set("site", "secret")
    vault.change_password(PASSWORD, "a brand new passphrase")
    vault.lock()

    reopened = Vault(path=vault.path)
    with pytest.raises(WrongPassword):
        reopened.unlock(PASSWORD)
    reopened.unlock("a brand new passphrase")
    assert reopened.get("site") == "secret"


def test_delete_removes_a_secret(vault):
    vault.create(PASSWORD)
    vault.set("a", "1")
    vault.set("b", "2")
    vault.delete("a")
    assert vault.keys() == ["b"]


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permissions")
def test_vault_file_is_owner_only(vault):
    vault.create(PASSWORD)
    mode = stat.S_IMODE(os.stat(vault.path).st_mode)
    assert mode == 0o600, f"vault is {oct(mode)}, expected 0600"
