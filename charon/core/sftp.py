"""SFTP transport, built on paramiko's low-level ``Transport``.

Deliberately *not* built on ``SSHClient``.  ``SSHClient`` couples host-key
handling to a policy object, and the policy nearly every tutorial reaches for is
``AutoAddPolicy`` — which accepts whatever key the far end offers and turns SSH
into encryption-without-authentication.  Driving ``Transport`` directly lets
Charon inspect the server's key **after** the handshake and **before** a single
credential byte is sent, and refuse there.
"""

from __future__ import annotations

import logging
import socket
import stat as stat_mod
import threading
from typing import Optional

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    PasswordRequiredException,
    SSHException,
)

from .model import Credentials, Protocol, RemoteEntry, SecurityState, Site
from .policy import Policy
from .safety import normalise_remote
from .transport import (
    AuthFailed,
    HostKeyChanged,
    HostKeyUnknown,
    ProgressFn,
    TransferCancelled,
    Transport,
    TransportError,
)
from .trust import HostKeyStore, TrustDecision

log = logging.getLogger(__name__)

CHUNK = 262_144  # 256 KiB — large enough to keep the pipe full, small enough
                 # that a cancel is felt within a few milliseconds.

# Anything using CBC mode, 3DES, or an MD5/truncated MAC is refused outright.
# These are not theoretical worries: the CBC modes in SSH have a practical
# plaintext-recovery attack, and 3DES is below any current strength floor.
DISABLED_ALGORITHMS = {
    "ciphers": ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc", "blowfish-cbc",
                "arcfour", "arcfour128", "arcfour256", "cast128-cbc"],
    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160"],
    "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1"],
    "keys": ["ssh-dss", "ssh-rsa"],  # SHA-1 host-key signatures
}

PREFERRED_CIPHERS = ("aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
                     "aes256-ctr", "aes192-ctr", "aes128-ctr")
PREFERRED_MACS = ("hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
                  "hmac-sha2-512", "hmac-sha2-256")
PREFERRED_KEX = ("curve25519-sha256@libssh.org", "ecdh-sha2-nistp521",
                 "ecdh-sha2-nistp384", "ecdh-sha2-nistp256",
                 "diffie-hellman-group16-sha512",
                 "diffie-hellman-group-exchange-sha256",
                 "diffie-hellman-group14-sha256")

# Built by lookup rather than hard reference: paramiko 4 dropped ``DSSKey``
# outright, and a missing legacy type must not stop the module importing.
_KEY_LOADERS = tuple(
    (label, getattr(paramiko, attr))
    for label, attr in (("Ed25519", "Ed25519Key"), ("ECDSA", "ECDSAKey"),
                        ("RSA", "RSAKey"), ("DSA", "DSSKey"))
    if hasattr(paramiko, attr)
)


def _prefer(options, attr: str, wanted: tuple[str, ...]) -> bool:
    """Reorder one paramiko preference list, keeping only names it knows.

    Assigning an unknown algorithm name raises, and both the property names and
    the supported set have moved between paramiko releases (MACs live under
    ``digests``, not ``macs``), so this intersects the wanted order with what
    this build actually offers and reports whether it could be applied.
    """
    available = tuple(getattr(options, attr, ()) or ())
    if not available:
        log.warning("paramiko has no security option %r; leaving its default order", attr)
        return False
    ordered = [name for name in wanted if name in available]
    ordered += [name for name in available if name not in ordered]
    setattr(options, attr, ordered)
    return True


class _RecordingTransport(paramiko.Transport):
    """paramiko transport that remembers which key exchange was agreed.

    paramiko instantiates a kex engine, runs it, then clears ``kex_engine`` back
    to ``None`` — so by the time the handshake returns there is no public way to
    ask what was negotiated.  Charon shows the user the real algorithms rather
    than the ones it asked for, so the name is captured as it is chosen.  Guarded
    throughout: if this internal hook ever disappears, the security panel loses
    one line and nothing else.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.negotiated_kex = ""

    def _parse_kex_init(self, m):  # noqa: D102 - paramiko internal
        super()._parse_kex_init(m)
        try:
            engine = self.kex_engine
            for name, cls in self._kex_info.items():
                if isinstance(engine, cls):
                    self.negotiated_kex = name
                    break
        except Exception:  # pragma: no cover - never break a handshake for a label
            pass


class SFTPTransport(Transport):
    """SSH File Transfer Protocol."""

    def __init__(self, site: Site, policy: Policy, hostkeys: Optional[HostKeyStore] = None) -> None:
        super().__init__(site, policy)
        self.hostkeys = hostkeys or HostKeyStore()
        self._t: Optional[paramiko.Transport] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    # ---------------------------------------------------------- lifecycle

    @property
    def is_connected(self) -> bool:
        return bool(self._sftp and self._t and self._t.is_active())

    def connect(self, creds: Credentials) -> None:
        site = self.site
        try:
            sock = socket.create_connection((site.host, site.port), timeout=20)
        except OSError as exc:
            raise TransportError(f"Cannot reach {site.host}:{site.port} — {exc.strerror or exc}")

        sock.settimeout(None)
        t = _RecordingTransport(sock, disabled_algorithms=DISABLED_ALGORITHMS)
        t.banner_timeout = 20
        t.auth_timeout = 30
        t.set_keepalive(30)
        opts = t.get_security_options()
        _prefer(opts, "ciphers", PREFERRED_CIPHERS)
        _prefer(opts, "digests", PREFERRED_MACS)  # paramiko calls MACs "digests"
        _prefer(opts, "kex", PREFERRED_KEX)

        try:
            t.start_client(timeout=20)
        except SSHException as exc:
            t.close()
            raise TransportError(f"SSH handshake failed: {exc}")

        # ---- identity check, before authentication ----------------------
        key = t.get_remote_server_key()
        key_type = key.get_name()
        blob = key.asbytes()
        identity = self.hostkeys.identity(site.host, site.port, key_type, blob,
                                          bits=getattr(key, "get_bits", lambda: 0)())
        decision = self.hostkeys.check(site.host, site.port, key_type, blob)
        if decision is TrustDecision.CHANGED:
            t.close()
            raise HostKeyChanged(
                identity,
                f"The SSH host key for {identity.label} has CHANGED since you last "
                f"connected. If the server was not rebuilt or re-keyed, someone may be "
                f"intercepting this connection.",
            )
        if decision is TrustDecision.UNKNOWN:
            t.close()
            raise HostKeyUnknown(
                identity,
                f"Charon has never connected to {identity.label} before. Check this "
                f"fingerprint against the server itself before trusting it.",
            )

        # ---- authentication ---------------------------------------------
        try:
            self._authenticate(t, creds)
        except (AuthFailed, TransportError):
            t.close()
            raise
        except AuthenticationException as exc:
            t.close()
            raise AuthFailed(f"Authentication failed: {exc}")
        except SSHException as exc:
            t.close()
            raise TransportError(f"Authentication error: {exc}")

        try:
            sftp = paramiko.SFTPClient.from_transport(t)
            if sftp is None:
                raise SSHException("server refused an SFTP channel")
            sftp.get_channel().settimeout(60)
        except SSHException as exc:
            t.close()
            raise TransportError(
                f"Connected and logged in, but the server would not open an SFTP "
                f"session: {exc}"
            )

        self._t, self._sftp = t, sftp
        self._cwd = normalise_remote(site.remote_dir or self.home())
        self.security = self._describe(identity.fingerprint, key_type)

    def _authenticate(self, t: paramiko.Transport, creds: Credentials) -> None:
        site = self.site
        user = site.username or ""

        if site.auth.value == "agent":
            keys = paramiko.Agent().get_keys()
            if not keys:
                raise AuthFailed(
                    "No keys were offered by the SSH agent. Start the agent and "
                    "ssh-add your key, or switch this site to key-file auth."
                )
            last: Exception | None = None
            for key in keys:
                try:
                    t.auth_publickey(user, key)
                    return
                except AuthenticationException as exc:
                    last = exc
            raise AuthFailed(f"The agent's keys were all rejected by the server. {last or ''}".strip())

        if site.auth.value == "key":
            key = self._load_key(site.key_path, creds.passphrase)
            t.auth_publickey(user, key)
            return

        if not creds.password:
            raise AuthFailed("A password is required for this site.")
        t.auth_password(user, creds.password)

    @staticmethod
    def _load_key(path: str, passphrase: Optional[str]):
        if not path:
            raise TransportError("No private key file is configured for this site.")
        errors = []
        needs_passphrase = False
        for label, loader in _KEY_LOADERS:
            try:
                return loader.from_private_key_file(path, password=passphrase or None)
            except PasswordRequiredException:
                needs_passphrase = True
            except SSHException as exc:
                errors.append(f"{label}: {exc}")
            except OSError as exc:
                raise TransportError(f"Cannot read private key {path}: {exc.strerror or exc}")
        if needs_passphrase:
            raise AuthFailed(
                "That private key is encrypted and the passphrase was missing or wrong."
            )
        raise TransportError(
            "Could not read that private key in any supported format "
            "(Ed25519, ECDSA, RSA, DSA)."
        )

    def _describe(self, fingerprint: str, key_type: str) -> SecurityState:
        t = self._t
        assert t is not None
        cipher = t.remote_cipher or t.local_cipher or ""
        aead = cipher.endswith("gcm@openssh.com")
        kex = getattr(t, "negotiated_kex", "")
        state = SecurityState(
            protocol=Protocol.SFTP,
            encrypted=True,
            cipher=cipher,
            kex=kex,
            mac="implicit (AEAD)" if aead else (t.remote_mac or t.local_mac or ""),
            host_key_type=key_type,
            fingerprint=fingerprint,
            identity_verified=True,
            verified_how="host key matches your pinned copy",
            data_channel_encrypted=True,
        )
        if not aead and state.mac.startswith("hmac-sha1"):
            state.warnings.append(
                "Server negotiated an SHA-1 MAC; it works, but the server is behind on patches."
            )
        if kex.startswith("diffie-hellman-group14"):
            state.warnings.append("Server chose a 2048-bit DH group; stronger groups are available.")
        return state

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._t is not None:
            try:
                self._t.close()
            except Exception:
                pass
            self._t = None

    # ------------------------------------------------------------ browsing

    def _client(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            raise TransportError("Not connected.")
        return self._sftp

    def home(self) -> str:
        try:
            return normalise_remote(self._client().normalize("."))
        except (OSError, SSHException):
            return "/"

    def listdir(self, path: str) -> list[RemoteEntry]:
        path = normalise_remote(path)
        try:
            attrs = self._client().listdir_attr(path)
        except FileNotFoundError:
            raise TransportError(f"No such directory: {path}")
        except PermissionError:
            raise TransportError(f"Permission denied: {path}")
        except (OSError, SSHException) as exc:
            raise TransportError(f"Cannot list {path}: {exc}")

        out = []
        for a in attrs:
            mode = a.st_mode or 0
            is_link = stat_mod.S_ISLNK(mode)
            is_dir = stat_mod.S_ISDIR(mode)
            if is_link:
                # listdir_attr reports the link itself; resolve it so the pane
                # can show whether following it lands on a directory.
                try:
                    target = self._client().stat(f"{path.rstrip('/')}/{a.filename}")
                    is_dir = stat_mod.S_ISDIR(target.st_mode or 0)
                except (OSError, SSHException):
                    pass  # broken link — leave it flagged as a plain entry
            out.append(RemoteEntry(
                name=a.filename,
                size=int(a.st_size or 0),
                mtime=float(a.st_mtime or 0),
                is_dir=is_dir,
                is_symlink=is_link,
                mode=stat_mod.filemode(mode) if mode else "",
                owner=str(a.st_uid) if a.st_uid is not None else "",
            ))
        return out

    def stat(self, path: str) -> RemoteEntry:
        path = normalise_remote(path)
        try:
            a = self._client().stat(path)
        except (OSError, SSHException) as exc:
            raise TransportError(f"Cannot stat {path}: {exc}")
        mode = a.st_mode or 0
        return RemoteEntry(
            name=path.rsplit("/", 1)[-1] or "/",
            size=int(a.st_size or 0),
            mtime=float(a.st_mtime or 0),
            is_dir=stat_mod.S_ISDIR(mode),
            mode=stat_mod.filemode(mode) if mode else "",
        )

    # ------------------------------------------------------------ mutation

    def mkdir(self, path: str) -> None:
        try:
            self._client().mkdir(normalise_remote(path))
        except (OSError, SSHException) as exc:
            raise TransportError(f"Cannot create folder: {exc}")

    def remove(self, path: str) -> None:
        try:
            self._client().remove(normalise_remote(path))
        except (OSError, SSHException) as exc:
            raise TransportError(f"Cannot delete file: {exc}")

    def rmdir(self, path: str) -> None:
        try:
            self._client().rmdir(normalise_remote(path))
        except (OSError, SSHException) as exc:
            raise TransportError(f"Cannot delete folder: {exc}")

    def rename(self, old: str, new: str) -> None:
        try:
            self._client().posix_rename(normalise_remote(old), normalise_remote(new))
        except (OSError, SSHException):
            try:
                self._client().rename(normalise_remote(old), normalise_remote(new))
            except (OSError, SSHException) as exc:
                raise TransportError(f"Cannot rename: {exc}")

    # ------------------------------------------------------------ transfer

    def download(self, remote: str, sink, *, offset: int = 0, size: int = 0,
                 progress: Optional[ProgressFn] = None,
                 cancel: Optional[threading.Event] = None) -> int:
        remote = normalise_remote(remote)
        done = offset
        try:
            with self._client().open(remote, "rb") as fh:
                fh.set_pipelined(True)
                if offset:
                    fh.seek(offset)
                elif size:
                    fh.prefetch(size)
                while True:
                    if cancel is not None and cancel.is_set():
                        raise TransferCancelled()
                    block = fh.read(CHUNK)
                    if not block:
                        break
                    sink.write(block)
                    done += len(block)
                    if progress:
                        progress(done, size)
        except TransferCancelled:
            raise
        except (OSError, SSHException) as exc:
            raise TransportError(f"Download of {remote} failed: {exc}")
        return done

    def upload(self, source, remote: str, *, offset: int = 0, size: int = 0,
               progress: Optional[ProgressFn] = None,
               cancel: Optional[threading.Event] = None) -> int:
        remote = normalise_remote(remote)
        done = offset
        mode = "ab" if offset else "wb"
        try:
            with self._client().open(remote, mode) as fh:
                fh.set_pipelined(True)
                while True:
                    if cancel is not None and cancel.is_set():
                        raise TransferCancelled()
                    block = source.read(CHUNK)
                    if not block:
                        break
                    fh.write(block)
                    done += len(block)
                    if progress:
                        progress(done, size)
        except TransferCancelled:
            raise
        except (OSError, SSHException) as exc:
            raise TransportError(f"Upload to {remote} failed: {exc}")
        return done

    def remote_sha256(self, path: str) -> Optional[str]:
        """Use the SFTP ``check-file`` extension when the server has it.

        OpenSSH does not implement it, so this returns ``None`` most of the
        time — and Charon then reports "size verified" instead of claiming a
        content match it never made.
        """
        try:
            with self._client().open(normalise_remote(path), "rb") as fh:
                algo, digest = fh.check("sha256")
            if "sha256" in str(algo).lower() and digest:
                return digest.hex()
        except Exception:
            return None
        return None

    def keepalive(self) -> None:
        try:
            if self._sftp is not None:
                self._sftp.stat(self._cwd)
        except Exception:
            pass
