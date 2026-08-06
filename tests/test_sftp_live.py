"""End-to-end SFTP tests against a real SSH server running in-process.

Everything below goes over a genuine TCP socket, a genuine SSH handshake and a
genuine SFTP channel — no mocking of paramiko.  That is the only way to prove
the parts that matter here actually hold in practice: that the host key is
checked *before* the password is sent, that an unknown key stops the connection,
and that a changed key is refused rather than quietly accepted.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time
from pathlib import Path

import paramiko
import pytest

from charon.core.model import AuthMethod, Credentials, Grade, Protocol, Site
from charon.core.policy import Policy
from charon.core.sftp import SFTPTransport
from charon.core.transport import AuthFailed, HostKeyChanged, HostKeyUnknown
from charon.core.trust import HostKeyStore

USER = "kai"
PASSWORD = "hunter2-correct"
PAYLOAD = b"the ferryman carries what you give him\n" * 300


# --------------------------------------------------------------- the server

class _Server(paramiko.ServerInterface):
    def __init__(self) -> None:
        self.password_seen_at: float | None = None

    def check_auth_password(self, username, password):
        self.password_seen_at = time.monotonic()
        if username == USER and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


class _Handle(paramiko.SFTPHandle):
    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)


class _SFTPServer(paramiko.SFTPServerInterface):
    """A minimal real SFTP server rooted at a temporary directory."""

    ROOT = ""

    def _real(self, path: str) -> str:
        return os.path.join(self.ROOT, path.lstrip("/"))

    def list_folder(self, path):
        try:
            out = []
            for name in os.listdir(self._real(path)):
                attr = paramiko.SFTPAttributes.from_stat(
                    os.stat(os.path.join(self._real(path), name)))
                attr.filename = name
                out.append(attr)
            return out
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    lstat = stat

    def open(self, path, flags, attr):
        real = self._real(path)
        try:
            if flags & os.O_WRONLY:
                mode = "ab" if flags & os.O_APPEND else "wb"
            elif flags & os.O_RDWR:
                mode = "a+b" if flags & os.O_APPEND else "r+b"
            else:
                mode = "rb"
            handle = _Handle(flags)
            fobj = open(real, mode)
            handle.filename = real
            handle.readfile = fobj
            handle.writefile = fobj
            return handle
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return paramiko.SFTP_OK

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._real(path))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return paramiko.SFTP_OK

    def rmdir(self, path):
        try:
            os.rmdir(self._real(path))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return paramiko.SFTP_OK

    def rename(self, oldpath, newpath):
        try:
            os.rename(self._real(oldpath), self._real(newpath))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return paramiko.SFTP_OK

    def canonicalize(self, path):
        return "/" + os.path.relpath(
            os.path.realpath(self._real(path)), self.ROOT).replace("\\", "/").lstrip("./")


class LiveSFTPServer:
    """Accepts one connection at a time on an ephemeral localhost port."""

    def __init__(self, root: Path, host_key: paramiko.PKey) -> None:
        self.root = root
        self.host_key = host_key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.servers: list[_Server] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(client,), daemon=True).start()

    def _session(self, client: socket.socket) -> None:
        transport = paramiko.Transport(client)
        transport.add_server_key(self.host_key)
        root = str(self.root)
        handler = type("_Rooted", (_SFTPServer,), {"ROOT": root})
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, handler)
        server = _Server()
        self.servers.append(server)
        try:
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is None:
                return
            while transport.is_active() and not self._stop.is_set():
                time.sleep(0.05)
        except Exception:
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture(scope="module")
def host_key():
    return paramiko.ECDSAKey.generate()


@pytest.fixture(scope="module")
def other_key():
    return paramiko.ECDSAKey.generate()


@pytest.fixture
def server(tmp_path_factory, host_key):
    root = tmp_path_factory.mktemp("sftp-root")
    (root / "report.pdf").write_bytes(PAYLOAD)
    (root / "notes.txt").write_text("hello from the far side\n")
    (root / "archive").mkdir()
    (root / "archive" / "old.log").write_bytes(b"log line\n" * 50)
    srv = LiveSFTPServer(root, host_key)
    yield srv
    srv.close()


def make_site(server, **kw) -> Site:
    return Site(name="live", host="127.0.0.1", port=server.port,
                protocol=Protocol.SFTP, username=USER, auth=AuthMethod.PASSWORD, **kw)


def connect(server, store, **kw) -> SFTPTransport:
    transport = SFTPTransport(make_site(server, **kw), Policy(), hostkeys=store)
    transport.connect(Credentials(password=PASSWORD))
    return transport


@pytest.fixture
def trusted_store(tmp_path, server, host_key):
    store = HostKeyStore(path=tmp_path / "known_hosts")
    store.trust("127.0.0.1", server.port, host_key.get_name(), host_key.asbytes())
    return store


# ------------------------------------------------------------ trust gating

def test_an_unknown_host_key_stops_the_connection(tmp_path, server):
    store = HostKeyStore(path=tmp_path / "known_hosts")
    transport = SFTPTransport(make_site(server), Policy(), hostkeys=store)
    with pytest.raises(HostKeyUnknown) as caught:
        transport.connect(Credentials(password=PASSWORD))
    assert caught.value.identity.fingerprint.startswith("SHA256:")
    assert caught.value.identity.blob, "the key must travel with its fingerprint"


def test_the_password_is_not_sent_to_an_unverified_server(tmp_path, server):
    """The whole point of checking the key first. If Charon ever authenticates
    before the trust decision, a machine-in-the-middle harvests the password on
    the very first connection."""
    store = HostKeyStore(path=tmp_path / "known_hosts")
    transport = SFTPTransport(make_site(server), Policy(), hostkeys=store)
    with pytest.raises(HostKeyUnknown):
        transport.connect(Credentials(password=PASSWORD))
    assert all(s.password_seen_at is None for s in server.servers)


def test_a_changed_host_key_is_refused(tmp_path, server, other_key):
    store = HostKeyStore(path=tmp_path / "known_hosts")
    # Pin a *different* key under the same algorithm: the interception case.
    store.trust("127.0.0.1", server.port, other_key.get_name(), other_key.asbytes())
    transport = SFTPTransport(make_site(server), Policy(), hostkeys=store)
    with pytest.raises(HostKeyChanged):
        transport.connect(Credentials(password=PASSWORD))


def test_a_pinned_key_connects_cleanly(server, trusted_store):
    transport = connect(server, trusted_store)
    try:
        assert transport.is_connected
        assert transport.security.encrypted
        assert transport.security.identity_verified
        assert transport.security.grade in (Grade.STRONG, Grade.OK)
        assert transport.security.cipher
        assert transport.security.kex
    finally:
        transport.close()


def test_a_wrong_password_is_reported_as_an_auth_failure(server, trusted_store):
    transport = SFTPTransport(make_site(server), Policy(), hostkeys=trusted_store)
    with pytest.raises(AuthFailed):
        transport.connect(Credentials(password="not the password"))


# --------------------------------------------------------------- operations

def test_listing_a_directory(server, trusted_store):
    transport = connect(server, trusted_store)
    try:
        names = {e.name: e for e in transport.listdir("/")}
        assert "report.pdf" in names
        assert names["report.pdf"].size == len(PAYLOAD)
        assert names["archive"].is_dir
        assert not names["report.pdf"].is_dir
        assert names["report.pdf"].mode.startswith("-rw")
    finally:
        transport.close()


def test_download_over_the_wire_is_byte_exact(server, trusted_store, tmp_path):
    transport = connect(server, trusted_store)
    try:
        target = tmp_path / "out.pdf"
        with target.open("wb") as sink:
            written = transport.download("/report.pdf", sink, size=len(PAYLOAD))
        assert written == len(PAYLOAD)
        assert hashlib.sha256(target.read_bytes()).hexdigest() == \
            hashlib.sha256(PAYLOAD).hexdigest()
    finally:
        transport.close()


def test_resuming_a_download_from_an_offset(server, trusted_store, tmp_path):
    transport = connect(server, trusted_store)
    try:
        target = tmp_path / "partial.pdf"
        target.write_bytes(PAYLOAD[:5000])
        with target.open("ab") as sink:
            transport.download("/report.pdf", sink, offset=5000, size=len(PAYLOAD))
        assert target.read_bytes() == PAYLOAD
    finally:
        transport.close()


def test_upload_then_read_back(server, trusted_store, tmp_path):
    transport = connect(server, trusted_store)
    try:
        source = tmp_path / "upload.bin"
        source.write_bytes(PAYLOAD)
        with source.open("rb") as fh:
            transport.upload(fh, "/uploaded.bin", size=len(PAYLOAD))
        assert transport.stat("/uploaded.bin").size == len(PAYLOAD)
    finally:
        transport.close()


def test_mkdir_rename_and_remove(server, trusted_store):
    transport = connect(server, trusted_store)
    try:
        transport.mkdir("/fresh")
        assert any(e.name == "fresh" for e in transport.listdir("/"))
        transport.rename("/fresh", "/renamed")
        assert any(e.name == "renamed" for e in transport.listdir("/"))
        transport.rmdir("/renamed")
        assert not any(e.name == "renamed" for e in transport.listdir("/"))
    finally:
        transport.close()


def test_cancelling_a_transfer_stops_it(server, trusted_store, tmp_path):
    transport = connect(server, trusted_store)
    cancel = threading.Event()
    cancel.set()  # already cancelled: the loop must bail on its first check
    try:
        from charon.core.transport import TransferCancelled

        with (tmp_path / "x.bin").open("wb") as sink:
            with pytest.raises(TransferCancelled):
                transport.download("/report.pdf", sink, size=len(PAYLOAD),
                                   cancel=cancel)
    finally:
        transport.close()


def test_the_negotiated_cipher_is_a_modern_one(server, trusted_store):
    """The weak-algorithm blocklist is not decoration — check what was actually
    agreed, not what was offered."""
    transport = connect(server, trusted_store)
    try:
        cipher = transport.security.cipher
        assert "cbc" not in cipher, f"negotiated a CBC cipher: {cipher}"
        assert "3des" not in cipher
        assert cipher.startswith("aes")
        assert "md5" not in (transport.security.mac or "")
    finally:
        transport.close()
