"""FTPS (FTP over explicit TLS) and — only when deliberately unlocked — plain FTP.

FTP is a 1971 protocol with security bolted on in 1997, and every sharp edge is
still there.  This backend deals with all of them explicitly:

* **The control channel is not the data channel.**  ``AUTH TLS`` encrypts the
  commands; the *files* stay in the clear until ``PROT P`` is negotiated.  A
  client that skips it shows a padlock while shipping your data in plaintext.
  Charon issues ``PROT P`` and **hangs up if the server refuses it**.
* **PASV hands the client an address to dial.**  A malicious or confused server
  can point that anywhere — the classic FTP-bounce primitive.  Charon pins the
  data connection to the host it is already talking to and ignores the address
  in the reply.
* **Session reuse.**  Hardened servers (vsftpd's ``require_ssl_reuse``, FileZilla
  Server) demand that the data connection resume the control channel's TLS
  session, to prove it belongs to the same client.  Stock ``ftplib`` does not do
  this, which is why so much Python FTPS code dies on "425". Charon resumes it.
* **Self-signed certificates.**  The usual advice is to disable verification,
  which discards identity altogether.  Charon instead pins the certificate on
  first use, so a swap is still detected.
"""

from __future__ import annotations

import ftplib
import logging
import re
import ssl
import threading
from datetime import datetime, timezone
from typing import Optional

from .model import Credentials, Protocol, RemoteEntry, SecurityState, Site
from .policy import Policy, build_tls_context
from .safety import normalise_remote
from .transport import (
    AuthFailed,
    CertChanged,
    CertUnknown,
    ProgressFn,
    TransferCancelled,
    Transport,
    TransportError,
)
from .trust import CertPinStore, TrustDecision

log = logging.getLogger(__name__)

CHUNK = 262_144


class _SessionReusingFTP_TLS(ftplib.FTP_TLS):
    """``FTP_TLS`` that resumes the control channel's TLS session on the data
    channel, and refuses to dial an address the server made up."""

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            session = getattr(self.sock, "session", None)
            conn = self.context.wrap_socket(
                conn,
                server_hostname=self.host if self.context.check_hostname else None,
                session=session,
            )
        return conn, size


class FTPTransport(Transport):
    """FTP over TLS, or bare FTP when the policy has been unlocked for it."""

    def __init__(self, site: Site, policy: Policy, pins: Optional[CertPinStore] = None) -> None:
        super().__init__(site, policy)
        self.pins = pins or CertPinStore()
        self._ftp: Optional[ftplib.FTP] = None
        self._features: set[str] = set()
        self._needs_reconnect = False

    # ---------------------------------------------------------- lifecycle

    @property
    def is_connected(self) -> bool:
        return self._ftp is not None and not self._needs_reconnect

    def connect(self, creds: Credentials) -> None:
        if self.site.protocol is Protocol.FTPS:
            self._connect_tls(creds)
        else:
            self._connect_plain(creds)
        self._read_features()
        try:
            if "UTF8" in self._features and self._ftp is not None:
                self._ftp.sendcmd("OPTS UTF8 ON")
        except ftplib.all_errors:
            pass
        self._cwd = normalise_remote(self.site.remote_dir or self.home())

    # -- TLS ------------------------------------------------------------

    def _connect_tls(self, creds: Credentials) -> None:
        site = self.site
        verify = site.verify_tls
        ca_verified = False

        if verify:
            try:
                ftp = self._open(build_tls_context(self.policy, verify=True))
                ca_verified = True
            except ssl.SSLCertVerificationError as exc:
                # Not CA-signed.  That is the normal case for a NAS or an
                # internal server, so fall through to pinning rather than
                # either failing outright or silently trusting.
                log.info("FTPS certificate is not CA-valid (%s); checking pins", exc.verify_message)
                ftp = self._pin_or_raise()
            except ssl.SSLError as exc:
                raise TransportError(f"TLS handshake with {site.host} failed: {exc}")
            except OSError as exc:
                raise TransportError(f"Cannot reach {site.host}:{site.port} — {exc.strerror or exc}")
        else:
            ftp = self._pin_or_raise()

        assert isinstance(ftp, ftplib.FTP_TLS)
        der = ftp.sock.getpeercert(binary_form=True) if ftp.sock else b""
        cert = ftp.sock.getpeercert() if ftp.sock and ca_verified else None
        tls_version = ftp.sock.version() if ftp.sock else ""
        cipher_info = ftp.sock.cipher() if ftp.sock else None

        self._ftp = ftp
        self._login(creds)

        # --- the step that actually protects the files --------------------
        try:
            ftp.prot_p()
        except ftplib.all_errors as exc:
            self.close()
            raise TransportError(
                "The server accepted an encrypted login but refused to encrypt the "
                f"data channel (PROT P): {exc}\n\nThat would send your files across "
                "the network in the clear, so Charon has disconnected."
            )

        identity = CertPinStore.identity(site.host, site.port, der or b"", cert)
        self.security = SecurityState(
            protocol=Protocol.FTPS,
            encrypted=True,
            tls_version=tls_version,
            cipher=cipher_info[0] if cipher_info else "",
            identity_verified=True,
            verified_how=("certificate signed by a trusted CA"
                          if ca_verified else "certificate matches your pinned copy"),
            fingerprint=identity.fingerprint,
            host_key_type="TLS certificate",
            data_channel_encrypted=True,
        )
        if not ca_verified:
            self.security.warnings.append(
                "Certificate is self-signed; trusted because its fingerprint matches "
                "the one you approved."
            )
        if tls_version and tls_version < "TLSv1.2":
            self.security.warnings.append(f"Server negotiated {tls_version}, which is obsolete.")

    def _open(self, ctx: ssl.SSLContext) -> ftplib.FTP_TLS:
        ftp = _SessionReusingFTP_TLS(context=ctx)
        ftp.encoding = "utf-8"
        ftp.connect(self.site.host, self.site.port, timeout=20)
        ftp.auth()  # AUTH TLS — upgrade the control channel before any credential
        self._harden(ftp)
        return ftp

    def _pin_or_raise(self) -> ftplib.FTP_TLS:
        """Fetch the certificate without trusting it, then consult the pin store."""
        site = self.site
        probe_ctx = build_tls_context(self.policy, verify=False)
        try:
            ftp = self._open(probe_ctx)
        except ssl.SSLError as exc:
            raise TransportError(f"TLS handshake with {site.host} failed: {exc}")
        except OSError as exc:
            raise TransportError(f"Cannot reach {site.host}:{site.port} — {exc.strerror or exc}")

        der = ftp.sock.getpeercert(binary_form=True) if ftp.sock else b""
        if not der:
            self._quiet_close(ftp)
            raise TransportError("The server did not present a TLS certificate.")

        decision = self.pins.check(site.host, site.port, der)
        identity = CertPinStore.identity(site.host, site.port, der)
        if decision is TrustDecision.CHANGED:
            self._quiet_close(ftp)
            raise CertChanged(
                identity,
                f"The TLS certificate for {identity.label} has CHANGED since you "
                f"approved it. If the server's certificate was not just renewed, "
                f"someone may be intercepting this connection.",
            )
        if decision is TrustDecision.UNKNOWN:
            self._quiet_close(ftp)
            raise CertUnknown(
                identity,
                f"{identity.label} presented a certificate that is not signed by any "
                f"authority your system trusts. Check this fingerprint against the "
                f"server before approving it.",
            )
        return ftp

    # -- plaintext ------------------------------------------------------

    def _connect_plain(self, creds: Credentials) -> None:
        if not self.policy.allow_plaintext_ftp:
            # Belt and braces: policy.check_connection already blocks this, but
            # the refusal must also exist at the point the socket is opened, so
            # no future caller can route around it.
            raise TransportError("Plain FTP is disabled by policy.")
        site = self.site
        try:
            ftp = ftplib.FTP()
            ftp.encoding = "utf-8"
            ftp.connect(site.host, site.port, timeout=20)
        except OSError as exc:
            raise TransportError(f"Cannot reach {site.host}:{site.port} — {exc.strerror or exc}")
        self._harden(ftp)
        self._ftp = ftp
        self._login(creds)
        self.security = SecurityState(
            protocol=Protocol.FTP,
            encrypted=False,
            identity_verified=False,
            data_channel_encrypted=False,
            warnings=[
                "Your password was sent across the network in readable text.",
                "Every file transferred can be read and altered in transit.",
                "Anyone on this network can replay your login.",
            ],
        )

    def _harden(self, ftp: ftplib.FTP) -> None:
        ftp.set_pasv(self.site.passive)
        # Never dial an address the server chose.  ftplib defaults this to
        # False on modern Python; set it anyway so the guarantee does not
        # depend on the interpreter version underneath us.
        ftp.trust_server_pasv_ipv4_address = False

    def _login(self, creds: Credentials) -> None:
        assert self._ftp is not None
        user = self.site.username or "anonymous"
        password = creds.password or ("charon@example.invalid" if user == "anonymous" else "")
        try:
            self._ftp.login(user, password)
        except ftplib.error_perm as exc:
            self.close()
            raise AuthFailed(f"The server rejected that login: {exc}")
        except ftplib.all_errors as exc:
            self.close()
            raise TransportError(f"Login failed: {exc}")

    def _read_features(self) -> None:
        self._features = set()
        try:
            assert self._ftp is not None
            raw = self._ftp.sendcmd("FEAT")
        except ftplib.all_errors:
            return
        for line in raw.splitlines()[1:]:
            token = line.strip().split(" ")[0].upper()
            if token and not token.startswith("211"):
                self._features.add(token)

    @staticmethod
    def _quiet_close(ftp: ftplib.FTP) -> None:
        try:
            ftp.close()
        except Exception:
            pass

    def close(self) -> None:
        if self._ftp is not None:
            try:
                self._ftp.quit()
            except Exception:
                self._quiet_close(self._ftp)
            self._ftp = None

    # ------------------------------------------------------------ browsing

    def _client(self) -> ftplib.FTP:
        if self._ftp is None:
            raise TransportError("Not connected.")
        return self._ftp

    def home(self) -> str:
        try:
            return normalise_remote(self._client().pwd())
        except ftplib.all_errors:
            return "/"

    def listdir(self, path: str) -> list[RemoteEntry]:
        ftp = self._client()
        path = normalise_remote(path)
        try:
            ftp.cwd(path)
        except ftplib.all_errors as exc:
            raise TransportError(f"Cannot open {path}: {exc}")

        if "MLSD" in self._features:
            try:
                return self._listdir_mlsd(ftp)
            except ftplib.all_errors as exc:
                log.info("MLSD failed on %s (%s); falling back to LIST", path, exc)
        return self._listdir_list(ftp)

    def _listdir_mlsd(self, ftp: ftplib.FTP) -> list[RemoteEntry]:
        out = []
        for name, facts in ftp.mlsd(facts=["type", "size", "modify", "perm", "unix.owner"]):
            kind = facts.get("type", "")
            if kind in ("cdir", "pdir"):
                continue
            out.append(RemoteEntry(
                name=name,
                size=int(facts.get("size", 0) or 0),
                mtime=_mlsd_time(facts.get("modify", "")),
                is_dir=kind in ("dir", "OS.unix=slink:dir"),
                is_symlink=kind.startswith("OS.unix=slink"),
                mode=facts.get("perm", ""),
                owner=facts.get("unix.owner", ""),
            ))
        return out

    def _listdir_list(self, ftp: ftplib.FTP) -> list[RemoteEntry]:
        lines: list[str] = []
        try:
            ftp.retrlines("LIST -a", lines.append)
        except ftplib.all_errors:
            lines.clear()
            try:
                ftp.retrlines("LIST", lines.append)
            except ftplib.all_errors as exc:
                raise TransportError(f"Cannot list directory: {exc}")
        out = []
        for line in lines:
            entry = _parse_list_line(line)
            if entry and entry.name not in (".", ".."):
                out.append(entry)
        return out

    def stat(self, path: str) -> RemoteEntry:
        ftp = self._client()
        path = normalise_remote(path)
        name = path.rsplit("/", 1)[-1] or "/"
        try:
            ftp.voidcmd("TYPE I")
            size = ftp.size(path) or 0
            return RemoteEntry(name=name, size=int(size), is_dir=False)
        except ftplib.all_errors:
            pass
        # SIZE fails on directories, which is how we identify them here.
        try:
            here = ftp.pwd()
            ftp.cwd(path)
            ftp.cwd(here)
            return RemoteEntry(name=name, is_dir=True)
        except ftplib.all_errors as exc:
            raise TransportError(f"Cannot stat {path}: {exc}")

    # ------------------------------------------------------------ mutation

    def mkdir(self, path: str) -> None:
        try:
            self._client().mkd(normalise_remote(path))
        except ftplib.all_errors as exc:
            raise TransportError(f"Cannot create folder: {exc}")

    def remove(self, path: str) -> None:
        try:
            self._client().delete(normalise_remote(path))
        except ftplib.all_errors as exc:
            raise TransportError(f"Cannot delete file: {exc}")

    def rmdir(self, path: str) -> None:
        try:
            self._client().rmd(normalise_remote(path))
        except ftplib.all_errors as exc:
            raise TransportError(f"Cannot delete folder: {exc}")

    def rename(self, old: str, new: str) -> None:
        try:
            self._client().rename(normalise_remote(old), normalise_remote(new))
        except ftplib.all_errors as exc:
            raise TransportError(f"Cannot rename: {exc}")

    # ------------------------------------------------------------ transfer

    def download(self, remote: str, sink, *, offset: int = 0, size: int = 0,
                 progress: Optional[ProgressFn] = None,
                 cancel: Optional[threading.Event] = None) -> int:
        ftp = self._client()
        remote = normalise_remote(remote)
        done = offset
        try:
            ftp.voidcmd("TYPE I")
            conn = ftp.transfercmd(f"RETR {remote}", rest=offset or None)
        except ftplib.all_errors as exc:
            raise TransportError(f"Download of {remote} failed to start: {exc}")

        try:
            while True:
                if cancel is not None and cancel.is_set():
                    raise TransferCancelled()
                block = conn.recv(CHUNK)
                if not block:
                    break
                sink.write(block)
                done += len(block)
                if progress:
                    progress(done, size)
        except TransferCancelled:
            self._abort(conn)
            raise
        except (OSError, ssl.SSLError) as exc:
            self._abort(conn)
            raise TransportError(f"Download of {remote} was interrupted: {exc}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

        try:
            ftp.voidresp()
        except ftplib.all_errors as exc:
            raise TransportError(f"Server reported a problem finishing {remote}: {exc}")
        return done

    def upload(self, source, remote: str, *, offset: int = 0, size: int = 0,
               progress: Optional[ProgressFn] = None,
               cancel: Optional[threading.Event] = None) -> int:
        ftp = self._client()
        remote = normalise_remote(remote)
        done = offset
        try:
            ftp.voidcmd("TYPE I")
            cmd = f"APPE {remote}" if offset else f"STOR {remote}"
            conn = ftp.transfercmd(cmd)
        except ftplib.all_errors as exc:
            raise TransportError(f"Upload to {remote} failed to start: {exc}")

        try:
            while True:
                if cancel is not None and cancel.is_set():
                    raise TransferCancelled()
                block = source.read(CHUNK)
                if not block:
                    break
                conn.sendall(block)
                done += len(block)
                if progress:
                    progress(done, size)
        except TransferCancelled:
            self._abort(conn)
            raise
        except (OSError, ssl.SSLError) as exc:
            self._abort(conn)
            raise TransportError(f"Upload to {remote} was interrupted: {exc}")
        finally:
            try:
                if isinstance(conn, ssl.SSLSocket):
                    conn.unwrap()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

        try:
            ftp.voidresp()
        except ftplib.all_errors as exc:
            raise TransportError(f"Server reported a problem storing {remote}: {exc}")
        return done

    def _abort(self, conn) -> None:
        """Cut a transfer short.

        The control channel is left in an indeterminate state after an aborted
        data transfer — some servers answer the ABOR, some do not — so the
        connection is flagged for replacement rather than reused and hoped for.
        """
        try:
            conn.close()
        except Exception:
            pass
        self._needs_reconnect = True

    def remote_sha256(self, path: str) -> Optional[str]:
        """Use RFC 3659-era hash extensions when the server advertises one."""
        ftp = self._client()
        path = normalise_remote(path)
        try:
            if "HASH" in self._features:
                ftp.sendcmd("OPTS HASH SHA-256")
                reply = ftp.sendcmd(f"HASH {path}")
                match = re.search(r"([0-9a-fA-F]{64})", reply)
                if match:
                    return match.group(1).lower()
            if "XSHA256" in self._features:
                reply = ftp.sendcmd(f"XSHA256 {path}")
                match = re.search(r"([0-9a-fA-F]{64})", reply)
                if match:
                    return match.group(1).lower()
        except ftplib.all_errors:
            return None
        return None

    def supports_resume(self) -> bool:
        return "REST" in self._features or self.site.protocol is Protocol.FTPS

    def keepalive(self) -> None:
        try:
            self._client().voidcmd("NOOP")
        except Exception:
            pass


# ------------------------------------------------------------------ parsing

_LIST_UNIX = re.compile(
    r"^(?P<mode>[bcdlps\-][rwxstST\-]{9})[+@.]?\s+\d+\s+"
    r"(?P<owner>\S+)\s+(?P<group>\S+)\s+(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\d{1,2}\s+(?:\d{4}|\d{2}:\d{2}))\s+(?P<name>.+)$"
)
_LIST_DOS = re.compile(
    r"^(?P<date>\d{2}-\d{2}-\d{2,4}\s+\d{2}:\d{2}(?:[AP]M)?)\s+"
    r"(?P<dir><DIR>|\d+)\s+(?P<name>.+)$"
)


def _parse_list_line(line: str) -> Optional[RemoteEntry]:
    """Parse one line of a ``LIST`` response.

    ``LIST`` output is for humans, not machines — the format is whatever the
    server's ``ls`` prints.  This handles the two families that cover almost
    everything in the wild; anything else falls back to a name-only entry
    rather than guessing at a size or a type.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    m = _LIST_UNIX.match(line)
    if m:
        name = m.group("name")
        is_link = m.group("mode").startswith("l")
        if is_link and " -> " in name:
            name = name.split(" -> ", 1)[0]
        return RemoteEntry(
            name=name,
            size=int(m.group("size")),
            is_dir=m.group("mode").startswith("d"),
            is_symlink=is_link,
            mode=m.group("mode"),
            owner=m.group("owner"),
        )

    m = _LIST_DOS.match(line)
    if m:
        is_dir = m.group("dir") == "<DIR>"
        return RemoteEntry(
            name=m.group("name"),
            size=0 if is_dir else int(m.group("dir")),
            is_dir=is_dir,
        )

    parts = line.split()
    return RemoteEntry(name=parts[-1]) if parts else None


def _mlsd_time(value: str) -> float:
    """MLSD ``modify`` facts are ``YYYYMMDDHHMMSS`` in UTC."""
    if not value:
        return 0.0
    try:
        dt = datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return 0.0
