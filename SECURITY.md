# Security

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/at0m-b0mb/Charon/security/advisories/new)
rather than a public issue. Please include the protocol, the server software
involved, and what an attacker gains. Expect a first reply within a few days.

---

## What Charon protects, and what it does not

Charon defends the **transfer**: the credentials you use, the bytes on the wire,
and the files as they land on disk.

It does **not** defend against a compromised endpoint. If your machine is running
a keylogger, or the server is already owned, no client can help you. Charon's
job is to make sure that everything *between* those two points is confidential,
authenticated, and verifiable — and to refuse, loudly, when it cannot be.

---

## Design decisions and why

### The host key is checked before the password is sent

SSH encrypts the session first and authenticates the server second. A client
that authenticates before deciding whether it trusts the server hands the
password to whoever answered the connection — and on a first connection, that is
exactly what a machine-in-the-middle is waiting for.

Charon drives paramiko's low-level `Transport` rather than `SSHClient`, inspects
`get_remote_server_key()` immediately after the handshake, and raises before
`auth_password` is ever reached. This is covered by a test that asserts the
server never observed an authentication attempt
(`tests/test_sftp_live.py::test_the_password_is_not_sent_to_an_unverified_server`).

`AutoAddPolicy` — the policy nearly every Python SFTP tutorial reaches for —
appears nowhere in this codebase. There is no code path that accepts a host key
without a human clicking a dialog that shows the fingerprint.

### A changed host key is refused, not warned about

Three distinct outcomes, never collapsed into two:

| Outcome | Meaning | What Charon does |
|---|---|---|
| `KNOWN` | pinned and matching | connect silently |
| `UNKNOWN` | never seen before | show the fingerprint, default to **Cancel** |
| `CHANGED` | pinned and **different** | red dialog, default to **Cancel**, button reads "Replace the trusted key" |

A host that is pinned under `ssh-rsa` and now offers `ssh-ed25519` is reported as
`UNKNOWN`, not `CHANGED` — servers legitimately add key types, and crying wolf
teaches people to click through the dialog that matters.

### FTPS: the padlock is on the commands, not the files

`AUTH TLS` encrypts the FTP *control* channel. The data channel — the actual
files — stays in the clear until `PROT P` is negotiated. A client that shows a
padlock after `AUTH TLS` alone is lying to you.

Charon issues `PROT P` and **disconnects if the server refuses it**. A session
whose data channel is not encrypted grades `UNSAFE` regardless of how good the
control-channel TLS is.

Also handled:

- **PASV address injection.** The server's `PASV` reply nominates an address for
  the client to dial, which is the classic FTP-bounce primitive. Charon sets
  `trust_server_pasv_ipv4_address = False` explicitly and reuses the control
  connection's host.
- **TLS session reuse.** Hardened servers (vsftpd `require_ssl_reuse`, FileZilla
  Server) require the data connection to resume the control channel's TLS
  session. Stock `ftplib` does not, which is why so much Python FTPS code fails
  with "425". Charon resumes it.
- **Self-signed certificates.** The usual advice is to disable verification,
  which throws away identity entirely. Charon pins the certificate on first use
  instead, so a later swap is still detected.

### Plain FTP is off by default

FTP sends the username, the password, and every byte of every file in readable
text. Enabling it takes a deliberate switch in Settings *and* a per-connection
confirmation, and a plaintext session keeps a red banner across the window for
its whole life. Charon will never describe such a session as secure.

### A remote server never chooses a local path

A directory listing is attacker-controlled data. A server can answer with
`../../../../etc/cron.d/backdoor`, a name containing a NUL, or a Windows device
name. Every remote name that becomes part of a local path passes through
`charon/core/safety.py`, which reduces it to a single safe component, and the
resulting path is then re-checked against the destination directory after
resolution — which also catches redirection through a symlink already on disk.

Related guards: remote symlinks are not followed when copying a folder, and
directory recursion is depth-capped so a self-referential tree cannot hang the
client.

### A partial download never looks like a complete file

Bytes land in a `.charon-part` sidecar, created `0600` from the first byte, and
are moved into place with a single `os.replace` only after the transfer has been
checked. Pull the network cable and you are left with an obviously incomplete
file, not a truncated document that opens fine and is quietly missing its end.

The default conflict rule invents a new name. Overwriting an existing file is
always a deliberate choice.

### Integrity is reported honestly

Charon hashes every byte it writes, in the same pass as the transfer. When the
server can also hash — FTPS servers advertising `HASH`/`XSHA256`, SFTP servers
with the `check-file` extension — the two are compared and a mismatch throws the
file away.

Most servers, OpenSSH included, cannot hash remotely. In that case Charon says
*"size verified; SHA-256 … (server offers no hash)"* rather than showing a green
tick that means "we assume so".

### Credentials

Three modes, chosen in Settings:

- **OS keychain** — macOS Keychain, Windows Credential Manager, Secret Service /
  KWallet. The OS owns the key material. Probed with a real round-trip before
  being offered, because `keyring` imports fine on a machine with no working
  backend and then fails at first use.
- **Encrypted vault** — a single file: AES-256-GCM, key derived with scrypt at
  N=2¹⁶, r=8, p=1. The 13-byte header carrying the KDF parameters is passed as
  additional authenticated data, so an attacker cannot weaken the cost factor of
  a stolen vault and have it accepted. A fresh nonce is drawn on every write.
- **Never store** — prompt every time.

Saved-site files contain the username and *where* the secret lives, never the
secret. Nothing sensitive is written outside a `0700` per-user directory.

### Cryptographic algorithms

SSH ciphers, MACs and key exchanges known to be weak are refused outright rather
than deprioritised: all CBC modes, 3DES, RC4, MD5 and truncated MACs, and the
SHA-1 key exchanges. Preference order puts AES-GCM (AEAD) first, then AES-CTR
paired with SHA-2 encrypt-then-MAC, and Curve25519 ahead of the NIST curves for
key exchange. FTPS requires TLS 1.2 as a floor, with compression disabled.

The status bar reports what was **actually negotiated**, not what was requested,
and flags a session as "secure, with notes" when the server picked something
dated.

---

## Threat model, stated plainly

**In scope:** passive interception, active machine-in-the-middle, hostile or
compromised servers serving malicious directory listings, local theft of the
config directory or the vault file, and interrupted or corrupted transfers.

**Out of scope:** malware on your own machine, a server you have already lost
control of, traffic analysis (Charon does not hide *that* you are transferring
files or how large they are), and physical coercion.

## No telemetry

Charon makes no network connection other than to the servers you tell it to
connect to. There is no update check, no analytics, and no crash reporting. The
log file lives in the config directory, contains no secrets, and is plain text
so you can check that claim yourself.
