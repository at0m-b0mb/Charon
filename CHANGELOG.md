# Changelog

All notable changes to Charon are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08-06

First release.

### Transfers
- Dual-pane browser: local filesystem on the left, server on the right.
- **Copy and paste transfers** — `Ctrl+C` in one pane, `Ctrl+V` in the other.
  The clipboard holds references, not bytes, so copying a large tree costs
  nothing until you paste. Clipboard entries are bound to the session they came
  from and refuse to paste against a different server.
- Drag and drop between panes, and from the OS file manager onto the server pane.
- Recursive folder transfers with a queue showing per-file progress, transfer
  rate and ETA.
- Resume interrupted downloads from the `.charon-part` sidecar.
- Conflict handling — keep both (default), resume, skip, or overwrite.
- Transfers run on a separate connection, so a large upload never blocks
  directory browsing.
- Move semantics (`Ctrl+X`) delete the source only after every file in the batch
  has transferred and verified, and only after a confirmation.

### Security
- **SFTP** over SSH and **FTPS** over explicit TLS (`AUTH TLS`).
- Host key verified **before** authentication — no credential reaches an
  unverified server. `AutoAddPolicy` is not used anywhere.
- Host keys and TLS certificates pinned on first use; `known_hosts` is
  OpenSSH-compatible. A changed key produces a red, cancel-by-default dialog
  distinct from a first-contact prompt.
- `PROT P` enforced for FTPS — Charon disconnects if the server will not encrypt
  the data channel.
- `PASV` address injection blocked; TLS session reuse on the data connection for
  servers that require it.
- Weak algorithms refused: CBC ciphers, 3DES, RC4, MD5 and truncated MACs, SHA-1
  key exchanges. TLS 1.2 floor for FTPS with compression disabled.
- Plain FTP disabled by default; enabling it needs a settings switch plus a
  per-connection confirmation, and marks the whole session with a red banner.
- Remote-supplied filenames sanitised before they can touch a local path;
  remote symlinks not followed when copying folders; directory recursion
  depth-capped.
- Downloads written atomically through a `0600` sidecar; config directory `0700`.
- SHA-256 computed over every transfer, compared against the server's hash when
  the server can produce one, and reported honestly when it cannot.
- Credentials in the OS keychain (probed for real availability) or an
  AES-256-GCM vault with an scrypt-derived key and authenticated KDF parameters.
- Idle timeout disconnects the session and re-locks the vault.
- Live security badge reporting the negotiated cipher, key exchange, MAC and
  fingerprint — what was agreed, not what was asked for.

### Interface
- Dark and light themes; icons drawn at runtime, so there are no bitmap assets
  to go blurry on a high-DPI screen.
- All network work on a background thread; no dialog can be raised from it.

### Tests
- 132 tests, including 12 against a real in-process SSH server over a genuine
  socket.

[1.0.0]: https://github.com/at0m-b0mb/Charon/releases/tag/v1.0.0
