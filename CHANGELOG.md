# Changelog

All notable changes to Charon are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-08-07

Bug-fix and feature release. **Everyone on 1.0.0 should upgrade** — this fixes
three ways Charon could destroy a file you did not ask it to touch.

### Fixed — data loss

- **"Resume" silently overwrote a complete file.** Choosing the Resume conflict
  rule when there was no `.charon-part` to continue from meant a plain download
  onto an occupied path — and the finished transfer replaced whatever was there.
  Resume with nothing to resume now falls back to *keep both*, the same promise
  the default rule makes. The upload side had the identical bug and the same fix.
- **A delete could land in the wrong directory.** Deletion resolved bare
  filenames against the *current* remote directory, so a delete queued behind a
  long transfer — or one waiting under its confirmation dialog — would erase a
  same-named file in whatever folder you had browsed to in the meantime.
  Deletion is now path-based end to end.
- **Interrupted uploads left a truncated file at the real filename**, looking on
  the server exactly like a finished one. Uploads are now staged on a
  `.charon-part` name and renamed into place only after the size is confirmed,
  matching what downloads already did. A failed upload cleans up after itself.
- **On Windows, every binary download and the vault itself were corrupted.**
  Descriptors were opened without `O_BINARY`, so Windows ran them in text mode
  and rewrote every `0x0A` byte as `0x0D 0x0A`. Any non-text download arrived
  damaged, and the vault's ciphertext was mangled badly enough to break its GCM
  tag. Present in the v1.0.0 artifacts; fixed here, with a regression test that
  asserts the vault file is never longer than the bytes written to it.

### Fixed — other

- Cut/paste checked *every* job the engine had ever run before completing a
  move, so a single unrelated failure earlier in the session blocked every later
  move permanently. Batches are now tracked by job id.
- Cut/paste from local to remote never removed the local originals — a "move"
  quietly behaved as a copy. Both directions now complete properly.
- A batch of downloads rescanned the local directory once per completed file.
  Rescans are coalesced.
- Theme changes no longer ask for a restart; icons, the security badge and the
  progress bars all re-tint live.

### Added

- **Trust-store manager** — review every pinned host key and TLS certificate
  with its fingerprint, and revoke one after a genuine server rebuild. A
  trust-on-first-use store you cannot inspect is a liability.
- **Filter as you type** in either pane (`Ctrl+F`, `Esc` to clear), applied to
  the listing already in memory so it costs no network round trip.
- **Retry failed transfers**, from the queue's toolbar or its context menu.
  Retries resume rather than restart.
- Queue context menu: show a finished download in the file manager, stop a
  running transfer, copy an error message.
- Free space on the local disk, shown in the pane header.

### Tests

155 (up from 132), including regressions for all six defects above.

---

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
