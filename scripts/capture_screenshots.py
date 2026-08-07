#!/usr/bin/env python3
"""Render Charon's real widgets to PNGs for the README and the release.

Runs headless (``QT_QPA_PLATFORM=offscreen``) and drives the actual UI classes
with plausible data — not mock-ups.  If a pane or a dialog is broken, this
script produces a broken picture, which is the point: the screenshots in the
README cannot drift away from what the program looks like.

    .venv/bin/python scripts/capture_screenshots.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("CHARON_HOME", "/tmp/charon-screenshots")

from PyQt6.QtCore import QSize  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from charon.core.clipboard import ClipItem, Operation, Side  # noqa: E402
from charon.core.model import (  # noqa: E402
    AuthMethod, Protocol, RemoteEntry, SecurityState, Site,
)
from charon.core.store import Settings, SiteStore  # noqa: E402
from charon.core.transfer import Direction, JobState, TransferJob  # noqa: E402
from charon.core.trust import HostKeyStore  # noqa: E402
from charon.ui.dialogs import (  # noqa: E402
    ConnectDialog, InsecureConnectionDialog, PasteDialog, SettingsDialog, TrustDialog,
    TrustStoreDialog,
)
from charon.ui.main_window import MainWindow  # noqa: E402
from charon.ui.theme import palette  # noqa: E402

OUT = ROOT / "assets" / "screenshots"

REMOTE_LISTING = [
    RemoteEntry("archive", 0, 1_707_000_000, is_dir=True, mode="drwxr-xr-x", owner="kai"),
    RemoteEntry("configs", 0, 1_709_200_000, is_dir=True, mode="drwx------", owner="kai"),
    RemoteEntry("incoming", 0, 1_710_400_000, is_dir=True, mode="drwxrwxr-x", owner="kai"),
    RemoteEntry("latest", 0, 1_710_500_000, is_symlink=True, mode="lrwxrwxrwx", owner="kai"),
    RemoteEntry("db-backup-2026-08-05.sql.gz", 1_476_395_008, 1_754_300_000,
                mode="-rw-r-----", owner="postgres"),
    RemoteEntry("nginx-access.log", 284_016_640, 1_754_380_000, mode="-rw-r--r--", owner="www"),
    RemoteEntry("quarterly-report.pdf", 4_718_592, 1_753_900_000, mode="-rw-r--r--", owner="kai"),
    RemoteEntry("site-bundle.tar.zst", 96_468_992, 1_754_100_000, mode="-rw-r--r--", owner="kai"),
    RemoteEntry("deploy.sh", 3_412, 1_754_200_000, mode="-rwxr-xr-x", owner="kai"),
    RemoteEntry("README.md", 8_190, 1_752_000_000, mode="-rw-r--r--", owner="kai"),
]

LOCAL_LISTING = [
    RemoteEntry("Projects", 0, 1_753_000_000, is_dir=True, mode="drwxr-xr-x"),
    RemoteEntry("Screenshots", 0, 1_754_100_000, is_dir=True, mode="drwxr-xr-x"),
    RemoteEntry("quarterly-report.pdf", 4_718_592, 1_754_400_000, mode="-rw-------"),
    RemoteEntry("site-bundle.tar.zst", 96_468_992, 1_754_402_000, mode="-rw-------"),
    RemoteEntry("notes.md", 12_044, 1_754_390_000, mode="-rw-r--r--"),
]


def save(widget, name: str, size: QSize | None = None) -> None:
    if size is not None:
        widget.resize(size)
    widget.show()
    app = QApplication.instance()
    for _ in range(4):
        app.processEvents()
        time.sleep(0.02)
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    widget.grab().save(str(path))
    print(f"  {path.relative_to(ROOT)}  ({widget.width()}x{widget.height()})")
    widget.hide()


def secure_state() -> SecurityState:
    return SecurityState(
        protocol=Protocol.SFTP,
        encrypted=True,
        cipher="aes256-gcm@openssh.com",
        kex="curve25519-sha256@libssh.org",
        mac="implicit (AEAD)",
        host_key_type="ssh-ed25519",
        fingerprint="SHA256:kQ8vT2mXbN4pR7wZ1cF6hJ3sL9yA0dG5uE2nO8iV4rM",
        identity_verified=True,
        verified_how="host key matches your pinned copy",
    )


def demo_jobs() -> list[TransferJob]:
    jobs = [
        TransferJob(Direction.DOWNLOAD, "/srv/data/site-bundle.tar.zst",
                    Path("/Users/kai/Downloads/site-bundle.tar.zst"),
                    size=96_468_992, id=1),
        TransferJob(Direction.DOWNLOAD, "/srv/data/db-backup-2026-08-05.sql.gz",
                    Path("/Users/kai/Downloads/db-backup-2026-08-05.sql.gz"),
                    size=1_476_395_008, id=2),
        TransferJob(Direction.DOWNLOAD, "/srv/data/quarterly-report.pdf",
                    Path("/Users/kai/Downloads/quarterly-report.pdf"),
                    size=4_718_592, id=3),
        TransferJob(Direction.UPLOAD, "/srv/data/incoming/notes.md",
                    Path("/Users/kai/Downloads/notes.md"), size=12_044, id=4),
        TransferJob(Direction.DOWNLOAD, "/srv/data/nginx-access.log",
                    Path("/Users/kai/Downloads/nginx-access.log"),
                    size=284_016_640, id=5),
    ]
    now = time.time()
    jobs[0].state = JobState.RUNNING
    jobs[0].transferred = 61_000_000
    jobs[0].started_at = now - 6.4

    jobs[1].state = JobState.QUEUED

    jobs[2].state = JobState.DONE
    jobs[2].transferred = jobs[2].size
    jobs[2].started_at, jobs[2].finished_at = now - 3.1, now - 0.9
    jobs[2].integrity = "SHA-256 verified (9f2a41c8bd7e05a3…)"

    jobs[3].state = JobState.DONE
    jobs[3].transferred = jobs[3].size
    jobs[3].started_at, jobs[3].finished_at = now - 1.2, now - 1.0
    jobs[3].integrity = "sent 12,044 bytes; SHA-256 4c11e7ab90d3f682…"

    jobs[4].state = JobState.FAILED
    jobs[4].error = "Permission denied: /srv/data/nginx-access.log"
    return jobs


def main() -> int:
    app = QApplication(sys.argv[:1])
    app.setApplicationName("Charon")
    p = palette("dark")

    print("Rendering Charon screenshots…")

    # ---- main window ----------------------------------------------------
    window = MainWindow()
    window.resize(1360, 860)
    window.badge.set_state(secure_state())
    window.setWindowTitle("Charon — sftp://kai@files.example.com:22")
    window.remote_pane.show_entries("/srv/data", REMOTE_LISTING, False)
    window.local_pane.show_entries("/Users/kai/Downloads", LOCAL_LISTING, False)
    window.act_download.setEnabled(True)
    window.act_upload.setEnabled(True)
    window.act_disconnect.setEnabled(True)

    jobs = demo_jobs()
    for job in jobs:
        window.queue.upsert(job)
    window.queue.summarise(jobs)
    window.clipboard.set(
        [ClipItem(Side.REMOTE, "/srv/data/site-bundle.tar.zst",
                  "site-bundle.tar.zst", False, 96_468_992)],
        Operation.COPY, session_id="s1", session_label="files.example.com")
    window._update_clip_label()
    window.set_status("Copied “site-bundle.tar.zst” — paste into this device to transfer")

    # Select a couple of rows so the copy/paste story is visible.
    for row in (3, 7):
        item = window.remote_pane.tree.topLevelItem(row)
        if item is not None:
            item.setSelected(True)
    save(window, "main.png")

    # ---- the same window, plaintext FTP ---------------------------------
    window.badge.set_state(SecurityState(protocol=Protocol.FTP, encrypted=False,
                                         data_channel_encrypted=False))
    window.banner.setText(
        "UNENCRYPTED SESSION — your password and every file in this session "
        "cross the network in readable text.")
    window.banner.setVisible(True)
    window.setWindowTitle("Charon — ftp://kai@legacy.example.net:21")
    save(window, "insecure-session.png")

    # ---- dialogs ---------------------------------------------------------
    settings = Settings.load()
    sites = SiteStore()
    for site in (
        Site(name="Production files", host="files.example.com", protocol=Protocol.SFTP,
             username="kai", auth=AuthMethod.KEY, key_path="~/.ssh/id_ed25519",
             last_used=time.time()),
        Site(name="Home NAS", host="nas.local", protocol=Protocol.FTPS, port=21,
             username="kai", last_used=time.time() - 8000),
        Site(name="Build box", host="build.internal", protocol=Protocol.SFTP,
             username="deploy", auth=AuthMethod.AGENT, last_used=time.time() - 90000),
    ):
        sites.add(site)
    connect = ConnectDialog(sites, settings, p)
    connect.host_edit.setText("files.example.com")
    save(connect, "connect.png", QSize(760, 560))

    store = HostKeyStore()
    identity = store.identity(
        "files.example.com", 22, "ssh-ed25519",
        bytes.fromhex("0000000b7373682d65643235353139000000200f3a") + b"\xa7" * 30)

    save(TrustDialog(identity, "host-key-new",
                     "Charon has never connected to files.example.com:22 before. Check "
                     "this fingerprint against the server itself before trusting it.", p),
         "trust-first-contact.png", QSize(640, 460))

    save(TrustDialog(identity, "host-key-changed",
                     "The SSH host key for files.example.com:22 has CHANGED since you "
                     "last connected. If the server was not rebuilt or re-keyed, someone "
                     "may be intercepting this connection.", p),
         "trust-key-changed.png", QSize(640, 470))

    save(InsecureConnectionDialog(
        Site(name="Legacy", host="legacy.example.net", protocol=Protocol.FTP),
        "This connection is not encrypted",
        "Your password and files will cross the network in readable form.", p),
        "insecure-warning.png", QSize(600, 340))

    save(PasteDialog(2, 101_187_584, "/Users/kai/Downloads", "Download", p),
         "paste.png", QSize(560, 360))

    save(SettingsDialog(settings, p), "settings.png", QSize(660, 480))

    # The trust store, populated with a plausible set of pinned identities.
    from charon.core.trust import CertPinStore

    demo_keys = HostKeyStore(path=Path(tempfile.mkdtemp()) / "known_hosts")
    demo_pins = CertPinStore(path=Path(tempfile.mkdtemp()) / "pins.json")
    demo_keys.trust("files.example.com", 22, "ssh-ed25519",
                    b"\x00\x00\x00\x0bssh-ed25519" + bytes(range(32)))
    demo_keys.trust("build.example.com", 2222, "ecdsa-sha2-nistp256",
                    b"\x00\x00\x00\x13ecdsa-sha2-nistp256" + bytes(range(64)))
    demo_pins.trust("nas.local", 21, b"\x30\x82" + bytes(range(48)))
    save(TrustStoreDialog(demo_keys, demo_pins, p), "trust-store.png", QSize(720, 420))

    window.thread.quit()
    window.thread.wait(2000)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
