"""The trust-store manager: listing pinned identities and revoking them.

The fiddly part is turning a stored key back into the host and port it belongs
to.  SSH host specs and TLS pin keys use different encodings, and getting it
wrong means the "stop trusting" button silently revokes nothing — leaving the
user believing they removed a key that is still pinned.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from charon.core.trust import CertPinStore, HostKeyStore, TrustDecision  # noqa: E402
from charon.ui.dialogs import TrustStoreDialog, _split_hostspec  # noqa: E402
from charon.ui.theme import palette  # noqa: E402

KEY = b"\x00\x00\x00\x0bssh-ed25519" + b"\xaa" * 32
CERT = b"\x30\x82der-certificate"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def stores(tmp_path):
    return (HostKeyStore(path=tmp_path / "known_hosts"),
            CertPinStore(path=tmp_path / "pins.json"))


@pytest.mark.parametrize("spec, default, expected", [
    ("nas.local", 22, ("nas.local", 22)),                    # SSH, default port
    ("[nas.local]:2222", 22, ("nas.local", 2222)),           # SSH, custom port
    ("files.example.com:21", 21, ("files.example.com", 21)),  # TLS pin key
    ("[2001:db8::1]:2222", 22, ("2001:db8::1", 2222)),       # bracketed IPv6
    ("[nas.local]:notaport", 22, ("nas.local", 22)),         # junk falls back
])
def test_host_specs_round_trip(spec, default, expected):
    assert _split_hostspec(spec, default) == expected


def test_an_empty_store_shows_the_explanatory_note(app, stores):
    dialog = TrustStoreDialog(*stores, palette("dark"))
    assert dialog.tree.topLevelItemCount() == 0
    assert dialog.empty_note.isVisible() or not dialog.tree.isVisible()


def test_pinned_identities_are_listed_with_their_fingerprints(app, stores):
    hostkeys, pins = stores
    hostkeys.trust("nas.local", 22, "ssh-ed25519", KEY)
    pins.trust("files.example.com", 21, CERT)

    dialog = TrustStoreDialog(hostkeys, pins, palette("dark"))

    assert dialog.tree.topLevelItemCount() == 2
    rows = {dialog.tree.topLevelItem(i).text(0): dialog.tree.topLevelItem(i)
            for i in range(2)}
    assert rows["nas.local"].text(1) == "ssh-ed25519"
    assert rows["nas.local"].text(2).startswith("SHA256:")
    assert rows["files.example.com:21"].text(1) == "TLS certificate"


def test_revoking_an_ssh_key_actually_unpins_it(app, stores, monkeypatch):
    hostkeys, pins = stores
    hostkeys.trust("build.example.com", 2222, "ssh-ed25519", KEY)
    dialog = TrustStoreDialog(hostkeys, pins, palette("dark"))
    dialog.tree.setCurrentItem(dialog.tree.topLevelItem(0))

    _confirm(monkeypatch)
    dialog._forget()

    assert hostkeys.check("build.example.com", 2222, "ssh-ed25519", KEY) \
        is TrustDecision.UNKNOWN
    assert dialog.tree.topLevelItemCount() == 0


def test_revoking_a_tls_pin_actually_unpins_it(app, stores, monkeypatch):
    hostkeys, pins = stores
    pins.trust("files.example.com", 21, CERT)
    dialog = TrustStoreDialog(hostkeys, pins, palette("dark"))
    dialog.tree.setCurrentItem(dialog.tree.topLevelItem(0))

    _confirm(monkeypatch)
    dialog._forget()

    assert pins.check("files.example.com", 21, CERT) is TrustDecision.UNKNOWN


def test_declining_the_confirmation_keeps_the_pin(app, stores, monkeypatch):
    """Cancel must mean cancel: this dialog removes a security control."""
    hostkeys, pins = stores
    hostkeys.trust("nas.local", 22, "ssh-ed25519", KEY)
    dialog = TrustStoreDialog(hostkeys, pins, palette("dark"))
    dialog.tree.setCurrentItem(dialog.tree.topLevelItem(0))

    _confirm(monkeypatch, accept=False)
    dialog._forget()

    assert hostkeys.check("nas.local", 22, "ssh-ed25519", KEY) is TrustDecision.KNOWN


def test_an_unreadable_key_does_not_break_the_listing(app, stores):
    """A hand-edited known_hosts must not take the whole dialog down."""
    hostkeys, pins = stores
    hostkeys.path.write_text("nas.local ssh-ed25519 !!!not-base64!!!\n")

    dialog = TrustStoreDialog(hostkeys, pins, palette("dark"))

    assert dialog.tree.topLevelItemCount() == 1
    assert dialog.tree.topLevelItem(0).text(2) == "(unreadable)"


def _confirm(monkeypatch, accept: bool = True) -> None:
    from PyQt6.QtWidgets import QMessageBox

    answer = (QMessageBox.StandardButton.Yes if accept
              else QMessageBox.StandardButton.Cancel)
    monkeypatch.setattr(QMessageBox, "exec", lambda self: answer)
