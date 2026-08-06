"""Host-key and certificate pinning: the "is this really my server?" logic."""

from __future__ import annotations

import pytest

from charon.core.trust import (
    CertPinStore,
    HostKeyStore,
    TrustDecision,
    md5_fingerprint,
    sha256_fingerprint,
)

KEY_A = b"\x00\x00\x00\x0bssh-ed25519" + b"\xaa" * 32
KEY_B = b"\x00\x00\x00\x0bssh-ed25519" + b"\xbb" * 32


@pytest.fixture
def store(tmp_path):
    return HostKeyStore(path=tmp_path / "known_hosts")


def test_a_new_host_is_unknown_not_trusted(store):
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_A) is TrustDecision.UNKNOWN


def test_a_pinned_host_is_recognised(store):
    store.trust("nas.local", 22, "ssh-ed25519", KEY_A)
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_A) is TrustDecision.KNOWN


def test_a_swapped_key_is_reported_as_changed(store):
    """The interception case.  This must never come back as UNKNOWN, or the UI
    would show a calm first-contact prompt for an active attack."""
    store.trust("nas.local", 22, "ssh-ed25519", KEY_A)
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_B) is TrustDecision.CHANGED


def test_a_different_port_is_a_different_host(store):
    store.trust("nas.local", 22, "ssh-ed25519", KEY_A)
    assert store.check("nas.local", 2222, "ssh-ed25519", KEY_A) is TrustDecision.UNKNOWN


def test_a_second_key_algorithm_is_tofu_not_a_key_change(store):
    """Servers commonly add an ed25519 key beside an old RSA one; that is not
    an attack and must not be reported as one."""
    store.trust("nas.local", 22, "ssh-rsa", KEY_A)
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_B) is TrustDecision.UNKNOWN


def test_trusting_twice_does_not_duplicate_the_entry(store):
    store.trust("nas.local", 22, "ssh-ed25519", KEY_A)
    store.trust("nas.local", 22, "ssh-ed25519", KEY_B)
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_B) is TrustDecision.KNOWN
    assert len(store.pinned_for("nas.local", 22)) == 1


def test_forget_removes_the_pin(store):
    store.trust("nas.local", 22, "ssh-ed25519", KEY_A)
    assert store.forget("nas.local", 22) == 1
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_A) is TrustDecision.UNKNOWN


def test_the_file_is_openssh_compatible(store):
    store.trust("nas.local", 22, "ssh-ed25519", KEY_A)
    store.trust("nas.local", 2222, "ssh-ed25519", KEY_B)
    lines = store.path.read_text().splitlines()
    assert lines[0].startswith("nas.local ssh-ed25519 ")      # default port: bare
    assert lines[1].startswith("[nas.local]:2222 ssh-ed25519 ")  # non-default: bracketed


def test_comments_and_junk_lines_are_ignored(store):
    store.path.write_text("# a comment\n\nnot-enough-fields\n")
    assert store.check("nas.local", 22, "ssh-ed25519", KEY_A) is TrustDecision.UNKNOWN


def test_the_identity_carries_the_key_it_describes(store):
    identity = store.identity("nas.local", 22, "ssh-ed25519", KEY_A)
    # The GUI pins identity.blob after the user approves identity.fingerprint;
    # if these ever disagree the user approves one key and pins another.
    assert sha256_fingerprint(identity.blob) == identity.fingerprint


def test_fingerprint_format_matches_openssh():
    fp = sha256_fingerprint(KEY_A)
    assert fp.startswith("SHA256:") and not fp.endswith("=")
    assert md5_fingerprint(KEY_A).startswith("MD5:")
    assert md5_fingerprint(KEY_A).count(":") == 16


# ------------------------------------------------------------------ TLS pins

CERT_A = b"\x30\x82fake-der-certificate-a"
CERT_B = b"\x30\x82fake-der-certificate-b"


def test_certificate_pinning_round_trip(tmp_path):
    pins = CertPinStore(path=tmp_path / "pins.json")
    assert pins.check("nas.local", 21, CERT_A) is TrustDecision.UNKNOWN
    pins.trust("nas.local", 21, CERT_A)
    assert pins.check("nas.local", 21, CERT_A) is TrustDecision.KNOWN
    assert pins.check("nas.local", 21, CERT_B) is TrustDecision.CHANGED
    assert pins.forget("nas.local", 21) is True
    assert pins.check("nas.local", 21, CERT_A) is TrustDecision.UNKNOWN


def test_a_corrupt_pin_file_fails_closed(tmp_path):
    """Unreadable trust data must mean "nothing is trusted", never "everything
    is"."""
    path = tmp_path / "pins.json"
    path.write_text("{not json at all")
    pins = CertPinStore(path=path)
    assert pins.check("nas.local", 21, CERT_A) is TrustDecision.UNKNOWN
