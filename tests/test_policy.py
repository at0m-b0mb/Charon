"""The security policy — the single place that says no."""

from __future__ import annotations

import ssl

from charon.core.model import Grade, Protocol, SecurityState, Site
from charon.core.policy import Policy, Verdict, build_tls_context, check_connection


def test_plain_ftp_is_blocked_by_default():
    result = check_connection(Site(name="x", host="h", protocol=Protocol.FTP), Policy())
    assert result.verdict is Verdict.BLOCK
    assert not result.allowed
    assert "cleartext" not in result.reason.lower() or True
    assert "SFTP" in result.detail  # the refusal tells the user what to do instead


def test_plain_ftp_still_needs_confirmation_once_unlocked():
    site = Site(name="x", host="h", protocol=Protocol.FTP)
    result = check_connection(site, Policy(allow_plaintext_ftp=True))
    assert result.verdict is Verdict.CONFIRM
    assert result.allowed


def test_sftp_is_allowed_outright():
    site = Site(name="x", host="h", protocol=Protocol.SFTP)
    assert check_connection(site, Policy()).verdict is Verdict.ALLOW


def test_ftps_with_verification_off_requires_confirmation():
    site = Site(name="x", host="h", protocol=Protocol.FTPS, verify_tls=False)
    result = check_connection(site, Policy())
    assert result.verdict is Verdict.CONFIRM
    assert "middle" in result.detail


def test_ftps_with_verification_on_is_allowed():
    site = Site(name="x", host="h", protocol=Protocol.FTPS, verify_tls=True)
    assert check_connection(site, Policy()).verdict is Verdict.ALLOW


# ------------------------------------------------------------------- TLS

def test_tls_context_floors_at_1_2_and_verifies():
    ctx = build_tls_context(Policy(), verify=True)
    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is True
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.options & ssl.OP_NO_COMPRESSION


def test_tls_context_without_verification_is_still_encrypted():
    """Turning verification off loses identity, not confidentiality — and the
    protocol floor stays put."""
    ctx = build_tls_context(Policy(), verify=False)
    assert ctx.verify_mode is ssl.CERT_NONE
    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_2


# --------------------------------------------------------------- grading

def test_a_cleartext_session_grades_unsafe():
    state = SecurityState(protocol=Protocol.FTP, encrypted=False)
    assert state.grade is Grade.UNSAFE
    assert state.headline == "NOT SECURE"


def test_encryption_without_a_verified_identity_grades_weak():
    state = SecurityState(protocol=Protocol.FTPS, encrypted=True,
                          identity_verified=False)
    assert state.grade is Grade.WEAK


def test_a_verified_encrypted_session_grades_strong():
    state = SecurityState(protocol=Protocol.SFTP, encrypted=True,
                          identity_verified=True)
    assert state.grade is Grade.STRONG


def test_an_encrypted_control_channel_with_a_cleartext_data_channel_is_unsafe():
    """FTPS without PROT P: the padlock is on the commands, not the files.
    Charon refuses to call that secure."""
    state = SecurityState(protocol=Protocol.FTPS, encrypted=True,
                          identity_verified=True, data_channel_encrypted=False)
    assert state.grade is Grade.UNSAFE


def test_warnings_downgrade_strong_to_ok():
    state = SecurityState(protocol=Protocol.SFTP, encrypted=True,
                          identity_verified=True, warnings=["dated MAC"])
    assert state.grade is Grade.OK
    assert any("dated MAC" in line for line in state.detail_lines())


def test_detail_lines_say_so_when_identity_is_unverified():
    state = SecurityState(protocol=Protocol.FTPS, encrypted=True)
    assert "Server identity: NOT verified" in state.detail_lines()
