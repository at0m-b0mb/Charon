"""Path-safety tests — the ones that matter most.

Every case here is a real filename a hostile server can put in a directory
listing.  If any of these ever start passing through unchanged, Charon writes
files outside the folder the user chose.
"""

from __future__ import annotations

import pytest

from charon.core.safety import (
    UnsafeNameError,
    normalise_remote,
    remote_join,
    resolve_within,
    safe_local_name,
)


@pytest.mark.parametrize("hostile, expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\Windows\\System32\\evil.dll", "evil.dll"),
    ("/etc/shadow", "shadow"),
    ("C:\\boot.ini", "boot.ini"),   # the drive goes with the rest of the path
    ("sub/dir/file.txt", "file.txt"),
    ("normal.txt", "normal.txt"),
])
def test_directory_components_are_stripped(hostile, expected):
    assert safe_local_name(hostile) == expected


@pytest.mark.parametrize("hostile", ["..", ".", "", "   ", "...", "/", "//"])
def test_names_with_nothing_safe_left_are_rejected(hostile):
    with pytest.raises(UnsafeNameError):
        safe_local_name(hostile)


def test_control_characters_and_nul_are_replaced():
    assert safe_local_name("re\x00port\n.txt") == "re_port_.txt"


def test_windows_reserved_names_are_defused():
    # "CON" on Windows is a device, not a file; creating it does not do what
    # the user thinks.  Prefixed on every platform so behaviour is identical.
    assert safe_local_name("CON") == "_CON"
    assert safe_local_name("lpt1.txt") == "_lpt1.txt"
    assert safe_local_name("console.txt") == "console.txt"  # not reserved


def test_trailing_dots_and_spaces_are_dropped():
    # Windows silently strips these, which would let "evil.exe." collide with
    # an existing "evil.exe".
    assert safe_local_name("evil.exe. ") == "evil.exe"


def test_long_names_are_truncated_but_keep_their_extension():
    name = "a" * 400 + ".tar.gz"
    result = safe_local_name(name)
    assert len(result.encode()) <= 255
    assert result.endswith(".gz")


def test_unicode_is_normalised_before_inspection():
    # NFD "..": a decomposed form must not sneak past the ".." check.
    assert safe_local_name("\u002e\u002e/x") == "x"


def test_resolve_within_keeps_paths_inside_the_destination(tmp_path):
    result = resolve_within(tmp_path, "reports", "q3.pdf")
    assert result == (tmp_path / "reports" / "q3.pdf").resolve()
    assert tmp_path.resolve() in result.parents


def test_resolve_within_refuses_a_symlink_that_points_outside(tmp_path):
    outside = tmp_path.parent / "outside-charon-test"
    outside.mkdir(exist_ok=True)
    inside = tmp_path / "downloads"
    inside.mkdir()
    (inside / "escape").symlink_to(outside, target_is_directory=True)

    # An attacker cannot create this link, but one already on disk must not
    # become a write primitive either.
    with pytest.raises(UnsafeNameError):
        resolve_within(inside, "escape", "payload.sh")


@pytest.mark.parametrize("raw, expected", [
    ("/var/www", "/var/www"),
    ("var/www", "/var/www"),
    ("/var/../..", "/"),
    ("/var/./www/", "/var/www"),
    ("//srv//data", "/srv/data"),
    ("", "/"),
])
def test_remote_paths_never_climb_above_root(raw, expected):
    assert normalise_remote(raw) == expected


def test_remote_join_cannot_walk_out_of_the_current_directory():
    assert remote_join("/home/kai", "notes.txt") == "/home/kai/notes.txt"
    assert remote_join("/home/kai", "../../etc/passwd") == "/home/kai/passwd"
    with pytest.raises(UnsafeNameError):
        remote_join("/home/kai", "..")
