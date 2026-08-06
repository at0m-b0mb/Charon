"""Parsing FTP's human-readable directory listings.

``LIST`` output is whatever the server's ``ls`` prints, which is why MLSD exists
and why Charon prefers it.  These cover the two families that make up almost
everything in the wild, plus the failure mode that matters: an unparseable line
must degrade to a name, never to a wrong size or a wrong type.
"""

from __future__ import annotations

import pytest

from charon.core.ftp import _mlsd_time, _parse_list_line


def test_unix_file():
    entry = _parse_list_line(
        "-rw-r--r--   1 kai  staff   10485760 Mar  3 14:22 backup.tar.gz")
    assert entry.name == "backup.tar.gz"
    assert entry.size == 10_485_760
    assert not entry.is_dir
    assert entry.owner == "kai"


def test_unix_directory():
    entry = _parse_list_line("drwxr-xr-x   4 kai  staff   128 Jan 12  2024 archive")
    assert entry.name == "archive"
    assert entry.is_dir


def test_unix_symlink_drops_the_arrow_target():
    entry = _parse_list_line(
        "lrwxrwxrwx   1 root root   11 Feb  2 09:00 latest -> backup.tar.gz")
    assert entry.name == "latest"
    assert entry.is_symlink


def test_names_containing_spaces_survive():
    entry = _parse_list_line(
        "-rw-r--r--   1 kai  staff   2048 Mar  3 14:22 quarterly report final.pdf")
    assert entry.name == "quarterly report final.pdf"


def test_extended_attribute_marker_is_tolerated():
    entry = _parse_list_line(
        "-rw-r--r--@  1 kai  staff   512 Mar  3 14:22 tagged.txt")
    assert entry is not None and entry.name == "tagged.txt"


def test_windows_directory():
    entry = _parse_list_line("03-14-24  09:12AM       <DIR>          uploads")
    assert entry.name == "uploads"
    assert entry.is_dir
    assert entry.size == 0


def test_windows_file():
    entry = _parse_list_line("03-14-24  09:12AM              1048576 image.iso")
    assert entry.name == "image.iso"
    assert entry.size == 1_048_576
    assert not entry.is_dir


def test_an_unparseable_line_degrades_to_a_bare_name():
    """Better to show a file with no size than to invent one."""
    entry = _parse_list_line("some totally unexpected format mystery.bin")
    assert entry.name == "mystery.bin"
    assert entry.size == 0
    assert not entry.is_dir


def test_blank_lines_are_dropped():
    assert _parse_list_line("") is None
    assert _parse_list_line("   \r\n") is None


def test_mlsd_timestamps_are_utc():
    assert _mlsd_time("20240314091200") == pytest.approx(1_710_407_520, abs=1)
    assert _mlsd_time("20240314091200.123") == pytest.approx(1_710_407_520, abs=1)


def test_a_broken_mlsd_timestamp_is_zero_not_an_exception():
    assert _mlsd_time("not-a-date") == 0.0
    assert _mlsd_time("") == 0.0
