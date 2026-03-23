"""Tests for the filesystem analyzer (bodyfile parsing and mode strings)."""

import stat

import pytest

from lft.analyzers.filesystem import BodyfileEntry, stat_to_mode_string


# ============================================================================
# TestBodyfileEntry — constructor defaults and to_bodyfile_line
# ============================================================================

class TestBodyfileEntry:
    """Test BodyfileEntry constructor defaults and serialization."""

    def test_defaults(self):
        entry = BodyfileEntry()
        assert entry.md5 == "0"
        assert entry.name == ""
        assert entry.inode == 0
        assert entry.mode_str == "----------"
        assert entry.uid == 0
        assert entry.gid == 0
        assert entry.size == 0
        assert entry.atime == 0
        assert entry.mtime == 0
        assert entry.ctime == 0
        assert entry.crtime == 0

    def test_custom_values(self):
        entry = BodyfileEntry(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            name="/etc/passwd",
            inode=12345,
            mode_str="-rwxr-xr-x",
            uid=1000,
            gid=1000,
            size=2048,
            atime=1705312800,
            mtime=1705312900,
            ctime=1705313000,
            crtime=1705310000,
        )
        assert entry.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert entry.name == "/etc/passwd"
        assert entry.inode == 12345
        assert entry.uid == 1000
        assert entry.size == 2048

    def test_to_bodyfile_line_defaults(self):
        entry = BodyfileEntry()
        line = entry.to_bodyfile_line()
        assert line == "0||0|----------|0|0|0|0|0|0|0"

    def test_to_bodyfile_line_format(self):
        entry = BodyfileEntry(
            md5="0",
            name="/etc/passwd",
            inode=12345,
            mode_str="-rwxr-xr-x",
            uid=0,
            gid=0,
            size=1024,
            atime=1705312800,
            mtime=1705312800,
            ctime=1705312800,
            crtime=0,
        )
        line = entry.to_bodyfile_line()
        assert line == "0|/etc/passwd|12345|-rwxr-xr-x|0|0|1024|1705312800|1705312800|1705312800|0"

    def test_to_bodyfile_line_has_eleven_fields(self):
        entry = BodyfileEntry(name="/bin/sh")
        parts = entry.to_bodyfile_line().split("|")
        assert len(parts) == 11


# ============================================================================
# TestFromBodyfileLine — parsing
# ============================================================================

class TestFromBodyfileLine:
    """Test BodyfileEntry.from_bodyfile_line static method."""

    def test_valid_line(self):
        line = "0|/etc/passwd|12345|-rwxr-xr-x|0|0|1024|1705312800|1705312800|1705312800|0"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.md5 == "0"
        assert entry.name == "/etc/passwd"
        assert entry.inode == 12345
        assert entry.mode_str == "-rwxr-xr-x"
        assert entry.uid == 0
        assert entry.gid == 0
        assert entry.size == 1024
        assert entry.atime == 1705312800
        assert entry.mtime == 1705312800
        assert entry.ctime == 1705312800
        assert entry.crtime == 0

    def test_short_line_returns_none(self):
        line = "0|/etc/passwd|12345"
        result = BodyfileEntry.from_bodyfile_line(line)
        assert result is None

    def test_empty_line_returns_none(self):
        result = BodyfileEntry.from_bodyfile_line("")
        assert result is None

    def test_ten_fields_returns_none(self):
        line = "0|/etc/passwd|12345|-rwxr-xr-x|0|0|1024|100|200|300"
        result = BodyfileEntry.from_bodyfile_line(line)
        assert result is None

    def test_non_numeric_inode_defaults_to_zero(self):
        line = "0|/tmp/test|abc|-rw-r--r--|0|0|512|100|200|300|0"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.inode == 0

    def test_non_numeric_uid_defaults_to_zero(self):
        line = "0|/tmp/test|100|-rw-r--r--|root|wheel|512|100|200|300|0"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.uid == 0
        assert entry.gid == 0

    def test_non_numeric_size_defaults_to_zero(self):
        line = "0|/tmp/test|100|-rw-r--r--|0|0|big|100|200|300|0"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.size == 0

    def test_non_numeric_timestamps_default_to_zero(self):
        line = "0|/tmp/test|100|-rw-r--r--|0|0|512|abc|def|ghi|jkl"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.atime == 0
        assert entry.mtime == 0
        assert entry.ctime == 0
        assert entry.crtime == 0

    def test_negative_timestamps_parsed(self):
        line = "0|/tmp/test|100|-rw-r--r--|0|0|512|-100|-200|-300|-400"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.atime == -100
        assert entry.mtime == -200
        assert entry.ctime == -300
        assert entry.crtime == -400

    def test_trailing_whitespace_stripped(self):
        line = "0|/etc/hosts|99|-rw-r--r--|0|0|256|100|200|300|0\n"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.crtime == 0

    def test_extra_fields_ignored(self):
        line = "0|/tmp/test|100|-rw-r--r--|0|0|512|100|200|300|0|extra|fields"
        entry = BodyfileEntry.from_bodyfile_line(line)
        assert entry is not None
        assert entry.name == "/tmp/test"


# ============================================================================
# TestBodyfileRoundtrip — serialize then parse and verify
# ============================================================================

class TestBodyfileRoundtrip:
    """Test that to_bodyfile_line -> from_bodyfile_line preserves all fields."""

    def test_roundtrip_defaults(self):
        original = BodyfileEntry()
        line = original.to_bodyfile_line()
        parsed = BodyfileEntry.from_bodyfile_line(line)
        assert parsed is not None
        assert parsed.md5 == original.md5
        assert parsed.name == original.name
        assert parsed.inode == original.inode
        assert parsed.mode_str == original.mode_str
        assert parsed.uid == original.uid
        assert parsed.gid == original.gid
        assert parsed.size == original.size
        assert parsed.atime == original.atime
        assert parsed.mtime == original.mtime
        assert parsed.ctime == original.ctime
        assert parsed.crtime == original.crtime

    def test_roundtrip_custom(self):
        original = BodyfileEntry(
            md5="abc123",
            name="/var/log/syslog",
            inode=98765,
            mode_str="-rw-------",
            uid=0,
            gid=4,
            size=1048576,
            atime=1700000000,
            mtime=1700000100,
            ctime=1700000200,
            crtime=1699999000,
        )
        line = original.to_bodyfile_line()
        parsed = BodyfileEntry.from_bodyfile_line(line)
        assert parsed is not None
        assert parsed.md5 == original.md5
        assert parsed.name == original.name
        assert parsed.inode == original.inode
        assert parsed.mode_str == original.mode_str
        assert parsed.uid == original.uid
        assert parsed.gid == original.gid
        assert parsed.size == original.size
        assert parsed.atime == original.atime
        assert parsed.mtime == original.mtime
        assert parsed.ctime == original.ctime
        assert parsed.crtime == original.crtime

    def test_roundtrip_path_with_spaces(self):
        original = BodyfileEntry(name="/home/user/my documents/file.txt")
        parsed = BodyfileEntry.from_bodyfile_line(original.to_bodyfile_line())
        assert parsed is not None
        assert parsed.name == original.name


# ============================================================================
# TestStatToModeString — os.stat mode integer to ls-style string
# ============================================================================

class TestStatToModeString:
    """Test stat_to_mode_string conversion."""

    def test_regular_file_644(self):
        # -rw-r--r--
        result = stat_to_mode_string(0o100644)
        assert result == "-rw-r--r--"

    def test_directory_755(self):
        # drwxr-xr-x
        result = stat_to_mode_string(0o040755)
        assert result == "drwxr-xr-x"

    def test_suid_file(self):
        # -rwsr-xr-x  (SUID set, owner execute set)
        result = stat_to_mode_string(0o104755)
        assert result == "-rwsr-xr-x"

    def test_suid_no_execute(self):
        # -rwSr-xr-x  (SUID set, owner execute NOT set)
        result = stat_to_mode_string(0o104655)
        assert result == "-rwSr-xr-x"

    def test_sgid_file(self):
        # -rwxr-sr-x  (SGID set, group execute set)
        result = stat_to_mode_string(0o102755)
        assert result == "-rwxr-sr-x"

    def test_sgid_no_execute(self):
        # -rwxr-Sr-x  (SGID set, group execute NOT set)
        result = stat_to_mode_string(0o102745)
        assert result == "-rwxr-Sr-x"

    def test_sticky_bit(self):
        # drwxrwxrwt  (sticky set, other execute set)
        result = stat_to_mode_string(0o041777)
        assert result == "drwxrwxrwt"

    def test_sticky_no_execute(self):
        # drwxrwxrwT  (sticky set, other execute NOT set)
        result = stat_to_mode_string(0o041776)
        assert result == "drwxrwxrwT"

    def test_regular_file_755(self):
        # -rwxr-xr-x
        result = stat_to_mode_string(0o100755)
        assert result == "-rwxr-xr-x"

    def test_regular_file_600(self):
        # -rw-------
        result = stat_to_mode_string(0o100600)
        assert result == "-rw-------"

    def test_symlink(self):
        # lrwxrwxrwx
        result = stat_to_mode_string(0o120777)
        assert result == "lrwxrwxrwx"

    def test_fifo(self):
        # prw-r--r--
        result = stat_to_mode_string(0o010644)
        assert result == "prw-r--r--"

    def test_socket(self):
        # srwxrwxrwx
        result = stat_to_mode_string(0o140777)
        assert result == "srwxrwxrwx"

    def test_no_permissions(self):
        # ----------
        result = stat_to_mode_string(0o100000)
        assert result == "----------"
