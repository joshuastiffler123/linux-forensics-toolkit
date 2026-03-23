"""Tests for lft.analyzers.login_timeline module."""

import struct
from datetime import datetime

import pytest

from lft.analyzers.login_timeline import (
    TimelineEvent,
    is_valid_ip,
    is_valid_username,
    classify_username,
    parse_auth_log,
    parse_utmp_record,
    UTMP_STRUCT_SIZE,
    UTMP_STRUCT_FORMAT,
)


# ── sample auth.log data used by multiple tests ──────────────────────────

AUTH_LOG_DATA = (
    b"Jun  1 12:00:00 testhost sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2\n"
    b"Jun  1 12:01:00 testhost sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2\n"
    b"Jun  1 12:02:00 testhost sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update\n"
    b"Jun  1 12:03:00 testhost sshd[1236]: Accepted password for backdoor from 10.0.0.99 port 443 ssh2\n"
)


# ============================================================================
# TestTimelineEvent
# ============================================================================

class TestTimelineEvent:
    """Tests for the TimelineEvent data class."""

    def test_constructor_defaults(self):
        ts = datetime(2025, 6, 1, 12, 0, 0)
        event = TimelineEvent(
            timestamp=ts,
            event_type="SSH_LOGIN",
            source_file="/var/log/auth.log",
        )
        assert event.timestamp == ts
        assert event.event_type == "SSH_LOGIN"
        assert event.source_file == "/var/log/auth.log"
        assert event.username == ""
        assert event.source_ip == ""
        assert event.terminal == ""
        assert event.pid == 0
        assert event.description == ""
        assert event.raw_data == ""
        assert event.username_category == ""

    def test_constructor_all_fields(self):
        ts = datetime(2025, 6, 1, 12, 0, 0)
        event = TimelineEvent(
            timestamp=ts,
            event_type="SSH_LOGIN_PUBKEY",
            source_file="auth.log",
            username="root",
            source_ip="10.0.0.1",
            terminal="pts/0",
            pid=1234,
            description="Accepted publickey",
            raw_data="raw line here",
            username_category="user",
        )
        assert event.username == "root"
        assert event.source_ip == "10.0.0.1"
        assert event.terminal == "pts/0"
        assert event.pid == 1234
        assert event.description == "Accepted publickey"
        assert event.raw_data == "raw line here"
        assert event.username_category == "user"

    def test_to_dict_keys(self):
        ts = datetime(2025, 6, 1, 12, 0, 0)
        event = TimelineEvent(
            timestamp=ts,
            event_type="SSH_LOGIN",
            source_file="auth.log",
            username="root",
            source_ip="10.0.0.1",
            pid=42,
        )
        d = event.to_dict()
        expected_keys = {
            "Timestamp",
            "Timestamp_Local",
            "event_type",
            "username",
            "username_category",
            "source_ip",
            "terminal",
            "pid",
            "description",
            "source_file",
            "raw_data",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self):
        ts = datetime(2025, 6, 1, 12, 0, 0)
        event = TimelineEvent(
            timestamp=ts,
            event_type="SSH_LOGIN",
            source_file="auth.log",
            username="root",
            source_ip="10.0.0.1",
            pid=42,
        )
        d = event.to_dict()
        assert d["Timestamp"] == "2025-06-01 12:00:00"
        assert d["event_type"] == "SSH_LOGIN"
        assert d["username"] == "root"
        assert d["source_ip"] == "10.0.0.1"
        assert d["pid"] == "42"
        assert d["source_file"] == "auth.log"

    def test_to_dict_none_timestamp(self):
        event = TimelineEvent(
            timestamp=None,
            event_type="UNKNOWN",
            source_file="auth.log",
        )
        d = event.to_dict()
        assert d["Timestamp"] == ""
        assert d["Timestamp_Local"] == ""

    def test_to_dict_truncates_long_raw_data(self):
        long_raw = "x" * 600
        event = TimelineEvent(
            timestamp=datetime(2025, 1, 1),
            event_type="TEST",
            source_file="test",
            raw_data=long_raw,
        )
        d = event.to_dict()
        assert d["raw_data"].endswith("[TRUNCATED]")
        assert len(d["raw_data"]) < len(long_raw)

    def test_to_dict_no_truncation_short_raw(self):
        short_raw = "short line"
        event = TimelineEvent(
            timestamp=datetime(2025, 1, 1),
            event_type="TEST",
            source_file="test",
            raw_data=short_raw,
        )
        d = event.to_dict()
        assert d["raw_data"] == short_raw


# ============================================================================
# TestIsValidIp
# ============================================================================

class TestIsValidIp:
    """Tests for is_valid_ip()."""

    # ── valid IPv4 ──

    def test_valid_ipv4_private(self):
        assert is_valid_ip("10.0.0.1") is True

    def test_valid_ipv4_loopback(self):
        assert is_valid_ip("127.0.0.1") is True

    def test_valid_ipv4_broadcast(self):
        assert is_valid_ip("255.255.255.255") is True

    def test_valid_ipv4_class_c(self):
        assert is_valid_ip("192.168.1.100") is True

    def test_valid_ipv4_zeros(self):
        assert is_valid_ip("0.0.0.0") is True

    # ── invalid IPv4 ──

    def test_invalid_ipv4_octet_too_high(self):
        assert is_valid_ip("256.1.1.1") is False

    def test_invalid_ipv4_too_few_octets(self):
        assert is_valid_ip("10.0.1") is False

    def test_invalid_ipv4_too_many_octets(self):
        assert is_valid_ip("10.0.0.1.2") is False

    def test_invalid_ipv4_letters(self):
        assert is_valid_ip("10.0.0.abc") is False

    # ── invalid strings ──

    def test_empty_string(self):
        assert is_valid_ip("") is False

    def test_hostname(self):
        assert is_valid_ip("example.com") is False

    def test_short_string(self):
        assert is_valid_ip("1.1") is False

    def test_random_text(self):
        assert is_valid_ip("notanip") is False

    # ── IPv6 ──

    def test_valid_ipv6_full(self):
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_valid_ipv6_short(self):
        assert is_valid_ip("fe80::1") is True

    def test_invalid_ipv6_single_colon(self):
        # Must have at least 2 colons
        assert is_valid_ip("fe80:1") is False


# ============================================================================
# TestIsValidUsername
# ============================================================================

class TestIsValidUsername:
    """Tests for is_valid_username()."""

    # ── valid usernames ──

    def test_root(self):
        assert is_valid_username("root") is True

    def test_admin(self):
        assert is_valid_username("admin") is True

    def test_regular_user(self):
        assert is_valid_username("jsmith") is True

    def test_underscore_prefix(self):
        assert is_valid_username("_apt") is True

    def test_hyphenated(self):
        assert is_valid_username("www-data") is True

    def test_user_with_numbers(self):
        assert is_valid_username("user01") is True

    def test_nobody(self):
        assert is_valid_username("nobody") is True

    def test_syslog(self):
        assert is_valid_username("syslog") is True

    # ── invalid usernames ──

    def test_empty_string(self):
        assert is_valid_username("") is False

    def test_none(self):
        assert is_valid_username(None) is False

    def test_flag_short(self):
        assert is_valid_username("-o") is False

    def test_flag_long(self):
        assert is_valid_username("--help") is False

    def test_path(self):
        assert is_valid_username("/usr/bin/bash") is False

    def test_hex_string(self):
        assert is_valid_username("deadbeef") is False

    def test_long_hex_string(self):
        assert is_valid_username("a1b2c3d4e5f6") is False

    def test_contains_dot(self):
        assert is_valid_username("user.name") is False

    def test_contains_at(self):
        assert is_valid_username("user@host") is False

    def test_key_value(self):
        assert is_valid_username("key=value") is False

    def test_single_char(self):
        assert is_valid_username("a") is False

    def test_starts_with_digit(self):
        assert is_valid_username("1user") is False

    def test_too_long(self):
        assert is_valid_username("a" * 33) is False

    def test_all_uppercase_long(self):
        assert is_valid_username("ADMIN") is False

    def test_noise_word_session(self):
        assert is_valid_username("session") is False

    def test_noise_word_password(self):
        assert is_valid_username("password") is False

    def test_systemd_unit_pattern(self):
        assert is_valid_username("user-1000") is False

    def test_contains_backslash(self):
        assert is_valid_username("domain\\user") is False


# ============================================================================
# TestClassifyUsername
# ============================================================================

class TestClassifyUsername:
    """Tests for classify_username()."""

    def test_root_is_user(self):
        name, category = classify_username("root")
        assert name == "root"
        assert category == "user"

    def test_regular_user(self):
        name, category = classify_username("jdoe")
        assert name == "jdoe"
        assert category == "user"

    def test_system_noise_word(self):
        name, category = classify_username("session")
        assert name == "session"
        assert category == "system_noise"

    def test_invalid_path(self):
        name, category = classify_username("/usr/bin/bash")
        assert name == "/usr/bin/bash"
        assert category == "invalid"

    def test_invalid_hex(self):
        name, category = classify_username("deadbeef")
        assert name == "deadbeef"
        assert category == "invalid"

    def test_empty_string(self):
        name, category = classify_username("")
        assert name == ""
        assert category == ""

    def test_none_input(self):
        name, category = classify_username(None)
        assert name == ""
        assert category == ""

    def test_strips_trailing_punctuation(self):
        name, category = classify_username("admin:")
        assert name == "admin"
        assert category == "user"

    def test_www_data_is_user(self):
        name, category = classify_username("www-data")
        assert name == "www-data"
        assert category == "user"


# ============================================================================
# TestParseAuthLog
# ============================================================================

class TestParseAuthLog:
    """Tests for parse_auth_log() using in-memory byte data."""

    def _parse(self, data=AUTH_LOG_DATA, reference_date=None):
        if reference_date is None:
            reference_date = datetime(2025, 6, 1, 12, 0, 0)
        return parse_auth_log(
            filepath="auth.log",
            data=data,
            reference_date=reference_date,
        )

    def test_returns_list(self):
        events = self._parse()
        assert isinstance(events, list)

    def test_events_are_timeline_events(self):
        events = self._parse()
        for ev in events:
            assert isinstance(ev, TimelineEvent)

    def test_accepted_publickey_parsed(self):
        events = self._parse()
        pubkey_events = [e for e in events if "PUBKEY" in e.event_type or "publickey" in e.description.lower()]
        assert len(pubkey_events) >= 1
        ev = pubkey_events[0]
        assert ev.username == "root"
        assert ev.source_ip == "10.0.0.1"

    def test_failed_password_parsed(self):
        events = self._parse()
        failed_events = [e for e in events if "FAILED" in e.event_type or "INVALID" in e.event_type]
        assert len(failed_events) >= 1
        # The source IP for the failed attempt should be present
        ips = [e.source_ip for e in failed_events]
        assert "192.168.1.100" in ips

    def test_sudo_command_parsed(self):
        events = self._parse()
        sudo_events = [e for e in events if "SUDO" in e.event_type]
        assert len(sudo_events) >= 1
        ev = sudo_events[0]
        assert ev.username == "root"

    def test_accepted_password_parsed(self):
        events = self._parse()
        password_events = [
            e for e in events
            if "PASSWORD" in e.event_type and "FAILED" not in e.event_type
        ]
        assert len(password_events) >= 1
        ev = password_events[0]
        assert ev.username == "backdoor"
        assert ev.source_ip == "10.0.0.99"

    def test_timestamps_are_datetime(self):
        events = self._parse()
        for ev in events:
            assert isinstance(ev.timestamp, datetime)

    def test_empty_data_returns_empty(self):
        events = self._parse(data=b"")
        assert events == []

    def test_garbage_data_returns_empty(self):
        events = self._parse(data=b"this is not a log line\nno timestamps here\n")
        assert events == []


# ============================================================================
# TestParseUtmpRecord
# ============================================================================

class TestParseUtmpRecord:
    """Tests for parse_utmp_record()."""

    def _build_record(
        self,
        ut_type=7,
        ut_pid=1234,
        ut_line=b"pts/0",
        ut_id=b"ts/0",
        ut_user=b"testuser",
        ut_host=b"10.0.0.1",
        ut_tv_sec=1717200000,
    ):
        """Build a minimal 384-byte utmp record."""
        # Pad strings to their fixed sizes
        ut_line = ut_line.ljust(32, b"\x00")
        ut_id = ut_id.ljust(4, b"\x00")
        ut_user = ut_user.ljust(32, b"\x00")
        ut_host = ut_host.ljust(256, b"\x00")
        unused = b"\x00" * 20

        record = struct.pack(
            UTMP_STRUCT_FORMAT,
            ut_type,        # ut_type
            0,              # padding
            ut_pid,         # ut_pid
            ut_line,        # ut_line
            ut_id,          # ut_id
            ut_user,        # ut_user
            ut_host,        # ut_host
            0,              # ut_exit.e_termination
            0,              # ut_exit.e_exit
            0,              # ut_session
            ut_tv_sec,      # ut_tv.tv_sec
            0,              # ut_tv.tv_usec
            0, 0, 0, 0,    # ut_addr_v6
            unused,         # __unused
        )
        return record

    def test_valid_user_process(self):
        record = self._build_record()
        result = parse_utmp_record(record)
        assert result is not None
        assert result["type"] == 7
        assert result["type_name"] == "USER_PROCESS"
        assert result["user"] == "testuser"
        assert result["pid"] == 1234
        assert result["line"] == "pts/0"

    def test_boot_time_record(self):
        record = self._build_record(ut_type=2, ut_user=b"reboot", ut_host=b"5.15.0-generic")
        result = parse_utmp_record(record)
        assert result is not None
        assert result["type"] == 2
        assert result["type_name"] == "BOOT_TIME"
        assert result["user"] == "reboot"

    def test_timestamp_parsed(self):
        record = self._build_record(ut_tv_sec=1717200000)
        result = parse_utmp_record(record)
        assert result is not None
        assert result["timestamp"] is not None
        assert isinstance(result["timestamp"], datetime)

    def test_empty_record_returns_none(self):
        result = parse_utmp_record(b"")
        assert result is None

    def test_short_data_returns_none(self):
        result = parse_utmp_record(b"\x00" * 100)
        assert result is None

    def test_host_used_as_ip_for_user_process(self):
        record = self._build_record(ut_type=7, ut_host=b"192.168.1.50")
        result = parse_utmp_record(record)
        assert result is not None
        assert result["source_ip"] == "192.168.1.50"

    def test_dead_process(self):
        record = self._build_record(ut_type=8, ut_user=b"", ut_host=b"")
        result = parse_utmp_record(record)
        assert result is not None
        assert result["type_name"] == "DEAD_PROCESS"

    def test_zero_timestamp(self):
        record = self._build_record(ut_tv_sec=0)
        result = parse_utmp_record(record)
        assert result is not None
        assert result["timestamp"] is None
