"""Tests for the journal analyzer."""

from dataclasses import fields
from datetime import datetime

import pytest
from lft.analyzers.journal import (
    JournalEntry,
    DEFAULT_MAX_MESSAGE_LENGTH,
)


class TestJournalEntry:
    """Test the JournalEntry dataclass."""

    def test_constructor(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        entry = JournalEntry(
            timestamp=ts,
            hostname="testhost",
            unit="sshd.service",
            priority=6,
            priority_name="INFO",
            message="Accepted publickey for root",
        )
        assert entry.timestamp == ts
        assert entry.hostname == "testhost"
        assert entry.unit == "sshd.service"
        assert entry.priority == 6
        assert entry.priority_name == "INFO"
        assert entry.message == "Accepted publickey for root"

    def test_defaults(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        entry = JournalEntry(
            timestamp=ts, hostname="h", unit="u",
            priority=6, priority_name="INFO", message="m",
        )
        assert entry.pid == 0
        assert entry.uid == -1
        assert entry.gid == -1
        assert entry.comm == ""
        assert entry.exe == ""
        assert entry.boot_id == ""
        assert entry.category == "GENERAL"

    def test_priority_constants(self):
        assert JournalEntry.PRIORITIES[0] == "EMERG"
        assert JournalEntry.PRIORITIES[3] == "ERR"
        assert JournalEntry.PRIORITIES[4] == "WARNING"
        assert JournalEntry.PRIORITIES[6] == "INFO"
        assert JournalEntry.PRIORITIES[7] == "DEBUG"
        assert len(JournalEntry.PRIORITIES) == 8

    def test_to_dict_keys(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        entry = JournalEntry(
            timestamp=ts, hostname="testhost", unit="sshd",
            priority=6, priority_name="INFO", message="test",
        )
        d = entry.to_dict()
        assert isinstance(d, dict)
        assert "Timestamp" in d or "Timestamp_UTC" in d
        assert "Priority" in d or "priority" in d.get("Priority_Name", d)

    def test_to_dict_truncates_long_message(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        long_msg = "A" * 60000
        entry = JournalEntry(
            timestamp=ts, hostname="h", unit="u",
            priority=6, priority_name="INFO", message=long_msg,
        )
        d = entry.to_dict(max_message_length=100)
        # The message in the dict should be truncated
        msg_val = d.get("Message", d.get("message", ""))
        assert len(msg_val) <= 120  # allow slack for truncation marker

    def test_clean_message_strips_prefix(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        entry = JournalEntry(
            timestamp=ts, hostname="testhost", unit="sshd",
            priority=6, priority_name="INFO", message="test",
            syslog_identifier="sshd",
        )
        result = entry.clean_message("sshd[1234]: Accepted publickey for root")
        assert "Accepted publickey" in result
        # Should have removed the sshd[1234]: prefix
        assert not result.startswith("sshd")


class TestDefaultMaxMessageLength:
    """Test the default message length constant."""

    def test_value(self):
        assert DEFAULT_MAX_MESSAGE_LENGTH == 50000


class TestJournalEntryDataclassFields:
    """Verify the dataclass has the expected fields."""

    def test_required_fields(self):
        field_names = {f.name for f in fields(JournalEntry)}
        required = {
            'timestamp', 'hostname', 'unit', 'priority',
            'priority_name', 'message',
        }
        assert required.issubset(field_names)

    def test_optional_fields(self):
        field_names = {f.name for f in fields(JournalEntry)}
        optional = {
            'pid', 'uid', 'gid', 'comm', 'exe', 'cmdline',
            'boot_id', 'machine_id', 'transport',
            'syslog_identifier', 'category', 'extra',
        }
        assert optional.issubset(field_names)
