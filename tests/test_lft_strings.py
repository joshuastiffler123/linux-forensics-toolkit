"""Tests for the string analyzer (log carving)."""

import re
import pytest
from lft.analyzers.strings import (
    LogEntry,
    AUDIT_LOG_RE,
    TRAD_SYSLOG_RE,
    NEWSYSLOG_RE,
    WEBLOG_RE,
    SECURITY_PROCS,
    SECURITY_MSG_RE,
    StringAnalyzer,
)


class TestLogEntry:
    """Test the LogEntry data class."""

    def test_constructor(self):
        entry = LogEntry(
            category="audit",
            timestamp="1705312800.123",
            raw_line="type=SYSCALL msg=audit(1705312800.123:456): arch=...",
            source_file="/var/log/audit/audit.log",
            hostname="testhost",
            process="sshd",
            message="session opened",
        )
        assert entry.category == "audit"
        assert entry.timestamp == "1705312800.123"
        assert entry.hostname == "testhost"

    def test_defaults(self):
        entry = LogEntry("syslog", "2025-01-15", "test line")
        assert entry.source_file == ""
        assert entry.hostname == ""
        assert entry.process == ""
        assert entry.message == ""


class TestAuditLogRegex:
    """Test the audit log regex pattern."""

    def test_matches_audit_entry(self):
        line = 'type=SYSCALL msg=audit(1705312800.123:456): arch=c000003e'
        m = AUDIT_LOG_RE.match(line)
        assert m is not None
        assert m.group(1) == "SYSCALL"
        assert m.group(2) == "1705312800.123"
        assert m.group(3) == "456"

    def test_matches_user_login(self):
        line = 'type=USER_LOGIN msg=audit(1705312800.000:100): pid=1234 uid=0'
        m = AUDIT_LOG_RE.match(line)
        assert m is not None
        assert m.group(1) == "USER_LOGIN"

    def test_no_match_on_plain_text(self):
        assert AUDIT_LOG_RE.match("just a regular log line") is None


class TestTraditionalSyslogRegex:
    """Test traditional syslog format parsing."""

    def test_matches_syslog(self):
        line = "Jun  1 12:00:00 testhost sshd[1234]: Accepted publickey for root"
        m = TRAD_SYSLOG_RE.match(line)
        assert m is not None
        assert m.group(1) == "Jun"      # month
        assert m.group(4) == "testhost" # hostname
        assert m.group(5) == "sshd[1234]"  # process

    def test_matches_single_digit_day(self):
        line = "Jan  5 08:30:00 myhost kernel: some message"
        m = TRAD_SYSLOG_RE.match(line)
        assert m is not None

    def test_no_match_on_iso(self):
        line = "2025-01-15T10:00:00.000+00:00 kern.info testhost kernel: msg"
        assert TRAD_SYSLOG_RE.match(line) is None


class TestNewSyslogRegex:
    """Test new-style syslog format (ISO timestamp)."""

    def test_matches_new_syslog(self):
        line = "2025-01-15T10:00:00.123456+00:00 kern.info testhost kernel: boot message"
        m = NEWSYSLOG_RE.match(line)
        assert m is not None
        assert "2025-01-15" in m.group(1)


class TestWeblogRegex:
    """Test Apache/Nginx combined log format regex."""

    def test_matches_access_log(self):
        line = '10.0.0.1 - - [15/Jan/2025:10:00:00 +0000] "GET /index.html HTTP/1.1"'
        m = WEBLOG_RE.match(line)
        assert m is not None
        assert m.group(1) == "10.0.0.1"

    def test_captures_request(self):
        line = '192.168.1.1 - admin [15/Jan/2025:10:00:00 +0000] "POST /login HTTP/1.1"'
        m = WEBLOG_RE.match(line)
        assert m is not None
        assert "POST /login" in m.group(4)


class TestSecurityPatterns:
    """Test security-relevant pattern matching."""

    @pytest.mark.parametrize("proc", [
        "sshd", "sudo", "su", "useradd", "passwd", "login",
        "systemd-logind", "polkitd", "pkexec",
    ])
    def test_security_procs_match(self, proc):
        assert SECURITY_PROCS.search(proc) is not None

    def test_non_security_proc(self):
        assert SECURITY_PROCS.search("httpd") is None

    @pytest.mark.parametrize("msg", [
        "Accepted publickey for root",
        "Failed password for admin",
        "session opened for user root",
        "COMMAND=/usr/bin/apt",
        "authentication failure",
        "new user: name=testuser",
    ])
    def test_security_message_match(self, msg):
        assert SECURITY_MSG_RE.search(msg) is not None


class TestStringAnalyzerInit:
    """Test StringAnalyzer initialization."""

    def test_directory_init(self, sample_uac_dir):
        analyzer = StringAnalyzer(str(sample_uac_dir))
        assert not analyzer.is_tarball
        assert analyzer.audit_entries == []
        assert analyzer.syslog_entries == []
        assert analyzer.weblog_entries == []
        assert analyzer.security_entries == []

    def test_tarball_init(self, sample_tarball):
        analyzer = StringAnalyzer(str(sample_tarball))
        assert analyzer.is_tarball
        assert analyzer.tar is not None
        analyzer.close()
