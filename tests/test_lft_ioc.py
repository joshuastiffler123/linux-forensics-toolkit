"""Tests for the IOC scanner."""

import os
import pytest
from lft.analyzers.ioc import IOCMatch, IOCScanner, SCAN_PATHS


class TestIOCMatch:
    """Test the IOCMatch data class."""

    def test_constructor(self):
        match = IOCMatch(
            ioc="10.0.0.99",
            source_file="/var/log/auth.log",
            line_number=42,
            line_content="connection from 10.0.0.99",
            context="auth log match",
        )
        assert match.ioc == "10.0.0.99"
        assert match.source_file == "/var/log/auth.log"
        assert match.line_number == 42
        assert match.line_content == "connection from 10.0.0.99"
        assert match.context == "auth log match"

    def test_default_context(self):
        match = IOCMatch("evil.com", "test.log", 1, "evil.com found")
        assert match.context == ""


class TestScanPaths:
    """Verify scan path coverage."""

    def test_includes_var_log(self):
        assert 'var/log/' in SCAN_PATHS

    def test_includes_etc(self):
        assert 'etc/' in SCAN_PATHS

    def test_includes_tmp(self):
        assert 'tmp/' in SCAN_PATHS

    def test_includes_home(self):
        assert 'home/' in SCAN_PATHS


class TestIOCScannerInit:
    """Test IOCScanner initialization."""

    def test_loads_iocs_from_file(self, ioc_file, sample_uac_dir):
        scanner = IOCScanner(str(sample_uac_dir), str(ioc_file))
        # Comments (lines starting with #) should be skipped
        assert "10.0.0.99" in scanner.iocs
        assert "malicious-c2.example.com" in scanner.iocs
        assert "evil.example.com" in scanner.iocs
        # Comment line should not be loaded
        assert "# IOC indicators" not in scanner.iocs

    def test_ioc_count(self, ioc_file, sample_uac_dir):
        scanner = IOCScanner(str(sample_uac_dir), str(ioc_file))
        assert len(scanner.iocs) == 3

    def test_max_file_size_override(self, ioc_file, sample_uac_dir):
        scanner = IOCScanner(str(sample_uac_dir), str(ioc_file),
                             max_file_size=1024)
        assert scanner.MAX_FILE_SIZE == 1024


class TestIOCScannerDirectory:
    """Test IOC scanning against an extracted directory."""

    def test_scan_finds_matches(self, ioc_file, sample_uac_dir):
        scanner = IOCScanner(str(sample_uac_dir), str(ioc_file))
        scanner.scan()
        # auth.log contains 10.0.0.99, hosts contains malicious-c2.example.com,
        # crontab contains evil.example.com
        assert len(scanner.matches) > 0

    def test_scan_matches_correct_ioc(self, ioc_file, sample_uac_dir):
        scanner = IOCScanner(str(sample_uac_dir), str(ioc_file))
        scanner.scan()
        matched_iocs = {m.ioc for m in scanner.matches}
        assert "10.0.0.99" in matched_iocs

    def test_files_scanned_positive(self, ioc_file, sample_uac_dir):
        scanner = IOCScanner(str(sample_uac_dir), str(ioc_file))
        scanner.scan()
        assert scanner.files_scanned > 0


class TestIOCScannerTarball:
    """Test IOC scanning against a tarball."""

    def test_scan_tarball(self, ioc_file, sample_tarball):
        scanner = IOCScanner(str(sample_tarball), str(ioc_file))
        scanner.scan()
        assert scanner.files_scanned > 0
        scanner.close()


class TestIOCScannerConstants:
    """Test scanner constants."""

    def test_text_extensions(self):
        assert '.log' in IOCScanner.TEXT_EXTENSIONS
        assert '.conf' in IOCScanner.TEXT_EXTENSIONS
        assert '.sh' in IOCScanner.TEXT_EXTENSIONS

    def test_binary_extensions(self):
        assert '.so' in IOCScanner.BINARY_EXTENSIONS
        assert '.png' in IOCScanner.BINARY_EXTENSIONS
        assert '.pyc' in IOCScanner.BINARY_EXTENSIONS

    def test_max_file_size_default(self):
        assert IOCScanner.MAX_FILE_SIZE == 200 * 1024 * 1024
