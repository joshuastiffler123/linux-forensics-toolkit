"""Tests for the security analyzer."""

import pytest
from lft.analyzers.security import (
    SecurityFinding,
    MITRE_TECHNIQUES,
    is_elf_binary,
    is_script,
    is_executable,
    is_hidden_path,
    LinuxSecurityAnalyzer,
)


class TestSecurityFinding:
    """Test the SecurityFinding dataclass."""

    def test_constructor(self):
        finding = SecurityFinding(
            filepath="/usr/bin/suspicious",
            finding_type="SUID Binary",
            technique="Abuse Elevation Control",
            technique_id="T1548.001",
            severity="HIGH",
            description="SUID binary in non-standard location",
        )
        assert finding.filepath == "/usr/bin/suspicious"
        assert finding.technique_id == "T1548.001"
        assert finding.severity == "HIGH"

    def test_defaults(self):
        finding = SecurityFinding(
            filepath="/t", finding_type="t", technique="t",
            technique_id="T0", severity="INFO", description="d",
        )
        assert finding.indicator == ""
        assert finding.line_number == 0
        assert finding.hash_md5 == ""
        assert finding.file_size == 0

    def test_to_dict(self):
        finding = SecurityFinding(
            filepath="/test", finding_type="Binary",
            technique="Test", technique_id="T0000",
            severity="MEDIUM", description="test finding",
        )
        d = finding.to_dict()
        assert d["Filepath"] == "/test"
        assert d["Finding_Type"] == "Binary"
        assert d["MITRE_ATT&CK_ID"] == "T0000"
        assert d["Severity"] == "MEDIUM"


class TestMitreTechniques:
    """Verify MITRE technique constant."""

    @pytest.mark.parametrize("key", [
        "cron", "systemd_service", "ssh_authorized_keys",
        "ld_preload", "suid_sgid", "rootkit", "web_shell",
        "kernel_module", "pam_backdoor",
    ])
    def test_key_present(self, key):
        assert key in MITRE_TECHNIQUES

    def test_all_have_technique_id(self):
        for key, (name, tid) in MITRE_TECHNIQUES.items():
            assert tid.startswith("T"), f"{key}: ID {tid} doesn't start with T"
            assert name, f"{key}: missing technique name"


class TestBinaryDetection:
    """Test binary/script detection functions."""

    def test_elf_detection(self):
        elf_header = b'\x7fELF' + b'\x00' * 100
        assert is_elf_binary(elf_header) is True

    def test_non_elf_detection(self):
        assert is_elf_binary(b'plain text content') is False

    def test_empty_data(self):
        assert is_elf_binary(b'') is False

    def test_script_detection_bash(self):
        assert is_script(b'#!/bin/bash\necho hello') is True

    def test_script_detection_python(self):
        assert is_script(b'#!/usr/bin/env python3\nprint("hi")') is True

    def test_script_detection_plain(self):
        assert is_script(b'just plain text') is False

    def test_executable_elf(self):
        assert is_executable(b'\x7fELF' + b'\x00' * 100) is True

    def test_executable_script(self):
        assert is_executable(b'#!/bin/sh\necho test') is True

    def test_executable_text(self):
        assert is_executable(b'regular text file') is False


class TestHiddenPath:
    """Test hidden path detection."""

    def test_hidden_file(self):
        assert is_hidden_path("/home/user/.malware/tool") is True

    def test_hidden_dir(self):
        assert is_hidden_path("/tmp/.hidden/") is True

    def test_normal_path(self):
        assert is_hidden_path("/usr/bin/normal") is False

    def test_dotconfig(self):
        # .config is typically hidden
        assert is_hidden_path("/home/user/.config/something") is True


class TestLinuxSecurityAnalyzerInit:
    """Test LinuxSecurityAnalyzer initialization."""

    def test_directory_init(self, sample_uac_dir):
        analyzer = LinuxSecurityAnalyzer(str(sample_uac_dir))
        assert analyzer.findings == []
        analyzer.close()

    def test_tarball_init(self, sample_tarball):
        analyzer = LinuxSecurityAnalyzer(str(sample_tarball))
        assert analyzer.findings == []
        analyzer.close()
