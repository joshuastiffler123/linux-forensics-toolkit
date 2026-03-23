"""Tests for lft.analyzers.packages — package manager log analyzer."""

import pytest
from datetime import datetime

from lft.analyzers.packages import (
    PackageEvent,
    SUSPICIOUS_PACKAGES,
    _is_suspicious,
    parse_dpkg_log,
)


# ============================================================================
# Sample dpkg.log content used across multiple tests
# ============================================================================

DPKG_LOG_SAMPLE = """\
2025-01-15 10:30:00 install nmap:amd64 <none> 7.94+git20230101-1
2025-01-15 10:35:00 install curl:amd64 <none> 7.88.1-10
2025-01-15 11:00:00 remove apache2:amd64 2.4.57-2 <none>
2025-01-15 11:05:00 upgrade openssl:amd64 3.0.11-1 3.0.13-1
"""


# ============================================================================
# TestPackageEvent
# ============================================================================

class TestPackageEvent:
    """Tests for the PackageEvent data class."""

    def test_constructor_defaults(self):
        ts = datetime(2025, 1, 15, 10, 30, 0)
        ev = PackageEvent(
            timestamp=ts,
            action='install',
            package_name='curl',
            version='7.88.1-10',
        )
        assert ev.timestamp == ts
        assert ev.action == 'install'
        assert ev.package_name == 'curl'
        assert ev.version == '7.88.1-10'
        assert ev.previous_version == ''
        assert ev.is_suspicious is False
        assert ev.suspicion_reason == ''

    def test_constructor_all_fields(self):
        ts = datetime(2025, 6, 1, 0, 0, 0)
        ev = PackageEvent(
            timestamp=ts,
            action='install',
            package_name='nmap',
            version='7.94',
            previous_version='',
            commandline='apt install nmap',
            requested_by='root (0)',
            source='dpkg',
            log_file='/var/log/dpkg.log',
            raw_entry='raw line here',
            is_suspicious=True,
            suspicion_reason="'nmap' commonly used in intrusions",
        )
        assert ev.is_suspicious is True
        assert ev.commandline == 'apt install nmap'
        assert ev.requested_by == 'root (0)'

    def test_to_dict_keys(self):
        ev = PackageEvent(
            timestamp=datetime(2025, 1, 15, 10, 30, 0),
            action='install',
            package_name='curl',
            version='7.88.1-10',
        )
        d = ev.to_dict()
        expected_keys = {
            'Timestamp_UTC', 'Action', 'Package', 'Version',
            'Previous_Version', 'Commandline', 'Requested_By',
            'Source', 'Log_File', 'Suspicious', 'Suspicion_Reason',
            'Raw_Entry',
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self):
        ev = PackageEvent(
            timestamp=datetime(2025, 1, 15, 10, 30, 0),
            action='install',
            package_name='curl',
            version='7.88.1-10',
            previous_version='7.80.0-1',
        )
        d = ev.to_dict()
        assert d['Timestamp_UTC'] == '2025-01-15 10:30:00'
        assert d['Action'] == 'install'
        assert d['Package'] == 'curl'
        assert d['Version'] == '7.88.1-10'
        assert d['Previous_Version'] == '7.80.0-1'
        assert d['Suspicious'] == ''

    def test_to_dict_suspicious_flag(self):
        ev = PackageEvent(
            timestamp=datetime(2025, 1, 15, 10, 30, 0),
            action='install',
            package_name='nmap',
            version='7.94',
            is_suspicious=True,
            suspicion_reason="'nmap' commonly used in intrusions",
        )
        d = ev.to_dict()
        assert d['Suspicious'] == 'Yes'
        assert 'nmap' in d['Suspicion_Reason']

    def test_to_dict_none_timestamp(self):
        ev = PackageEvent(
            timestamp=None,
            action='install',
            package_name='curl',
            version='1.0',
        )
        d = ev.to_dict()
        assert d['Timestamp_UTC'] == ''


# ============================================================================
# TestIsSuspicious
# ============================================================================

class TestIsSuspicious:
    """Tests for the _is_suspicious() helper."""

    def test_nmap_is_suspicious(self):
        result, reason = _is_suspicious('nmap')
        assert result is True
        assert 'nmap' in reason

    def test_curl_is_not_suspicious(self):
        result, reason = _is_suspicious('curl')
        assert result is False
        assert reason == ''

    def test_tor_is_suspicious(self):
        result, reason = _is_suspicious('tor')
        assert result is True

    def test_hashcat_is_suspicious(self):
        result, reason = _is_suspicious('hashcat')
        assert result is True

    def test_hydra_is_suspicious(self):
        result, reason = _is_suspicious('hydra')
        assert result is True

    def test_metasploit_framework_is_suspicious(self):
        result, reason = _is_suspicious('metasploit-framework')
        assert result is True

    def test_case_insensitive(self):
        result, _ = _is_suspicious('NMAP')
        assert result is True

    def test_fragment_match_xmrig(self):
        result, reason = _is_suspicious('custom-xmrig-build')
        assert result is True
        assert 'xmrig' in reason

    def test_fragment_match_miner(self):
        result, reason = _is_suspicious('my-crypto-miner-tool')
        assert result is True
        assert 'miner' in reason

    def test_benign_package(self):
        result, reason = _is_suspicious('python3')
        assert result is False
        assert reason == ''


# ============================================================================
# TestParseDpkgLog
# ============================================================================

class TestParseDpkgLog:
    """Tests for parse_dpkg_log()."""

    def test_parses_four_events(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        assert len(events) == 4

    def test_install_action(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        assert events[0].action == 'install'
        assert events[1].action == 'install'

    def test_remove_action(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        assert events[2].action == 'remove'

    def test_upgrade_action(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        assert events[3].action == 'upgrade'

    def test_nmap_flagged_suspicious(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        nmap_event = events[0]
        assert nmap_event.package_name == 'nmap'
        assert nmap_event.is_suspicious is True
        assert 'nmap' in nmap_event.suspicion_reason

    def test_curl_not_suspicious(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        curl_event = events[1]
        assert curl_event.package_name == 'curl'
        assert curl_event.is_suspicious is False

    def test_none_becomes_empty_string(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        # nmap install: old version is <none> -> ''
        assert events[0].previous_version == ''
        # nmap install: new version is 7.94+git20230101-1
        assert events[0].version == '7.94+git20230101-1'
        # apache2 remove: new version is <none> -> ''
        assert events[2].version == ''

    def test_upgrade_versions(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        openssl = events[3]
        assert openssl.package_name == 'openssl'
        assert openssl.previous_version == '3.0.11-1'
        assert openssl.version == '3.0.13-1'

    def test_timestamps_parsed(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        assert events[0].timestamp == datetime(2025, 1, 15, 10, 30, 0)
        assert events[3].timestamp == datetime(2025, 1, 15, 11, 5, 0)

    def test_source_set_to_dpkg(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, 'dpkg.log')
        for ev in events:
            assert ev.source == 'dpkg'

    def test_log_file_preserved(self):
        events = parse_dpkg_log(DPKG_LOG_SAMPLE, '/var/log/dpkg.log')
        for ev in events:
            assert ev.log_file == '/var/log/dpkg.log'

    def test_empty_content(self):
        events = parse_dpkg_log('', 'dpkg.log')
        assert events == []

    def test_blank_lines_skipped(self):
        content = "\n\n2025-01-15 10:30:00 install curl:amd64 <none> 7.88.1-10\n\n"
        events = parse_dpkg_log(content, 'dpkg.log')
        assert len(events) == 1

    def test_malformed_line_skipped(self):
        content = (
            "this is not a valid dpkg line\n"
            "2025-01-15 10:30:00 install curl:amd64 <none> 7.88.1-10\n"
        )
        events = parse_dpkg_log(content, 'dpkg.log')
        assert len(events) == 1
        assert events[0].package_name == 'curl'


# ============================================================================
# TestSuspiciousPackagesConstant
# ============================================================================

class TestSuspiciousPackagesConstant:
    """Tests that SUSPICIOUS_PACKAGES contains expected entries."""

    def test_is_frozenset(self):
        assert isinstance(SUSPICIOUS_PACKAGES, frozenset)

    @pytest.mark.parametrize("pkg", [
        'nmap', 'hashcat', 'tor', 'hydra', 'metasploit-framework',
        'masscan', 'wireshark', 'tcpdump', 'rclone', 'xmrig',
        'sqlmap', 'nikto', 'john', 'socat', 'proxychains',
    ])
    def test_key_packages_present(self, pkg):
        assert pkg in SUSPICIOUS_PACKAGES

    def test_benign_packages_absent(self):
        for pkg in ('curl', 'wget', 'python3', 'bash', 'openssh-server'):
            assert pkg not in SUSPICIOUS_PACKAGES
