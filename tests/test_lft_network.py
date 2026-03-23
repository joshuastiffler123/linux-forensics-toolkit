"""Tests for lft.analyzers.network — network artifact analysis."""

import pytest
from datetime import datetime

from lft.analyzers.network import (
    NetworkFinding,
    WebAccessEvent,
    parse_hosts_file,
    parse_resolv_conf,
    parse_web_access_log,
    _WELL_KNOWN_DNS,
    _WEBSHELL_NAMES,
)


# ============================================================================
# Test data
# ============================================================================

HOSTS_CONTENT = (
    "127.0.0.1\tlocalhost\n"
    "10.0.0.50\tmalicious-c2.example.com\n"
)

RESOLV_CONF_CONTENT = (
    "nameserver 8.8.8.8\n"
    "nameserver 203.0.113.53\n"
)

WEB_ACCESS_LOG = (
    '10.0.0.1 - - [15/Jan/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
    '10.0.0.2 - - [15/Jan/2025:10:01:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.88"\n'
    '10.0.0.3 - - [15/Jan/2025:10:02:00 +0000] "GET /search?q=SELECT+*+FROM+users HTTP/1.1" 200 500 "-" "sqlmap/1.7"\n'
    '10.0.0.4 - - [15/Jan/2025:10:03:00 +0000] "POST /shell.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
)


# ============================================================================
# TestNetworkFinding
# ============================================================================

class TestNetworkFinding:
    """Tests for the NetworkFinding data class."""

    def test_constructor_defaults(self):
        f = NetworkFinding(finding_type='test_type', description='A test finding')
        assert f.finding_type == 'test_type'
        assert f.description == 'A test finding'
        assert f.severity == 'INFO'
        assert f.timestamp is None
        assert f.source_ip == ''
        assert f.dest_ip == ''
        assert f.dest_port == ''
        assert f.protocol == ''
        assert f.action == ''
        assert f.log_file == ''
        assert f.raw_entry == ''

    def test_constructor_all_fields(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        f = NetworkFinding(
            finding_type='firewall_event',
            description='UFW BLOCK',
            severity='HIGH',
            timestamp=ts,
            source_ip='10.0.0.1',
            dest_ip='10.0.0.2',
            dest_port='22',
            protocol='TCP',
            action='BLOCK',
            log_file='/var/log/ufw.log',
            raw_entry='raw log line',
        )
        assert f.finding_type == 'firewall_event'
        assert f.severity == 'HIGH'
        assert f.timestamp == ts
        assert f.source_ip == '10.0.0.1'
        assert f.dest_ip == '10.0.0.2'
        assert f.dest_port == '22'
        assert f.protocol == 'TCP'
        assert f.action == 'BLOCK'

    def test_to_dict_keys(self):
        f = NetworkFinding(finding_type='test', description='desc')
        d = f.to_dict()
        expected_keys = {
            'Timestamp_UTC', 'Finding_Type', 'Severity', 'Description',
            'Source_IP', 'Dest_IP', 'Dest_Port', 'Protocol',
            'Action', 'Log_File', 'Raw_Entry',
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_timestamp_formatting(self):
        ts = datetime(2025, 1, 15, 10, 30, 45)
        f = NetworkFinding(finding_type='t', description='d', timestamp=ts)
        assert f.to_dict()['Timestamp_UTC'] == '2025-01-15 10:30:45'

    def test_to_dict_no_timestamp(self):
        f = NetworkFinding(finding_type='t', description='d')
        assert f.to_dict()['Timestamp_UTC'] == ''

    def test_to_dict_raw_entry_truncation(self):
        long_entry = 'x' * 500
        f = NetworkFinding(finding_type='t', description='d', raw_entry=long_entry)
        raw = f.to_dict()['Raw_Entry']
        assert raw.endswith('[TRUNCATED]')
        assert len(raw) < 500

    def test_to_dict_short_raw_entry_not_truncated(self):
        f = NetworkFinding(finding_type='t', description='d', raw_entry='short')
        assert f.to_dict()['Raw_Entry'] == 'short'


# ============================================================================
# TestWebAccessEvent
# ============================================================================

class TestWebAccessEvent:
    """Tests for the WebAccessEvent data class."""

    def test_constructor_defaults(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        e = WebAccessEvent(
            timestamp=ts, client_ip='10.0.0.1', method='GET',
            uri='/index.html', status_code=200, response_bytes=1234,
            referrer='-', user_agent='Mozilla/5.0', log_file='access.log',
        )
        assert e.client_ip == '10.0.0.1'
        assert e.method == 'GET'
        assert e.uri == '/index.html'
        assert e.status_code == 200
        assert e.response_bytes == 1234
        assert e.is_suspicious is False
        assert e.suspicion_reason == ''

    def test_constructor_suspicious(self):
        e = WebAccessEvent(
            timestamp=None, client_ip='1.2.3.4', method='POST',
            uri='/shell.php', status_code=200, response_bytes=50,
            referrer='', user_agent='curl/7.88', log_file='access.log',
            is_suspicious=True, suspicion_reason='webshell detected',
        )
        assert e.is_suspicious is True
        assert e.suspicion_reason == 'webshell detected'

    def test_to_dict_keys(self):
        e = WebAccessEvent(
            timestamp=None, client_ip='1.2.3.4', method='GET',
            uri='/', status_code=200, response_bytes=0,
            referrer='', user_agent='', log_file='test.log',
        )
        d = e.to_dict()
        expected_keys = {
            'Timestamp_UTC', 'Client_IP', 'Method', 'URI',
            'Status_Code', 'Response_Bytes', 'Referrer', 'User_Agent',
            'Log_File', 'Suspicious', 'Suspicion_Reason',
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_suspicious_flag_yes(self):
        e = WebAccessEvent(
            timestamp=None, client_ip='1.2.3.4', method='GET',
            uri='/', status_code=200, response_bytes=0,
            referrer='', user_agent='', log_file='test.log',
            is_suspicious=True, suspicion_reason='test reason',
        )
        d = e.to_dict()
        assert d['Suspicious'] == 'Yes'
        assert d['Suspicion_Reason'] == 'test reason'

    def test_to_dict_suspicious_flag_empty_when_not_suspicious(self):
        e = WebAccessEvent(
            timestamp=None, client_ip='1.2.3.4', method='GET',
            uri='/', status_code=200, response_bytes=0,
            referrer='', user_agent='', log_file='test.log',
        )
        d = e.to_dict()
        assert d['Suspicious'] == ''
        assert d['Suspicion_Reason'] == ''

    def test_to_dict_timestamp_formatting(self):
        ts = datetime(2025, 6, 1, 12, 30, 0)
        e = WebAccessEvent(
            timestamp=ts, client_ip='1.2.3.4', method='GET',
            uri='/', status_code=200, response_bytes=0,
            referrer='', user_agent='', log_file='test.log',
        )
        assert e.to_dict()['Timestamp_UTC'] == '2025-06-01 12:30:00'

    def test_to_dict_no_timestamp(self):
        e = WebAccessEvent(
            timestamp=None, client_ip='1.2.3.4', method='GET',
            uri='/', status_code=200, response_bytes=0,
            referrer='', user_agent='', log_file='test.log',
        )
        assert e.to_dict()['Timestamp_UTC'] == ''


# ============================================================================
# TestParseHostsFile
# ============================================================================

class TestParseHostsFile:
    """Tests for parse_hosts_file()."""

    def test_localhost_not_flagged(self):
        findings = parse_hosts_file(HOSTS_CONTENT, '/etc/hosts')
        descriptions = [f.description for f in findings]
        assert not any('localhost' in d and '127.0.0.1' in d for d in descriptions)

    def test_nonstandard_entry_flagged(self):
        findings = parse_hosts_file(HOSTS_CONTENT, '/etc/hosts')
        assert len(findings) >= 1
        found = [f for f in findings if '10.0.0.50' in f.dest_ip]
        assert len(found) == 1
        assert 'malicious-c2.example.com' in found[0].description

    def test_private_ip_severity_info(self):
        findings = parse_hosts_file(HOSTS_CONTENT, '/etc/hosts')
        found = [f for f in findings if f.dest_ip == '10.0.0.50']
        assert found[0].severity == 'INFO'

    def test_public_ip_severity_high(self):
        content = "44.33.22.11\tevil.example.com\n"
        findings = parse_hosts_file(content, '/etc/hosts')
        assert len(findings) == 1
        assert findings[0].severity == 'HIGH'
        assert 'C2' in findings[0].description

    def test_comment_lines_ignored(self):
        content = "# This is a comment\n127.0.0.1\tlocalhost\n"
        findings = parse_hosts_file(content, '/etc/hosts')
        assert len(findings) == 0

    def test_empty_content(self):
        findings = parse_hosts_file('', '/etc/hosts')
        assert findings == []

    def test_log_file_preserved(self):
        findings = parse_hosts_file(HOSTS_CONTENT, '/custom/path/hosts')
        for f in findings:
            assert f.log_file == '/custom/path/hosts'


# ============================================================================
# TestParseResolvConf
# ============================================================================

class TestParseResolvConf:
    """Tests for parse_resolv_conf()."""

    def test_well_known_dns_not_flagged_as_suspicious(self):
        findings = parse_resolv_conf(RESOLV_CONF_CONTENT, '/etc/resolv.conf')
        google_dns = [f for f in findings if f.dest_ip == '8.8.8.8']
        assert len(google_dns) == 1
        assert google_dns[0].severity == 'INFO'
        assert 'well-known' in google_dns[0].description

    def test_unusual_dns_flagged(self):
        findings = parse_resolv_conf(RESOLV_CONF_CONTENT, '/etc/resolv.conf')
        unusual = [f for f in findings if f.dest_ip == '203.0.113.53']
        assert len(unusual) == 1
        assert unusual[0].severity == 'MEDIUM'
        assert 'Unusual' in unusual[0].description

    def test_two_nameservers_parsed(self):
        findings = parse_resolv_conf(RESOLV_CONF_CONTENT, '/etc/resolv.conf')
        assert len(findings) == 2

    def test_private_dns_severity_info(self):
        content = "nameserver 192.168.1.1\n"
        findings = parse_resolv_conf(content, '/etc/resolv.conf')
        assert len(findings) == 1
        assert findings[0].severity == 'INFO'
        assert 'private' in findings[0].description

    def test_finding_type_dns_server(self):
        findings = parse_resolv_conf(RESOLV_CONF_CONTENT, '/etc/resolv.conf')
        for f in findings:
            assert f.finding_type == 'dns_server'

    def test_empty_content(self):
        findings = parse_resolv_conf('', '/etc/resolv.conf')
        assert findings == []


# ============================================================================
# TestParseWebAccessLog
# ============================================================================

class TestParseWebAccessLog:
    """Tests for parse_web_access_log()."""

    def test_four_events_parsed(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        assert len(events) == 4

    def test_normal_request_not_suspicious(self):
        # The first line (GET /index.html with Mozilla UA) should not be suspicious
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        index_events = [e for e in events if e.uri == '/index.html']
        assert len(index_events) == 1
        assert index_events[0].is_suspicious is False

    def test_directory_traversal_detected(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        traversal = [e for e in events if '../' in e.uri]
        assert len(traversal) == 1
        assert traversal[0].is_suspicious is True
        assert 'traversal' in traversal[0].suspicion_reason.lower()

    def test_sqlmap_user_agent_detected(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        sqlmap_events = [e for e in events if 'sqlmap' in e.user_agent.lower()]
        assert len(sqlmap_events) == 1
        assert sqlmap_events[0].is_suspicious is True
        assert 'sqlmap' in sqlmap_events[0].suspicion_reason.lower()

    def test_webshell_detected(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        shell_events = [e for e in events if 'shell.php' in e.uri]
        assert len(shell_events) == 1
        assert shell_events[0].is_suspicious is True
        assert 'web-shell' in shell_events[0].suspicion_reason.lower()

    def test_timestamps_parsed(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        for e in events:
            assert e.timestamp is not None
            assert e.timestamp.year == 2025
            assert e.timestamp.month == 1
            assert e.timestamp.day == 15

    def test_client_ips_parsed(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        ips = [e.client_ip for e in events]
        assert '10.0.0.1' in ips
        assert '10.0.0.2' in ips
        assert '10.0.0.3' in ips
        assert '10.0.0.4' in ips

    def test_status_codes_parsed(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, 'access.log')
        codes = {e.client_ip: e.status_code for e in events}
        assert codes['10.0.0.1'] == 200
        assert codes['10.0.0.2'] == 404

    def test_log_file_preserved(self):
        events = parse_web_access_log(WEB_ACCESS_LOG, '/var/log/apache2/access.log')
        for e in events:
            assert e.log_file == '/var/log/apache2/access.log'

    def test_empty_content(self):
        events = parse_web_access_log('', 'access.log')
        assert events == []


# ============================================================================
# TestWebshellNames
# ============================================================================

class TestWebshellNames:
    """Tests for the _WEBSHELL_NAMES constant."""

    @pytest.mark.parametrize("name", [
        'shell.php', 'c99.php', 'r57.php', 'cmd.php',
        'b374k.php', 'wso.php', 'webshell.php',
        'cmd.asp', 'shell.jsp',
    ])
    def test_known_webshells_present(self, name):
        assert name in _WEBSHELL_NAMES

    def test_is_frozenset(self):
        assert isinstance(_WEBSHELL_NAMES, frozenset)

    def test_not_empty(self):
        assert len(_WEBSHELL_NAMES) > 10


# ============================================================================
# TestWellKnownDns
# ============================================================================

class TestWellKnownDns:
    """Tests for the _WELL_KNOWN_DNS constant."""

    @pytest.mark.parametrize("ip", ['8.8.8.8', '1.1.1.1', '9.9.9.9'])
    def test_major_dns_present(self, ip):
        assert ip in _WELL_KNOWN_DNS

    def test_google_secondary_present(self):
        assert '8.8.4.4' in _WELL_KNOWN_DNS

    def test_cloudflare_secondary_present(self):
        assert '1.0.0.1' in _WELL_KNOWN_DNS

    def test_is_frozenset(self):
        assert isinstance(_WELL_KNOWN_DNS, frozenset)

    def test_random_ip_not_present(self):
        assert '203.0.113.53' not in _WELL_KNOWN_DNS
