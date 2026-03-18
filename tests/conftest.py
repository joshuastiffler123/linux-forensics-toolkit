"""
Shared fixtures for the Linux Forensics Toolkit test suite.
"""

import io
import json
import os
import tarfile
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Synthetic UAC tarball
# ---------------------------------------------------------------------------

_HOSTNAME_CONTENT = b"testhost\n"
_AUTH_LOG_CONTENT = b"Jun  1 12:00:00 testhost sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2\n"
_PASSWD_CONTENT = b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes):
    """Helper: add an in-memory file to a tarfile."""
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


@pytest.fixture
def sample_tarball(tmp_path):
    """Create a minimal synthetic UAC .tar.gz for testing.

    Structure::

        testhost-uac/etc/hostname
        testhost-uac/etc/passwd
        testhost-uac/var/log/auth.log
    """
    tarball_path = tmp_path / "testhost-uac.tar.gz"
    with tarfile.open(str(tarball_path), "w:gz") as tar:
        _add_bytes(tar, "testhost-uac/etc/hostname", _HOSTNAME_CONTENT)
        _add_bytes(tar, "testhost-uac/etc/passwd", _PASSWD_CONTENT)
        _add_bytes(tar, "testhost-uac/var/log/auth.log", _AUTH_LOG_CONTENT)
    return tarball_path


# ---------------------------------------------------------------------------
# Extracted UAC directory
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_uac_dir(tmp_path):
    """Create a minimal extracted UAC directory structure on disk."""
    base = tmp_path / "testhost-extracted"
    (base / "etc").mkdir(parents=True)
    (base / "var" / "log").mkdir(parents=True)

    (base / "etc" / "hostname").write_text("testhost\n")
    (base / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    )
    (base / "var" / "log" / "auth.log").write_text(
        "Jun  1 12:00:00 testhost sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2\n"
    )
    return base


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
