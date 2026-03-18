"""Tests for lft_uac — path security, hashing, UACHandler."""

import os

import pytest

from lft.core.uac import (
    is_safe_path,
    calculate_hashes,
    UACHandler,
    CoverageEntry,
)
from lft.core.errors import SourceCorruptError


# ---- Path security ------------------------------------------------------

class TestIsSafePath:
    """is_safe_path prevents path traversal."""

    def test_safe_subpath(self, tmp_path):
        child = os.path.join(str(tmp_path), "subdir", "file.txt")
        assert is_safe_path(str(tmp_path), child) is True

    def test_traversal_rejected(self, tmp_path):
        evil = os.path.join(str(tmp_path), "..", "..", "etc", "passwd")
        assert is_safe_path(str(tmp_path), evil) is False

    def test_same_path_is_safe(self, tmp_path):
        assert is_safe_path(str(tmp_path), str(tmp_path)) is True


# ---- Hashing ------------------------------------------------------------

class TestCalculateHashes:
    """calculate_hashes returns correct MD5 and SHA256."""

    def test_known_hash(self):
        data = b"hello world"
        md5, sha256 = calculate_hashes(data)
        assert md5 == "5eb63bbbe01eeed093cb22bb8f5acdc3"
        assert sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_empty_data(self):
        md5, sha256 = calculate_hashes(b"")
        assert isinstance(md5, str) and len(md5) == 32
        assert isinstance(sha256, str) and len(sha256) == 64


# ---- UACHandler with tarball --------------------------------------------

class TestUACHandlerTarball:
    """UACHandler opens a synthetic tarball and provides file access."""

    def test_detects_tarball(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        assert handler.is_tarball is True

    def test_detects_hostname(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        # Hostname should be detected from path prefix
        assert handler.hostname is not None
        assert len(handler.hostname) > 0
        handler.close()

    def test_get_file_returns_bytes(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        data = handler.get_file("etc/passwd")
        assert data is not None
        assert b"root" in data
        handler.close()

    def test_get_file_nonexistent_returns_none(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        data = handler.get_file("nonexistent/file.txt")
        assert data is None
        handler.close()

    def test_find_files_by_pattern(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        matches = handler.find_files_by_pattern(["auth.log"])
        assert len(matches) >= 1
        paths = [m[0] for m in matches]
        assert any("auth.log" in p for p in paths)
        handler.close()

    def test_find_files_by_suffix(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        matches = handler.find_files_by_suffix(["**/hostname"])
        assert len(matches) >= 1
        # Returns (path, text_content)
        assert any("testhost" in content for _, content in matches)
        handler.close()

    def test_list_directory(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        entries = handler.list_directory("/etc")
        assert len(entries) >= 1
        handler.close()

    def test_context_manager(self, sample_tarball):
        with UACHandler(str(sample_tarball)) as handler:
            assert handler.tar is not None
            data = handler.get_file("etc/hostname")
            assert data is not None

    def test_get_members(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        members = handler.get_members()
        assert len(members) >= 3  # hostname, passwd, auth.log
        handler.close()


# ---- UACHandler with directory ------------------------------------------

class TestUACHandlerDirectory:
    """UACHandler works with extracted directories."""

    def test_detects_directory(self, sample_uac_dir):
        handler = UACHandler(str(sample_uac_dir))
        assert handler.is_tarball is False

    def test_detects_hostname_from_dir(self, sample_uac_dir):
        handler = UACHandler(str(sample_uac_dir))
        assert handler.hostname == "testhost"

    def test_get_file_from_directory(self, sample_uac_dir):
        handler = UACHandler(str(sample_uac_dir))
        data = handler.get_file("etc/passwd")
        assert data is not None
        assert b"root" in data

    def test_find_files_by_pattern_directory(self, sample_uac_dir):
        handler = UACHandler(str(sample_uac_dir))
        matches = handler.find_files_by_pattern(["auth.log"])
        assert len(matches) >= 1


# ---- Coverage tracking --------------------------------------------------

class TestCoverage:
    """Coverage tracking works."""

    def test_add_and_get_coverage(self, sample_tarball):
        handler = UACHandler(str(sample_tarball))
        handler.add_coverage("test", "/etc/passwd", "FOUND", actual="/etc/passwd")
        cov = handler.get_coverage()
        assert len(cov) == 1
        assert cov[0]["category"] == "test"
        assert cov[0]["status"] == "FOUND"
        handler.close()

    def test_coverage_entry_to_dict(self):
        entry = CoverageEntry("cat", "expected", "NOT_FOUND", details="missing")
        d = entry.to_dict()
        assert d["category"] == "cat"
        assert d["status"] == "NOT_FOUND"
        assert d["details"] == "missing"


# ---- Static helpers ------------------------------------------------------

class TestStaticHelpers:
    """Static/class method helpers work correctly."""

    @pytest.mark.parametrize("path,expected", [
        ("file.tar.gz", True),
        ("file.tgz", True),
        ("file.tar.bz2", True),
        ("file.tar.xz", True),
        ("file.tar", True),
        ("file.zip", False),
        ("file.txt", False),
        ("file.csv", False),
    ])
    def test_is_tarball_path(self, path, expected):
        assert UACHandler.is_tarball_path(path) is expected


# ---- Error handling ------------------------------------------------------

class TestUACHandlerErrors:
    """UACHandler raises SourceCorruptError for bad tarballs."""

    def test_corrupt_tarball_raises(self, tmp_path):
        bad = tmp_path / "corrupt.tar.gz"
        bad.write_bytes(b"this is not a tarball")
        with pytest.raises(SourceCorruptError):
            UACHandler(str(bad))
