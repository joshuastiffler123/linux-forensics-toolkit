"""Tests for the miscellaneous artifacts collector."""

import pytest
from lft.analyzers.misc import (
    ARCHIVE_MAGIC,
    ARCHIVE_EXTENSIONS,
    TAR_MAGIC,
    TAR_MAGIC_OFFSET,
    CRON_PATHS,
    MiscArtifactsCollector,
)


class TestArchiveMagicConstants:
    """Verify archive magic byte definitions."""

    def test_zip_magic(self):
        assert b'PK\x03\x04' in ARCHIVE_MAGIC
        assert ARCHIVE_MAGIC[b'PK\x03\x04'] == 'zip'

    def test_gzip_magic(self):
        assert b'\x1f\x8b' in ARCHIVE_MAGIC
        assert ARCHIVE_MAGIC[b'\x1f\x8b'] == 'gzip'

    def test_bzip2_magic(self):
        assert b'BZh' in ARCHIVE_MAGIC
        assert ARCHIVE_MAGIC[b'BZh'] == 'bzip2'

    def test_xz_magic(self):
        assert b'\xfd7zXZ\x00' in ARCHIVE_MAGIC
        assert ARCHIVE_MAGIC[b'\xfd7zXZ\x00'] == 'xz'

    def test_seven_zip_magic(self):
        assert b'7z\xbc\xaf\x27\x1c' in ARCHIVE_MAGIC
        assert ARCHIVE_MAGIC[b'7z\xbc\xaf\x27\x1c'] == '7z'

    def test_rar_magic(self):
        assert b'Rar!\x1a\x07' in ARCHIVE_MAGIC
        assert ARCHIVE_MAGIC[b'Rar!\x1a\x07'] == 'rar'

    def test_tar_magic_at_offset_257(self):
        assert TAR_MAGIC == b'ustar'
        assert TAR_MAGIC_OFFSET == 257


class TestArchiveExtensions:
    """Verify common archive extensions are tracked."""

    @pytest.mark.parametrize("ext", [
        '.zip', '.7z', '.rar', '.tar', '.tar.gz', '.tgz',
        '.tar.bz2', '.tar.xz', '.gz', '.bz2', '.xz',
        '.deb', '.rpm', '.jar', '.iso',
    ])
    def test_extension_present(self, ext):
        assert ext in ARCHIVE_EXTENSIONS


class TestCronPaths:
    """Verify cron path coverage."""

    def test_system_crontab(self):
        assert 'etc/crontab' in CRON_PATHS

    def test_cron_d(self):
        assert 'etc/cron.d/' in CRON_PATHS

    def test_user_crontabs(self):
        assert 'var/spool/cron/crontabs/' in CRON_PATHS


class TestMiscArtifactsCollectorDirectory:
    """Test MiscArtifactsCollector with an extracted directory."""

    def test_init_sets_source(self, sample_uac_dir):
        collector = MiscArtifactsCollector(str(sample_uac_dir))
        assert not collector.is_tarball
        assert collector.archive_files == []
        assert collector.hidden_dirs == []
        assert collector.scheduled_tasks == []

    def test_detects_hidden_directory(self, sample_uac_dir):
        """The fixture includes a .malware/ hidden dir."""
        collector = MiscArtifactsCollector(str(sample_uac_dir))
        collector.collect(verbose=False)
        # Should find .malware in the hidden dirs
        found = any('.malware' in d for d in collector.hidden_dirs)
        assert found, f"Expected .malware in {collector.hidden_dirs}"


class TestMiscArtifactsCollectorTarball:
    """Test MiscArtifactsCollector with a tarball."""

    def test_init_tarball(self, sample_tarball):
        collector = MiscArtifactsCollector(str(sample_tarball))
        assert collector.is_tarball
        assert collector.tar is not None
        collector.close()
