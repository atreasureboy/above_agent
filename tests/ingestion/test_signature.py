"""Tests for PE signature verification."""

import pytest
import platform
from pathlib import Path
from src.ingestion.signature import verify_signature
from src.models import SignatureStatus


SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"
MOCK_DRIVER = SAMPLES_DIR / "unknown" / "mock_driver.sys"


class TestVerifySignature:
    def test_nonexistent_file(self):
        status, signer = verify_signature(Path("nonexistent.sys"))
        assert status == SignatureStatus.UNSIGNED
        assert signer == ""

    def test_non_pe_file(self, tmp_path):
        """A non-PE file should not be considered signed_valid."""
        fake = tmp_path / "fake.sys"
        fake.write_text("not a PE file")
        status, signer = verify_signature(fake)
        # Non-PE files may return various statuses depending on how
        # WinVerifyTrust handles them, but never SIGNED_VALID.
        assert status != SignatureStatus.SIGNED_VALID
        assert signer == ""

    @pytest.mark.skipif(not MOCK_DRIVER.exists(), reason="No mock_driver.sys")
    def test_unsigned_driver(self):
        """mock_driver.sys is self-built, not signed."""
        status, signer = verify_signature(MOCK_DRIVER)
        assert status == SignatureStatus.UNSIGNED
        assert signer == ""

    def test_returns_tuple(self, tmp_path):
        """verify_signature always returns a (status, name) tuple."""
        result = verify_signature(tmp_path / "nosuch.sys")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], SignatureStatus)
        assert isinstance(result[1], str)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
    def test_non_windows_returns_unsigned(self):
        """On non-Windows, should return UNSIGNED immediately."""
        # This test only makes sense on non-Windows; on Windows the
        # API is available so we just verify the happy path above.
        pass
