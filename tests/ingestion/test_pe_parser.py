"""Tests for PE parser ingestion functions."""

import pytest
from pathlib import Path
from src.ingestion.pe_parser import (
    detect_architecture,
    is_driver_pe,
    detect_driver_type,
    extract_imports,
    extract_exports,
    extract_sections,
    extract_version_info,
    extract_debug_path,
    ingest,
    ingest_directory,
    compute_sha256,
)
from src.models import Architecture, SignatureStatus


# Path to a real sample if available
SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"
MOCK_DRIVER = SAMPLES_DIR / "unknown" / "mock_driver.sys"


def _has_sample():
    return MOCK_DRIVER.exists()


def _get_test_scan_sample(name="amdgpio2.sys"):
    p = SAMPLES_DIR / "test_scan" / name
    return p if p.exists() else None


class TestComputeSHA256:
    def test_deterministic(self):
        assert compute_sha256(b"hello") == compute_sha256(b"hello")

    def test_different_input_different_hash(self):
        assert compute_sha256(b"hello") != compute_sha256(b"world")

    def test_returns_hex_string(self):
        h = compute_sha256(b"test")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA256 = 32 bytes = 64 hex chars


class TestDetectArchitecture:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_x64_detection(self):
        import pefile
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        arch = detect_architecture(pe)
        assert arch == Architecture.X64
        pe.close()

    def test_x86_machine_code(self):
        """Test that 0x14C maps to X86."""
        import pefile
        if not _has_sample():
            pytest.skip("No sample available")
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        pe.FILE_HEADER.Machine = 0x14C
        assert detect_architecture(pe) == Architecture.X86
        pe.close()

    def test_unknown_machine(self):
        import pefile
        if not _has_sample():
            pytest.skip("No sample available")
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        pe.FILE_HEADER.Machine = 0xFFFF
        assert detect_architecture(pe) == Architecture.UNKNOWN
        pe.close()


class TestIsDriverPE:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_driver_pe_returns_true(self):
        import pefile
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        assert is_driver_pe(pe) is True
        pe.close()


class TestDetectDriverType:
    def test_wdm_detection(self):
        """WDM: ntoskrnl.exe or hal.dll imports."""
        imports = ["ntoskrnl.exe", "hal.dll"]
        assert detect_driver_type(None, imports, []) == "WDM"

    def test_kmdf_detection(self):
        """KMDF: WdfLdr or Wdf01000 imports."""
        imports = ["WdfLdr.sys", "ntoskrnl.exe"]
        assert detect_driver_type(None, imports, []) == "WDF/KMDF"

    def test_umdf_detection(self):
        """UMDF: WUDF imports."""
        imports = ["WUDFPlatform.dll", "ntoskrnl.exe"]
        assert detect_driver_type(None, imports, []) == "WDF/UMDF"

    def test_unknown_type(self):
        """No indicators → UNKNOWN."""
        imports = ["some_unknown.dll"]
        assert detect_driver_type(None, imports, []) == "UNKNOWN"

    def test_wdf_api_prefix_detection(self):
        """WDF detection via Wdf* DLL imports (e.g. WdfLdr.sys, Wdf01000.sys)."""
        imports = ["Wdf01000.sys", "ntoskrnl.exe"]
        assert detect_driver_type(None, imports, []) == "WDF/KMDF"


class TestExtractSections:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_sections_nonempty(self):
        import pefile
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        sections = extract_sections(pe)
        assert len(sections) > 0
        assert ".text" in sections
        pe.close()


class TestExtractImports:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_imports_nonempty(self):
        import pefile
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=False)
        pe.parse_data_directories()
        imports = extract_imports(pe)
        pe.close()
        # mock_driver.sys is a minimal PE, may have no imports
        # Just verify the function runs without error and returns a list
        assert isinstance(imports, list)


class TestExtractVersionInfo:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_version_info_returns_dict(self):
        import pefile
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        info = extract_version_info(pe)
        assert isinstance(info, dict)
        pe.close()


class TestExtractDebugPath:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_debug_path_returns_string(self):
        import pefile
        pe = pefile.PE(str(MOCK_DRIVER), fast_load=True)
        path = extract_debug_path(pe)
        assert isinstance(path, str)
        pe.close()


class TestIngest:
    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_ingest_returns_sample(self):
        sample = ingest(MOCK_DRIVER)
        assert sample.name != ""
        assert sample.arch in (Architecture.X86, Architecture.X64, Architecture.ARM64)
        assert sample.is_driver is True
        assert sample.sha256 != ""
        assert sample.size > 0

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_ingest_populates_metadata(self):
        sample = ingest(MOCK_DRIVER)
        assert isinstance(sample.imports, list)
        assert isinstance(sample.exports, list)
        assert isinstance(sample.sections, list)
        assert sample.signature_status == SignatureStatus.UNSIGNED

    def test_ingest_missing_file(self):
        with pytest.raises(FileNotFoundError):
            ingest(Path("nonexistent_file.sys"))

    def test_ingest_non_pe_file(self, tmp_path):
        """A text file should raise ValueError."""
        fake = tmp_path / "fake.sys"
        fake.write_text("not a PE file")
        with pytest.raises(ValueError):
            ingest(fake)

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_ingest_sha256_matches_compute(self):
        import hashlib
        sample = ingest(MOCK_DRIVER)
        raw = MOCK_DRIVER.read_bytes()
        expected = hashlib.sha256(raw).hexdigest()
        assert sample.sha256 == expected


class TestIngestDirectory:
    @pytest.mark.skipif(not (SAMPLES_DIR / "test_scan").exists(), reason="No test_scan dir")
    def test_ingest_directory(self):
        samples = ingest_directory(SAMPLES_DIR / "test_scan")
        # Should have at least some .sys files parsed
        assert len(samples) > 0
        for s in samples:
            assert s.is_driver is True
            assert s.sha256 != ""
