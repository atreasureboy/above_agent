"""Tests for usermode_parser.py."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.ingestion.usermode_parser import (
    detect_com_interfaces,
    detect_service_entrypoints,
    detect_binary_type,
    detect_dangerous_usermode_imports,
    ingest_usermode,
)


class TestDetectComInterfaces:
    def test_finds_standard_com_exports(self):
        exports = ["DllGetClassObject", "DllCanUnloadNow", "SomeOtherExport"]
        result = detect_com_interfaces(exports)
        assert "DllGetClassObject" in result
        assert "DllCanUnloadNow" in result
        assert len(result) == 2

    def test_no_com_exports(self):
        exports = ["ServiceMain", "DriverEntry"]
        result = detect_com_interfaces(exports)
        assert result == []


class TestDetectServiceEntrypoints:
    def test_finds_service_exports(self):
        exports = ["ServiceMain", "SomeOtherFunction"]
        result = detect_service_entrypoints(exports)
        assert result["has_service_entry"] is True
        assert "ServiceMain" in result["service_exports"]

    def test_no_service_exports(self):
        exports = ["DllGetClassObject", "SomeFunction"]
        result = detect_service_entrypoints(exports)
        assert result["has_service_entry"] is False


class TestDetectBinaryType:
    def test_dll_detection(self):
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.Characteristics = 0x2000  # IMAGE_FILE_DLL
        result = detect_binary_type(mock_pe, [])
        assert result == "dll"

    def test_exe_detection(self):
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.Characteristics = 0x0100  # Not a DLL
        result = detect_binary_type(mock_pe, [])
        assert result == "exe"


class TestDetectDangerousImports:
    def test_detects_process_injection_apis(self):
        imports = ["kernel32.dll", "ntdll.dll"]
        result = detect_dangerous_usermode_imports(imports)
        assert len(result) >= 1

    def test_detects_service_apis(self):
        imports = ["advapi32.dll", "kernel32.dll"]
        result = detect_dangerous_usermode_imports(imports)
        assert len(result) >= 1

    def test_no_dangerous_imports(self):
        imports = ["user32.dll", "gdi32.dll", "shell32.dll"]
        result = detect_dangerous_usermode_imports(imports)
        assert len(result) == 0


class TestIngestUsermode:
    def _make_mock_pe(self):
        mock_pe = MagicMock()
        mock_pe.FILE_HEADER.Machine = 0x8664  # x64
        mock_pe.FILE_HEADER.Characteristics = 0x2000  # DLL
        mock_pe.FILE_HEADER.TimeDateStamp = 1234567890
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe.OPTIONAL_HEADER.Subsystem = 2  # WINDOWS_GUI
        mock_pe.VS_FIXEDFILEINFO = [MagicMock(
            ProductVersionMS=0x00010002,
            ProductVersionLS=0x00030004,
        )]
        mock_pe.FileInfo = []
        mock_pe.DIRECTORY_ENTRY_IMPORT = []

        # Create proper export symbols with bytes name attribute
        class FakeSymbol:
            def __init__(self, name_bytes):
                self.name = name_bytes
        mock_pe.DIRECTORY_ENTRY_EXPORT = MagicMock()
        mock_pe.DIRECTORY_ENTRY_EXPORT.symbols = [
            FakeSymbol(b"DllGetClassObject"),
            FakeSymbol(b"DllCanUnloadNow"),
        ]
        mock_pe.sections = [MagicMock(Name=b".text\x00\x00\x00")]
        return mock_pe

    @patch("src.ingestion.usermode_parser.pefile.PE")
    @patch("src.ingestion.usermode_parser.verify_signature")
    def test_ingest_usermode_basic(self, mock_verify, mock_pe_cls, tmp_path):
        mock_pe = self._make_mock_pe()
        mock_pe_cls.return_value = mock_pe
        mock_verify.return_value = ("unsigned", "")

        test_file = tmp_path / "test.dll"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        sample = ingest_usermode(test_file)

        assert sample.is_usermode is True
        assert sample.binary_type == "dll"
        assert sample.company == ""
        assert len(sample.com_interfaces) == 2
        assert sample.sha256 is not None
        assert sample.size == 102

    @patch("src.ingestion.usermode_parser.pefile.PE")
    @patch("src.ingestion.usermode_parser.verify_signature")
    def test_ingest_usermode_not_found(self, mock_verify, mock_pe_cls):
        with pytest.raises(FileNotFoundError):
            ingest_usermode(Path("/nonexistent/file.dll"))
