"""Tests for device name extraction from structure_analyzer."""

from __future__ import annotations

from pathlib import Path

from src.models import Architecture, DisassemblyResult, Function
from src.analysis.core.structure_analyzer import extract_device_names


class TestExtractDeviceNames:
    """Test kernel device name extraction from IR strings and API patterns."""

    def test_device_string_extraction(self):
        """\\Device\\MyDriver should yield \\\\.\\MyDriver."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = [
            "\\Device\\MyDriver",
            "\\DosDevices\\MyDriverLink",
            "Some other string",
        ]

        names = extract_device_names(ir)
        assert any("MyDriver" in n for n in names)
        assert any("MyDriverLink" in n for n in names)

    def test_dosdevices_extraction(self):
        """\\DosDevices\\ and \\??\\ patterns should be extracted."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = [
            "\\DosDevices\\TestDevice",
            "\\??\\Global\\MyGlobal",
        ]

        names = extract_device_names(ir)
        assert any("TestDevice" in n for n in names)
        assert any("Global" in n for n in names)

    def test_no_device_names_in_clean_driver(self):
        """Driver with no device strings should fall back to sample name."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = [
            "Copyright 2024",
            "Driver version 1.0",
            "Initialize complete",
        ]

        names = extract_device_names(ir)
        # Falls back to sample name: test -> \\.\test
        assert any("test" in n.lower() for n in names)

    def test_no_duplicates(self):
        """Same device name from multiple sources should appear only once."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = [
            "\\Device\\SameDevice",
            "\\DosDevices\\SameDevice",
        ]

        names = extract_device_names(ir)
        same_count = sum(1 for n in names if "SameDevice" in n)
        assert same_count <= 1

    def test_empty_strings(self):
        """Empty strings list should fall back to sample name."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = []

        names = extract_device_names(ir)
        # Falls back to sample name: test -> \\.\test
        assert any("test" in n.lower() for n in names)
