"""Tests for OVOIDA context JSON structure and Agent prompt fields."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile

from src.pipeline import _write_ovoida_context


class TestOvoidaContextStructure:
    """Test that _write_ovoida_context produces the expected fields."""

    def _make_sample_info(self) -> dict:
        return {
            "name": "TestDrv.sys",
            "path": str(Path("test.sys")),
            "sha256": "abc123",
            "arch": "x64",
            "driver_type": "WDM",
            "company": "Test Corp",
            "entry_point": "0x1000",
            "compile_timestamp": 1234567890,
            "debug_path": "C:\\build\\test.pdb",
            "sections": [".text", ".rdata", ".data"],
            "risk_score": 8.5,
            "risk_level": "HIGH",
            "finding_count": 50,
            "findings": [],
            "functions": [{"address": "0x1000", "name": "DriverEntry"}],
            "ioctl_handlers": {"0x22A004": "sub_2000"},
            "irp_handlers": {"0x0E": "sub_3000"},
            "imports": ["ntoskrnl.exe", "hal.dll"],
            "exports": ["DriverEntry"],
            "strings": ["\\Device\\TestDevice", "\\DosDevices\\TestLink"],
            "disassembly_backend": "capstone",
            "device_names": ["\\\\.\\TestDevice", "\\\\.\\TestLink"],
        }

    def test_context_has_all_required_fields(self):
        """Context JSON should contain all fields the Agent needs."""
        sample_info = self._make_sample_info()

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            ctx_path = _write_ovoida_context(session_dir, sample_info, Path("test.sys"))
            assert ctx_path.exists()

            ctx = json.loads(ctx_path.read_text(encoding="utf-8"))

            # Required top-level fields
            assert "sample" in ctx
            assert "risk_score" in ctx
            assert "risk_level" in ctx
            assert "finding_count" in ctx
            assert "findings" in ctx
            assert "functions" in ctx
            assert "ioctl_handlers" in ctx
            assert "irp_handlers" in ctx
            assert "dangerous_apis" in ctx
            assert "priority_functions" in ctx
            assert "imports" in ctx
            assert "exports" in ctx
            assert "strings_top50" in ctx
            assert "disassembly_backend" in ctx

            # Agent-focused fields
            assert "device_names" in ctx
            assert ctx["device_names"] == ["\\\\.\\TestDevice", "\\\\.\\TestLink"]

    def test_context_sample_fields(self):
        """Sample sub-object should have required fields."""
        sample_info = self._make_sample_info()

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            ctx_path = _write_ovoida_context(session_dir, sample_info, Path("test.sys"))
            ctx = json.loads(ctx_path.read_text(encoding="utf-8"))

            sample = ctx["sample"]
            assert sample["name"] == "TestDrv.sys"
            assert sample["sha256"] == "abc123"
            assert sample["driver_type"] == "WDM"
            assert sample["arch"] == "x64"
            assert sample["debug_path"] == "C:\\build\\test.pdb"

    def test_context_without_device_names(self):
        """Context should handle missing device_names gracefully."""
        sample_info = self._make_sample_info()
        del sample_info["device_names"]

        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            ctx_path = _write_ovoida_context(session_dir, sample_info, Path("test.sys"))
            ctx = json.loads(ctx_path.read_text(encoding="utf-8"))

            assert "device_names" in ctx
            assert ctx["device_names"] == []
