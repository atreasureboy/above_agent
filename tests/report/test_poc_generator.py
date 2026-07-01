"""Tests for PoC generator."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.report.poc_generator import (
    generate_poc,
    _generate_c_poc,
    _generate_python_poc,
    _extract_ioctl_code,
    _extract_method,
)


@pytest.fixture
def sample_chain():
    return {
        "name": "TestDriver",
        "severity": "CRITICAL",
        "function": "0x140001000",
        "dangerous_apis": ["MmMapIoSpaceEx"],
        "validation": "none",
        "user_controllable": True,
        "taint_sources": ["SystemBuffer@0x60"],
        "taint_sinks": ["MmMapIoSpaceEx(rcx)"],
        "method": 0,
        "ioctl_code": 0x22A004,
        "buffer_size": 0x1000,
    }


class TestPoCGenerator:
    """Test PoC generation."""

    def test_generate_c_poc(self, sample_chain):
        """C PoC contains essential elements."""
        code = generate_poc([sample_chain], device_name="TestDrv", format="c")
        assert "CreateFile" in code
        assert "DeviceIoControl" in code
        assert "MmMapIoSpaceEx" in code
        assert "TestDrv" in code
        assert "0x22A004" in code
        assert "SystemBuffer" in code
        assert "METHOD_BUFFERED" in code

    def test_generate_python_poc(self, sample_chain):
        """Python PoC contains essential elements."""
        code = generate_poc([sample_chain], device_name="TestDrv", format="python")
        assert "CreateFileA" in code
        assert "DeviceIoControl" in code
        assert "MmMapIoSpaceEx" in code
        assert "TestDrv" in code
        assert "ctypes" in code
        assert "kernel32" in code

    def test_generate_empty_chains(self):
        """No chains produces a 'no chains' message."""
        code = generate_poc([], device_name="TestDrv", format="c")
        assert "No exploit chains detected" in code

    def test_generate_to_file(self, sample_chain, tmp_path):
        """PoC can be written to a file."""
        out = tmp_path / "poc.c"
        code = generate_poc([sample_chain], device_name="TestDrv", format="c", output_path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == code

    def test_unsupported_format(self, sample_chain):
        """Unsupported format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported format"):
            generate_poc([sample_chain], device_name="TestDrv", format="rust")

    def test_extract_ioctl_code_default(self):
        """Default IOCTL code when not specified."""
        code = _extract_ioctl_code({})
        assert code == 0x22A004

    def test_extract_method_buffered(self):
        """Method 0 is METHOD_BUFFERED."""
        assert _extract_method({"method": 0}) == "METHOD_BUFFERED"

    def test_extract_method_neither(self):
        """Method 3 is METHOD_NEITHER."""
        assert _extract_method({"method": 3}) == "METHOD_NEITHER"

    def test_extract_method_unknown(self):
        """Unknown method code returns descriptive string."""
        assert "UNKNOWN" in _extract_method({"method": 99})


class TestWdfIoctlExtraction:
    """Test WDF real IOCTL code extraction."""

    def _make_mock_instruction(self, address, mnemonic, operands, api_target=None):
        """Create a mock instruction."""
        from src.models import Instruction
        return Instruction(
            address=address,
            mnemonic=mnemonic,
            operands=operands,
            api_target=api_target or "",
        )

    def test_extract_real_ioctl_code_pattern(self):
        """WDF handler with WdfRequestGetIoControlCode + cmp pattern."""
        from src.analysis.core.structure_analyzer import StructureAnalyzer
        from src.models import BasicBlock, CFG, DisassemblyResult, Function

        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.is_wdf_driver = True

        handler_addr = 0x1000
        handler = Function(name="EvtIoDeviceControl", address=handler_addr, size=0x200)
        ir.functions[handler_addr] = handler

        cfg = CFG(function_address=handler_addr, entry_block=handler_addr)
        block = BasicBlock(
            address=handler_addr,
            end_address=handler_addr + 0x100,
            instructions=[
                self._make_mock_instruction(0x1010, "call", "WdfRequestGetIoControlCode", "WdfRequestGetIoControlCode"),
                self._make_mock_instruction(0x1020, "mov", "r12, rax"),
                self._make_mock_instruction(0x1030, "cmp", "r12, 0x22A004"),
                self._make_mock_instruction(0x1040, "jne", "0x1100"),
            ],
            successors=[handler_addr + 0x100],
        )
        cfg.blocks[handler_addr] = block
        ir.cfgs[handler_addr] = ir.simple_cfgs[handler_addr] = cfg

        dispatch = {0x100000 | handler_addr: [handler_addr]}
        StructureAnalyzer._extract_wdf_real_ioctl_codes(ir, dispatch)

        # Should have extracted the real IOCTL code
        assert 0x22A004 in dispatch
        assert 0x22A004 in ir.ioctl_handlers
