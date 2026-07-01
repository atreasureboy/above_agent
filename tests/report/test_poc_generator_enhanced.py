"""Tests for enhanced PoC generation with API-specific payloads."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.report.poc_generator import (
    generate_poc,
    generate_poc_from_chain,
    _generate_targeted_payload_c,
    _generate_targeted_payload_python,
    _API_PAYLOADS,
    _C_STRUCTS,
    _get_c_struct_def,
    _get_struct_name,
    _get_exploit_value_c,
    _pack_python_struct,
)


@pytest.fixture
def mmmap_chain():
    """Chain with MmMapIoSpaceEx."""
    return {
        "name": "Physical Memory Map",
        "severity": "CRITICAL",
        "function": "0x140001000",
        "dangerous_apis": ["MmMapIoSpaceEx"],
        "validation": "none",
        "user_controllable": True,
        "taint_sources": ["SystemBuffer@0x60"],
        "taint_sinks": ["MmMapIoSpaceEx(rcx)"],
        "method": 0,
        "ioctl_code": 0x22A004,
        "buffer_size": 0x20,
    }


@pytest.fixture
def msrcw_chain():
    """Chain with MSR write."""
    return {
        "name": "MSR Access",
        "severity": "CRITICAL",
        "function": "0x140002000",
        "dangerous_apis": ["KeWriteMsr"],
        "validation": "none",
        "user_controllable": True,
        "taint_sources": ["SystemBuffer@0x10"],
        "taint_sinks": ["KeWriteMsr(rcx, rdx)"],
        "method": 0,
        "ioctl_code": 0x22E004,
        "buffer_size": 0x10,
    }


@pytest.fixture
def unknown_api_chain():
    """Chain with unknown API (fallback to generic payload)."""
    return {
        "name": "Unknown API",
        "severity": "HIGH",
        "function": "0x140003000",
        "dangerous_apis": ["SomeRareAPI"],
        "validation": "partial",
        "user_controllable": False,
        "taint_sources": [],
        "taint_sinks": [],
        "method": 0,
        "ioctl_code": 0x22A004,
        "buffer_size": 0x1000,
    }


class TestTargetedPayloadC:
    """Test C-specific payload generation."""

    def test_mmmap_io_space_payload(self, mmmap_chain):
        """MmMapIoSpaceEx should produce targeted payload."""
        code = _generate_targeted_payload_c(mmmap_chain)
        assert "MmMapIoSpaceEx" in code
        assert "PhysicalAddress" in code
        assert "BYTE inputBuffer" in code

    def test_msr_write_payload(self, msrcw_chain):
        """KeWriteMsr should produce targeted payload."""
        code = _generate_targeted_payload_c(msrcw_chain)
        assert "KeWriteMsr" in code
        assert "MsrIndex" in code

    def test_unknown_api_generic_payload(self, unknown_api_chain):
        """Unknown API should fall back to generic payload."""
        code = _generate_targeted_payload_c(unknown_api_chain)
        assert "Generic payload" in code
        assert "memset" in code


class TestTargetedPayloadPython:
    """Test Python-specific payload generation."""

    def test_mmmap_io_space_python(self, mmmap_chain):
        """MmMapIoSpaceEx Python payload should contain API details."""
        code = _generate_targeted_payload_python(mmmap_chain)
        assert "MmMapIoSpaceEx" in code
        assert "bytearray" in code

    def test_msr_write_python(self, msrcw_chain):
        """KeWriteMsr Python payload."""
        code = _generate_targeted_payload_python(msrcw_chain)
        assert "KeWriteMsr" in code
        assert "MsrIndex" in code


class TestGeneratePocFromChain:
    """Test enhanced PoC generation from exploit chain."""

    def test_generate_c_poc_from_chain(self, mmmap_chain):
        """C PoC from chain should use targeted payload."""
        code = generate_poc_from_chain(mmmap_chain, "TestDrv", format="c")
        assert "CreateFile" in code
        assert "DeviceIoControl" in code
        assert "MmMapIoSpaceEx" in code
        assert "PhysicalAddress" in code  # Targeted payload

    def test_generate_python_poc_from_chain(self, mmmap_chain):
        """Python PoC from chain should use targeted payload."""
        code = generate_poc_from_chain(mmmap_chain, "TestDrv", format="python")
        assert "CreateFileA" in code
        assert "DeviceIoControl" in code
        assert "ctypes" in code
        assert "MmMapIoSpaceEx" in code

    def test_generate_to_file(self, mmmap_chain, tmp_path):
        """PoC can be written to file."""
        out = tmp_path / "poc.py"
        code = generate_poc_from_chain(mmmap_chain, "TestDrv", format="python", output_path=out)
        assert out.exists()
        assert out.read_text(encoding="utf-8") == code

    def test_unsupported_format_raises(self, mmmap_chain):
        """Unsupported format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported format"):
            generate_poc_from_chain(mmmap_chain, "TestDrv", format="rust")


class TestAPIPayloadsExist:
    """Test that API payload templates are defined."""

    def test_known_api_payload_templates(self):
        """Key APIs should have payload templates."""
        expected = {
            "MmMapIoSpaceEx",
            "MmMapLockedPagesSpecifyCache",
            "MmCopyVirtualMemory",
            "ZwLoadDriver",
            "KeWriteMsr",
            "ZwSetInformationProcess",
            "ObReferenceObjectByHandle",
        }
        for api in expected:
            assert api in _API_PAYLOADS, f"Missing payload template for {api}"
            assert "description" in _API_PAYLOADS[api]
            assert "buffer_layout" in _API_PAYLOADS[api]


# ---------------------------------------------------------------------------
# P3: Struct packing tests
# ---------------------------------------------------------------------------

class TestStructPacking:
    """Test P3 struct packing for API-specific PoC generation."""

    def test_c_structs_defined(self):
        """C struct definitions should exist for key APIs."""
        for api in ["MmMapIoSpaceEx", "KeWriteMsr", "ObReferenceObjectByHandle"]:
            assert api in _C_STRUCTS
            assert "typedef struct" in _C_STRUCTS[api]

    def test_get_c_struct_def(self):
        """_get_c_struct_def returns struct for known API."""
        result = _get_c_struct_def("MmMapIoSpaceEx")
        assert "PhysicalAddress" in result
        assert "typedef struct" in result

    def test_get_c_struct_def_unknown(self):
        """_get_c_struct_def returns empty string for unknown API."""
        assert _get_c_struct_def("NonExistentAPI") == ""

    def test_get_struct_name(self):
        """_get_struct_name returns C type name for known APIs."""
        assert _get_struct_name("MmMapIoSpaceEx") == "MM_MAP_IO_SPACE_INPUT"
        assert _get_struct_name("KeWriteMsr") == "MSR_WRITE_INPUT"

    def test_get_exploit_value_c_physical_address(self):
        """_get_exploit_value_c returns LAPIC for physical address."""
        assert _get_exploit_value_c("PhysicalAddress (QWORD)", {}) == "0x0"

    def test_get_exploit_value_c_msr_index(self):
        """_get_exploit_value_c returns LSTAR for MSR index."""
        assert _get_exploit_value_c("MsrIndex (ULONG)", {}) == "0xC0000082"

    def test_get_exploit_value_c_access_mode(self):
        """_get_exploit_value_c returns KernelMode for access mode."""
        assert _get_exploit_value_c("AccessMode", {}) == "0"

    def test_get_exploit_value_c_override(self):
        """_get_exploit_value_c uses chain exploit_values override."""
        chain = {"exploit_values": {"physicaladdress": 0xDEADBEEF}}
        val = _get_exploit_value_c("PhysicalAddress (QWORD)", chain)
        assert "DEADBEEF" in val

    def test_pack_python_struct_mmmap(self):
        """_pack_python_struct generates struct.pack for MmMapIoSpaceEx."""
        result = _pack_python_struct("MmMapIoSpaceEx", {})
        assert result is not None
        full_code = "\n".join(result)
        assert "struct.pack" in full_code
        assert "QII" in full_code  # Format specifier

    def test_pack_python_struct_msr(self):
        """_pack_python_struct generates struct.pack for KeWriteMsr."""
        result = _pack_python_struct("KeWriteMsr", {})
        assert result is not None
        full_code = "\n".join(result)
        assert "C0000082" in full_code  # LSTAR

    def test_pack_python_struct_unknown(self):
        """_pack_python_struct returns None for unknown API."""
        assert _pack_python_struct("NonExistent", {}) is None

    def test_python_payload_contains_struct_pack(self, mmmap_chain):
        """Python targeted payload includes struct.pack code."""
        code = _generate_targeted_payload_python(mmmap_chain)
        assert "struct.pack" in code

    def test_method_neither_annotation(self):
        """METHOD_NEITHER chains get pointer warning in Python payload."""
        chain = {
            "name": "Test",
            "severity": "HIGH",
            "function": "0x1000",
            "dangerous_apis": ["MmMapIoSpaceEx"],
            "method": 3,  # METHOD_NEITHER
            "buffer_size": 0x100,
        }
        code = _generate_targeted_payload_python(chain)
        assert "METHOD_NEITHER" in code

    def test_taint_sources_in_python_payload(self, mmmap_chain):
        """Python payload includes taint source comments."""
        code = _generate_targeted_payload_python(mmmap_chain)
        assert "Taint sources" in code
        assert "SystemBuffer" in code

    def test_taint_sinks_in_python_payload(self, mmmap_chain):
        """Python payload includes taint sink comments."""
        code = _generate_targeted_payload_python(mmmap_chain)
        assert "Taint sinks" in code
        assert "MmMapIoSpaceEx" in code

    def test_c_payload_has_taint_info(self, mmmap_chain):
        """C payload includes taint source/sink comments."""
        code = _generate_targeted_payload_c(mmmap_chain)
        assert "Taint sources" in code
        assert "Taint sinks" in code
