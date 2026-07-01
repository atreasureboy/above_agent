"""Tests for Ghidra backend: dynamic import resolution integration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.disassembly.ghidra_backend import GhidraBackend
from src.models import DisassemblyResult


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_ghidra_raw(
    functions=None,
    api_calls=None,
    imports=None,
    image_base=0x140000000,
    cfg_blocks=None,
    wide_strings=None,
    data_structures=None,
):
    """Build a minimal Ghidra JSON output dict."""
    raw = {
        "functions": functions or [],
        "api_calls": api_calls or [],
        "strings": [],
        "wide_strings": wide_strings or [],
        "imports": imports or [],
        "exports": [],
        "cfg_blocks": cfg_blocks or [],
        "calls": [],
        "entry_point": 0x1000,
        "architecture": "x86_64",
        "image_base": image_base,
        "data_xrefs": [],
        "data_structures": data_structures or [],
    }
    return raw


def _make_function(addr=0x1000, name="DriverEntry", size=0x100, is_entry=True):
    return {"addr": addr, "name": name, "size": size, "is_entry": is_entry}


def _make_insn_data(addr, mnemonic, operands, api=None):
    d = {"addr": addr, "mnemonic": mnemonic, "operands": operands}
    if api:
        d["api"] = api
    return d


def _make_cfg_block(func_addr, instructions):
    return {
        "_func_addr": func_addr,
        "block_addr": func_addr,
        "successors": [],
        "instructions": instructions,
    }


# ------------------------------------------------------------------
# Test _build_disassembly_result sets image_base
# ------------------------------------------------------------------

class TestGhidraImageBase:
    def test_image_base_populated(self):
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            image_base=0xFFFFF80012340000,
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))
        assert result.image_base == 0xFFFFF80012340000

    def test_image_base_default_zero(self):
        raw = _make_ghidra_raw(functions=[_make_function()])
        del raw["image_base"]
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))
        assert result.image_base == 0


# ------------------------------------------------------------------
# Test dynamic imports are resolved when MmGetSystem present
# ------------------------------------------------------------------

class TestGhidraDynamicImports:
    def test_dynamic_imports_resolved_with_mmgetsystem(self):
        """When Ghidra output contains MmGetSystemRoutineAddress import,
        scan_for_dynamic_imports should be called and produce results."""
        raw = _make_ghidra_raw(
            functions=[_make_function(0x1000, "sub_1000")],
            imports=["ntoskrnl.MmGetSystemRoutineAddress"],
            cfg_blocks=[
                _make_cfg_block(0x1000, [
                    _make_insn_data(0x1050, "lea", "rcx, [rip+0x500]"),
                    _make_insn_data(0x1060, "call", "qword ptr [rip+0x100]"),
                ]),
            ],
            image_base=0x140000000,
        )
        backend = GhidraBackend()

        # scan_for_dynamic_imports is imported inside the method,
        # so patch at the api_resolver module level
        with patch("src.disassembly.api_resolver.scan_for_dynamic_imports") as mock_scan:
            result = backend._build_disassembly_result(raw, Path("dummy.sys"))
            assert mock_scan.called
            assert isinstance(result.dynamic_imports, dict)

    def test_no_crash_without_ghidra_available(self):
        """_build_disassembly_result should not crash even when
        scan_for_dynamic_imports raises."""
        raw = _make_ghidra_raw(functions=[_make_function()])
        backend = GhidraBackend()

        # Corrupt the data to make scan fail — should still not crash
        raw["image_base"] = None
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))
        assert result is not None
        assert isinstance(result, DisassemblyResult)

    def test_dynamic_imports_empty_without_mmgetsystem(self):
        """Without MmGetSystemRoutineAddress import, no dynamic imports."""
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            imports=["ntoskrnl.IoCreateDevice"],
            cfg_blocks=[
                _make_cfg_block(0x1000, [
                    _make_insn_data(0x1050, "call", "qword ptr [rip+0x100]"),
                ]),
            ],
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))
        assert result.dynamic_imports == {}


# ------------------------------------------------------------------
# Test Ghidra instruction-level API targets preserved
# ------------------------------------------------------------------

class TestGhidraApiTargets:
    def test_api_target_on_instruction(self):
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            api_calls=[{
                "func_addr": 0x1000,
                "api_name": "ntoskrnl.IoCreateDevice",
                "call_addr": 0x1050,
            }],
            cfg_blocks=[
                _make_cfg_block(0x1000, [
                    _make_insn_data(0x1050, "call", "qword ptr [rip+0x100]", api="ntoskrnl.IoCreateDevice"),
                ]),
            ],
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))

        # Check instruction has api_target
        for cfg in result.cfgs.values():
            for block in cfg.blocks.values():
                for insn in block.instructions:
                    if insn.address == 0x1050:
                        assert insn.api_target == "IoCreateDevice"

    def test_function_apis_populated(self):
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            api_calls=[{
                "func_addr": 0x1000,
                "api_name": "ntoskrnl.IoCreateDevice",
                "call_addr": 0x1050,
            }],
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))

        assert 0x1000 in result.function_apis
        assert "IoCreateDevice" in result.function_apis[0x1000]


# ------------------------------------------------------------------
# Test wide strings extraction (for MemoryMapAnalyzer, whitelist detection)
# ------------------------------------------------------------------

class TestGhidraWideStrings:
    def test_wide_strings_populated(self):
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            wide_strings=[
                {"string": "explorer.exe", "section": ".rdata", "rva": 0x1000},
                {"string": "\\Device\\MyDriver", "section": ".rdata", "rva": 0x1010},
                {"string": "C:\\Program Files\\360", "section": ".rdata", "rva": 0x1020},
            ],
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))

        assert len(result.wide_strings) == 3
        assert result.wide_strings[0]["string"] == "explorer.exe"
        assert result.wide_strings[0]["rva"] == 0x1000
        assert result.wide_strings[1]["section"] == ".rdata"


# ------------------------------------------------------------------
# Test data structures extraction (for MemoryMapAnalyzer, dispatch tables)
# ------------------------------------------------------------------

class TestGhidraDataStructures:
    def test_data_structures_populated(self):
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            data_structures=[
                {
                    "rva": 0x2000,
                    "type": "qword_array",
                    "section": ".rdata",
                    "element_count": 8,
                    "values": ["0x5000", "0x5100", "0x5200", "0x5300"],
                },
                {
                    "rva": 0x3000,
                    "type": "dword_array",
                    "section": ".rdata",
                    "element_count": 16,
                    "values": ["0x100", "0x200", "0x300", "0x400"],
                },
            ],
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))

        assert 0x2000 in result.data_structures
        assert result.data_structures[0x2000]["type"] == "qword_array"
        assert result.data_structures[0x2000]["element_count"] == 8
        assert 0x3000 in result.data_structures
        assert result.data_structures[0x3000]["type"] == "dword_array"


# ------------------------------------------------------------------
# Test multi-method import extraction
# ------------------------------------------------------------------

class TestGhidraImportExtraction:
    def test_imports_mapped_to_addresses(self):
        """Imports should be mapped to incrementing IAT addresses."""
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            imports=[
                "ntoskrnl.IoCreateDevice",
                "ntoskrnl.IoDeleteDevice",
                "ntoskrnl.ZwCreateFile",
                "hal.KeInitializeEvent",
            ],
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))

        assert len(result.import_addresses) == 4
        assert result.import_addresses[0x1000] == "ntoskrnl.IoCreateDevice"
        assert result.import_addresses[0x1008] == "ntoskrnl.IoDeleteDevice"
        assert result.import_addresses[0x1010] == "ntoskrnl.ZwCreateFile"
        assert result.import_addresses[0x1018] == "hal.KeInitializeEvent"

    def test_many_imports_no_collision(self):
        """69+ imports (like 360 drivers) should all be mapped uniquely."""
        imports = ["ntoskrnl.Api%d" % i for i in range(70)]
        raw = _make_ghidra_raw(
            functions=[_make_function()],
            imports=imports,
        )
        backend = GhidraBackend()
        result = backend._build_disassembly_result(raw, Path("dummy.sys"))

        assert len(result.import_addresses) == 70
        # All addresses should be unique
        addrs = list(result.import_addresses.keys())
        assert len(addrs) == len(set(addrs))
