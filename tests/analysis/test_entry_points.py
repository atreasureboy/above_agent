"""Tests for Phase 1: Entry point expansion (FastIO, WMI, MiniFilter, PnP/Power, MMIO)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.models import (
    APICallInfo,
    Architecture,
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Severity,
    SignatureStatus,
)


def _make_mock_ir() -> DisassemblyResult:
    """Create a mock IR with basic functions, CFG, and API calls."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

    handler = Function(name="sub_1000", address=0x1000, size=0x200)
    handler.calls = [0x2000]
    ir.functions[0x1000] = handler

    helper = Function(name="sub_2000", address=0x2000, size=0x100)
    ir.functions[0x2000] = helper

    cfg = CFG(function_address=0x1000, entry_block=0x1000)
    block = BasicBlock(
        address=0x1000,
        end_address=0x1200,
        instructions=[
            Instruction(address=0x1010, mnemonic="mov", operands="rax, rcx", size=3),
            Instruction(
                address=0x1020, mnemonic="call", operands="MmMapIoSpaceEx",
                api_target="MmMapIoSpaceEx", size=6,
            ),
        ],
        successors=[0x2000],
    )
    cfg.blocks[0x1000] = block
    ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

    ir.function_apis[0x1000] = ["MmMapIoSpaceEx"]
    ir.function_api_details[0x1000] = [
        APICallInfo(name="MmMapIoSpaceEx", call_address=0x1020),
    ]

    ir.ioctl_handlers[0x22A004] = 0x1000
    ir.irp_handlers[0xE] = 0x1000

    return ir


def _make_mock_sample() -> Sample:
    """Create a mock Sample."""
    return Sample(
        path=Path("test.sys"),
        name="TestDriver",
        company="TestCo",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=0x10000,
    )


# ---------------------------------------------------------------------------
# FastIO Detection Tests
# ---------------------------------------------------------------------------

class TestFastIODetection:
    """Test FastIO dispatch detection in capstone backend."""

    def test_fastio_device_control_offset_detected(self):
        """mov [reg+0x28], handler should populate fastio_handlers."""
        from src.disassembly.capstone_backend import CapstoneBackend

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.functions = {}
        ir.function_apis = {}

        insn = Instruction(
            address=0x500, mnemonic="mov",
            operands="qword ptr [rax + 0x28], 0x6000", size=7,
        )
        all_insns = {0x500: insn}

        backend = CapstoneBackend()
        backend._detect_fastio_patterns(
            MagicMock(), all_insns, ir.functions, ir
        )

        assert 0x28 in ir.fastio_handlers
        assert ir.fastio_handlers[0x28] == 0x500

    def test_fastio_read_offset_detected(self):
        """mov [reg+0x08], handler should populate fastio_handlers."""
        from src.disassembly.capstone_backend import CapstoneBackend

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        insn = Instruction(
            address=0x700, mnemonic="mov",
            operands="qword ptr [rbx + 0x8], 0x8000", size=7,
        )

        backend = CapstoneBackend()
        backend._detect_fastio_patterns(
            MagicMock(), {0x700: insn}, {}, ir
        )

        assert 0x08 in ir.fastio_handlers

    def test_fastio_does_not_conflict_with_irp_handlers(self):
        """FastIO detection should not overwrite existing IRP handler matches."""
        from src.disassembly.capstone_backend import CapstoneBackend

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.irp_handlers[0xE] = 0x300  # Existing IOCTL handler

        insn = Instruction(
            address=0x300, mnemonic="mov",
            operands="qword ptr [rax + 0x70], 0x1000", size=7,
        )

        backend = CapstoneBackend()
        backend._detect_fastio_patterns(
            MagicMock(), {0x300: insn}, {}, ir
        )

        # Should still have IRP handler intact
        assert ir.irp_handlers[0xE] == 0x300


# ---------------------------------------------------------------------------
# WMI / PnP / Power Detection Tests
# ---------------------------------------------------------------------------

class TestWmiPnpPowerDetection:
    """Test WMI, PnP, Power IRP handler detection."""

    def test_irp_mj_system_control_detected(self):
        """mov [reg+0xF0] should be detected as IRP_MJ_SYSTEM_CONTROL."""
        from src.disassembly.capstone_backend import CapstoneBackend

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        insn = Instruction(
            address=0x400, mnemonic="mov",
            operands="qword ptr [rcx + 0xF0], 0x5000", size=7,
        )

        backend = CapstoneBackend()
        backend._detect_wdm_patterns(
            MagicMock(), {0x400: insn}, {}, ir
        )

        assert 0x1E in ir.irp_handlers  # IRP_MJ_SYSTEM_CONTROL

    def test_irp_mj_pnp_detected(self):
        """mov [reg+0xD8] should be detected as IRP_MJ_PNP."""
        from src.disassembly.capstone_backend import CapstoneBackend

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        insn = Instruction(
            address=0x410, mnemonic="mov",
            operands="qword ptr [rdx + 0xD8], 0x6000", size=7,
        )

        backend = CapstoneBackend()
        backend._detect_wdm_patterns(
            MagicMock(), {0x410: insn}, {}, ir
        )

        assert 0x1B in ir.irp_handlers  # IRP_MJ_PNP

    def test_irp_mj_power_detected(self):
        """mov [reg+0xE0] should be detected as IRP_MJ_POWER."""
        from src.disassembly.capstone_backend import CapstoneBackend

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        insn = Instruction(
            address=0x420, mnemonic="mov",
            operands="qword ptr [r8 + 0xE0], 0x7000", size=7,
        )

        backend = CapstoneBackend()
        backend._detect_wdm_patterns(
            MagicMock(), {0x420: insn}, {}, ir
        )

        assert 0x1C in ir.irp_handlers  # IRP_MJ_POWER

    def test_pnp_handler_with_dangerous_api_flagged(self):
        """IRP_MJ_PNP handler calling MmMapIoSpace should produce HIGH finding."""
        from src.analysis.core.structure_analyzer import StructureAnalyzer

        ir = _make_mock_ir()
        # Make the handler also a PnP handler
        ir.irp_handlers[0x1B] = 0x1000  # PnP -> same handler with MmMapIoSpaceEx

        sample = _make_mock_sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)

        pnp_findings = [
            f for f in findings
            if f.context.get("irp_name") == "IRP_MJ_PNP"
        ]
        assert len(pnp_findings) >= 1
        # Should be HIGH severity because handler has dangerous API
        high_pnp = [f for f in pnp_findings if f.severity == Severity.HIGH]
        assert len(high_pnp) >= 1


# ---------------------------------------------------------------------------
# MiniFilter Detection Tests
# ---------------------------------------------------------------------------

class TestMiniFilterDetection:
    """Test MiniFilter callback detection."""

    def test_minifilter_flagged_by_api(self):
        """FltRegisterFilter import should set is_minifilter=True."""
        from src.disassembly.minifilter_detector import detect_minifilter

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.function_apis[0x3000] = ["FltRegisterFilter", "FltStartFiltering"]

        detect_minifilter(ir)

        assert ir.is_minifilter

    def test_minifilter_device_control_callback(self):
        """FltRegisterFilter + mov [reg+0x78] should populate minifilter_handlers."""
        from src.disassembly.minifilter_detector import detect_minifilter

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.function_apis[0x3000] = ["FltRegisterFilter"]

        # Add a function with callback struct setup
        func = Function(name="sub_4000", address=0x4000, size=0x200)
        ir.functions[0x4000] = func

        cfg = CFG(function_address=0x4000, entry_block=0x4000)
        block = BasicBlock(
            address=0x4000, end_address=0x4200,
            instructions=[
                Instruction(
                    address=0x4010, mnemonic="mov",
                    operands="qword ptr [rax + 0x78], 0x5000", size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x4000] = block
        ir.cfgs[0x4000] = cfg

        detect_minifilter(ir)

        assert ir.is_minifilter
        assert 0x78 in ir.minifilter_handlers  # DeviceControl callback

    def test_non_minifilter_unchanged(self):
        """Driver without FltRegisterFilter should not be marked as minifilter."""
        from src.disassembly.minifilter_detector import detect_minifilter

        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.function_apis[0x3000] = ["MmMapIoSpaceEx", "ExAllocatePoolWithTag"]

        detect_minifilter(ir)

        assert not ir.is_minifilter
        assert len(ir.minifilter_handlers) == 0


# ---------------------------------------------------------------------------
# Entry Point Reachability Tests
# ---------------------------------------------------------------------------

class TestEntryPointReachability:
    """Test that _is_ioctl_reachable considers all entry point types."""

    def test_fastio_handler_considered_reachable(self):
        """Function that IS a FastIO handler should be reachable."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        ir.fastio_handlers[0x28] = 0x1000  # FastIO handler

        analyzer = DangerousPrimitiveAnalyzer()
        assert analyzer._is_ioctl_reachable(0x1000, ir)

    def test_minifilter_callback_considered_reachable(self):
        """Function that IS a MiniFilter callback should be reachable."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        ir.is_minifilter = True
        ir.minifilter_handlers[0x78] = 0x1000

        analyzer = DangerousPrimitiveAnalyzer()
        assert analyzer._is_ioctl_reachable(0x1000, ir)

    def test_wmi_handler_considered_reachable(self):
        """IRP_MJ_SYSTEM_CONTROL handler should be reachable."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        ir.irp_handlers[0x1E] = 0x1000

        analyzer = DangerousPrimitiveAnalyzer()
        assert analyzer._is_ioctl_reachable(0x1000, ir)

    def test_pnp_handler_considered_reachable(self):
        """IRP_MJ_PNP handler should be reachable."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        ir.irp_handlers[0x1B] = 0x1000

        analyzer = DangerousPrimitiveAnalyzer()
        assert analyzer._is_ioctl_reachable(0x1000, ir)

    def test_power_handler_considered_reachable(self):
        """IRP_MJ_POWER handler should be reachable."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        ir.irp_handlers[0x1C] = 0x1000

        analyzer = DangerousPrimitiveAnalyzer()
        assert analyzer._is_ioctl_reachable(0x1000, ir)


# ---------------------------------------------------------------------------
# MMIO Surface Tests
# ---------------------------------------------------------------------------

class TestMMIOSurface:
    """Test MMIO surface detection."""

    def test_mmio_surface_recorded(self):
        """Function with MmMapIoSpace should appear in mmio_surfaces."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        sample = _make_mock_sample()

        analyzer = DangerousPrimitiveAnalyzer()
        analyzer.analyze(sample, ir)

        assert len(ir.mmio_surfaces) >= 1
        assert any(
            "MmMapIoSpaceEx" in s["apis"]
            for s in ir.mmio_surfaces
        )

    def test_mmio_surface_entry_point_flag(self):
        """MMIO surface reachable from IOCTL should have is_entry_point=True."""
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer

        ir = _make_mock_ir()
        sample = _make_mock_sample()

        analyzer = DangerousPrimitiveAnalyzer()
        analyzer.analyze(sample, ir)

        entry_mmio = [s for s in ir.mmio_surfaces if s["is_entry_point"]]
        assert len(entry_mmio) >= 1


# ---------------------------------------------------------------------------
# IR Model Field Tests
# ---------------------------------------------------------------------------

class TestIRModelFields:
    """Test that new DisassemblyResult fields exist and have correct defaults."""

    def test_disassembly_result_has_new_fields(self):
        """DisassemblyResult should have Phase 1 fields."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        assert hasattr(ir, "fastio_handlers")
        assert hasattr(ir, "wmi_handlers")
        assert hasattr(ir, "minifilter_handlers")
        assert hasattr(ir, "is_minifilter")
        assert hasattr(ir, "mmio_surfaces")

        assert ir.fastio_handlers == {}
        assert ir.wmi_handlers == {}
        assert ir.minifilter_handlers == {}
        assert ir.is_minifilter is False
        assert ir.mmio_surfaces == []

    def test_new_finding_categories_exist(self):
        """New FindingCategory enum values should exist."""
        assert FindingCategory.FASTIO_DISPATCHER_FOUND.value == "fastio_dispatcher"
        assert FindingCategory.WMI_HANDLER_FOUND.value == "wmi_handler"
        assert FindingCategory.MINIFILTER_CALLBACK_FOUND.value == "minifilter_callback"
        assert FindingCategory.MMIO_SURFACE.value == "mmio_surface"
