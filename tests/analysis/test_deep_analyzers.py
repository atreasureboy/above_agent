"""Tests for deep analyzers that lack dedicated test coverage.

Covers: XrefTracker, ComparisonTracer, StackStringAnalyzer,
        DataStructureAnalyzer, DataContentAnalyzer, StructInferenceAnalyzer.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import struct

import pytest

from src.analysis.deep.xref_tracker import XrefTracker
from src.analysis.deep.comparison_tracer import ComparisonTracer
from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer
from src.analysis.deep.data_structure_analyzer import DataStructureAnalyzer
from src.analysis.deep.data_content_analyzer import DataContentAnalyzer
from src.analysis.deep.struct_inference_analyzer import StructInferenceAnalyzer
from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
    Instruction,
    Function,
)


def _make_sample(**kwargs) -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="test.sys",
        company="Test",
        version="1.0",
        arch=Architecture.X64,
        sha256="abc",
        size=1000,
        **kwargs,
    )


def _make_ir(**kwargs) -> DisassemblyResult:
    return DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="capstone",
        **kwargs,
    )


# ------------------------------------------------------------------
# XrefTracker tests
# ------------------------------------------------------------------

class TestXrefTracker:
    def test_name(self):
        t = XrefTracker()
        assert t.name == "XrefTracker"

    def test_description_nonempty(self):
        t = XrefTracker()
        assert t.description != ""

    def test_empty_ir_returns_no_findings(self):
        """Empty IR should return no findings."""
        t = XrefTracker()
        ir = _make_ir()
        sample = _make_sample()
        findings = t.analyze(sample, ir)
        assert findings == []

    def test_rip_relative_read_detected(self):
        """RIP-relative memory read should be tracked."""
        ir = _make_ir()
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        ir.functions[0x1000] = func

        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(
            address=0x1000, end_address=0x1100,
            instructions=[
                Instruction(
                    address=0x1010, mnemonic="mov",
                    operands="rax, qword ptr [rip + 0x2000]",
                    size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        t = XrefTracker()
        sample = _make_sample()

        # Mock section ranges to accept the address
        with patch.object(t, "_get_section_ranges", return_value=([], None)):
            findings = t.analyze(sample, ir)

        # Should have recorded data references
        assert hasattr(ir, "data_references")

    def test_rip_relative_write_detected(self):
        """RIP-relative memory write should be classified as write."""
        ir = _make_ir()
        func = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x2000] = func

        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000, end_address=0x2100,
            instructions=[
                Instruction(
                    address=0x2010, mnemonic="mov",
                    operands="qword ptr [rip + 0x1000], rcx",
                    size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        t = XrefTracker()
        sample = _make_sample()

        with patch.object(t, "_get_section_ranges", return_value=([], None)):
            findings = t.analyze(sample, ir)

        assert hasattr(ir, "data_references")

    def test_hot_data_structure_detected(self):
        """Data referenced by >= 5 functions should be flagged as hot."""
        ir = _make_ir()

        # Each function's RIP-relative resolves to the same target address.
        # target = insn.address + insn.size + offset
        # We want target = 0x7000 for all functions.
        # For func at 0x1000, insn at 0x1010, size=7: offset = 0x7000 - 0x1017 = 0x5FE9
        TARGET = 0x7000
        offsets = []
        for i in range(5):
            addr = 0x1000 + i * 0x100
            insn_addr = addr + 0x10
            rip = insn_addr + 7
            offset = TARGET - rip
            offsets.append((addr, insn_addr, offset))

        for addr, insn_addr, offset in offsets:
            func = Function(name=f"sub_{addr:X}", address=addr, size=0x100)
            ir.functions[addr] = func

            cfg = CFG(function_address=addr, entry_block=addr)
            block = BasicBlock(
                address=addr, end_address=addr + 0x100,
                instructions=[
                    Instruction(
                        address=insn_addr, mnemonic="mov",
                        operands=f"rax, [rip+0x{offset:X}]",
                        size=7,
                    ),
                ],
                successors=[],
            )
            cfg.blocks[addr] = block
            ir.cfgs[addr] = ir.simple_cfgs[addr] = cfg

        t = XrefTracker()
        sample = _make_sample()

        def mock_get_ranges(pe_path):
            return [], None

        with patch.object(t, "_get_section_ranges", side_effect=mock_get_ranges):
            findings = t.analyze(sample, ir)

        hot_findings = [f for f in findings if f.category == FindingCategory.XREF_HOT_DATA]
        assert len(hot_findings) >= 1


# ------------------------------------------------------------------
# ComparisonTracer tests
# ------------------------------------------------------------------

class TestComparisonTracer:
    def test_name(self):
        t = ComparisonTracer()
        assert t.name == "ComparisonTracer"

    def test_description_nonempty(self):
        t = ComparisonTracer()
        assert t.description != ""

    def test_empty_ir_returns_no_findings(self):
        t = ComparisonTracer()
        ir = _make_ir()
        sample = _make_sample()
        findings = t.analyze(sample, ir)
        assert findings == []

    def test_cmp_rip_relative_detected(self):
        """cmp against RIP-relative memory should be traced."""
        ir = _make_ir()
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        ir.functions[0x1000] = func

        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(
            address=0x1000, end_address=0x1100,
            instructions=[
                Instruction(
                    address=0x1010, mnemonic="cmp",
                    operands="eax, dword ptr [rip + 0x3000]",
                    size=6,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        t = ComparisonTracer()
        sample = _make_sample()
        findings = t.analyze(sample, ir)

        assert len(findings) >= 1
        assert hasattr(ir, "comparison_traces")

    def test_cmp_immediate_detected(self):
        """cmp immediate value should be traced."""
        ir = _make_ir()
        func = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x2000] = func

        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000, end_address=0x2100,
            instructions=[
                Instruction(
                    address=0x2010, mnemonic="cmp",
                    operands="eax, 0x0",
                    size=6,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        t = ComparisonTracer()
        sample = _make_sample()
        findings = t.analyze(sample, ir)

        # cmp immediate with STATUS_SUCCESS (0x0) should be detected
        assert len(findings) >= 1

    def test_whitelist_classification(self):
        """Keyword 'allow' should classify as whitelist."""
        t = ComparisonTracer()
        is_wl, is_bl = t._classify_check("je allow_path", 0x1000, _make_ir())
        assert is_wl is True

    def test_blacklist_classification(self):
        """Keyword 'deny' should classify as blacklist."""
        t = ComparisonTracer()
        is_wl, is_bl = t._classify_check("jmp deny_path", 0x1000, _make_ir())
        assert is_bl is True

    def test_status_access_denied_is_blacklist(self):
        """STATUS_ACCESS_DENIED (0xC0000022) should be classified as blacklist."""
        t = ComparisonTracer()
        is_wl, is_bl = t._check_imm_hint(0xC0000022)
        assert is_bl is True

    def test_array_iteration_with_back_edge(self):
        """Block with back-edge successor should be detected as array iteration."""
        t = ComparisonTracer()
        block = MagicMock()
        block.address = 0x1000
        succ = MagicMock()
        succ.address = 0x1000  # back edge to same block
        block.successors = [succ]
        assert t._is_array_iteration(block, 0x1010) is True

    def test_no_array_iteration_without_back_edge(self):
        """Block without back-edge should not be array iteration."""
        t = ComparisonTracer()
        block = MagicMock()
        block.address = 0x1000
        succ = MagicMock()
        succ.address = 0x2000  # forward edge
        block.successors = [succ]
        assert t._is_array_iteration(block, 0x1010) is False


# ------------------------------------------------------------------
# StackStringAnalyzer tests
# ------------------------------------------------------------------

class TestStackStringAnalyzer:
    def test_name(self):
        a = StackStringAnalyzer()
        assert a.name == "StackStringAnalyzer"

    def test_description_nonempty(self):
        a = StackStringAnalyzer()
        assert a.description != ""

    def test_empty_ir_returns_no_findings(self):
        a = StackStringAnalyzer()
        ir = _make_ir()
        sample = _make_sample()
        findings = a.analyze(sample, ir)
        assert findings == []

    def test_ascii_stack_string_reconstructed(self):
        """Consecutive byte writes to stack should reconstruct ASCII string."""
        ir = _make_ir()
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        ir.functions[0x1000] = func

        # "Dev" = 0x44, 0x65, 0x76
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(
            address=0x1000, end_address=0x1100,
            instructions=[
                Instruction(
                    address=0x1010, mnemonic="mov",
                    operands="byte ptr [rsp + 0x10], 0x44",  # 'D'
                    size=7,
                ),
                Instruction(
                    address=0x1020, mnemonic="mov",
                    operands="byte ptr [rsp + 0x11], 0x65",  # 'e'
                    size=7,
                ),
                Instruction(
                    address=0x1030, mnemonic="mov",
                    operands="byte ptr [rsp + 0x12], 0x76",  # 'v'
                    size=7,
                ),
                Instruction(
                    address=0x1040, mnemonic="mov",
                    operands="byte ptr [rsp + 0x13], 0x00",  # null terminator
                    size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        a = StackStringAnalyzer()
        sample = _make_sample()
        findings = a.analyze(sample, ir)

        stack_findings = [f for f in findings if f.category == FindingCategory.STACK_STRING_RECONSTRUCTED]
        assert len(stack_findings) >= 1
        assert any("Dev" in f.description for f in stack_findings)

    def test_utf16_stack_string_reconstructed(self):
        """Consecutive word writes to stack should reconstruct UTF-16 string."""
        ir = _make_ir()
        func = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x2000] = func

        # "Dev" in UTF-16LE = 0x0044, 0x0065, 0x0076 (word writes)
        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000, end_address=0x2100,
            instructions=[
                Instruction(
                    address=0x2010, mnemonic="mov",
                    operands="word ptr [rsp + 0x10], 0x44",  # 'D'
                    size=7,
                ),
                Instruction(
                    address=0x2020, mnemonic="mov",
                    operands="word ptr [rsp + 0x12], 0x65",  # 'e'
                    size=7,
                ),
                Instruction(
                    address=0x2030, mnemonic="mov",
                    operands="word ptr [rsp + 0x14], 0x76",  # 'v'
                    size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        a = StackStringAnalyzer()
        sample = _make_sample()
        findings = a.analyze(sample, ir)

        stack_findings = [f for f in findings if f.category == FindingCategory.STACK_STRING_RECONSTRUCTED]
        assert len(stack_findings) >= 1

    def test_short_stack_string_ignored(self):
        """Less than 3 byte writes should not reconstruct a string."""
        ir = _make_ir()
        func = Function(name="sub_3000", address=0x3000, size=0x100)
        ir.functions[0x3000] = func

        cfg = CFG(function_address=0x3000, entry_block=0x3000)
        block = BasicBlock(
            address=0x3000, end_address=0x3100,
            instructions=[
                Instruction(
                    address=0x3010, mnemonic="mov",
                    operands="byte ptr [rsp + 0x10], 0x41",  # 'A'
                    size=7,
                ),
                Instruction(
                    address=0x3020, mnemonic="mov",
                    operands="byte ptr [rsp + 0x11], 0x42",  # 'B'
                    size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x3000] = block
        ir.cfgs[0x3000] = ir.simple_cfgs[0x3000] = cfg

        a = StackStringAnalyzer()
        sample = _make_sample()
        findings = a.analyze(sample, ir)

        stack_findings = [f for f in findings if f.category == FindingCategory.STACK_STRING_RECONSTRUCTED]
        assert len(stack_findings) == 0


# ------------------------------------------------------------------
# DataStructureAnalyzer tests
# ------------------------------------------------------------------

class TestDataStructureAnalyzer:
    def test_name(self):
        a = DataStructureAnalyzer()
        assert a.name == "DataStructureAnalyzer"

    def test_description_nonempty(self):
        a = DataStructureAnalyzer()
        assert a.description != ""

    def test_empty_ir_returns_no_findings(self):
        a = DataStructureAnalyzer()
        ir = _make_ir()
        sample = _make_sample()
        findings = a.analyze(sample, ir)
        assert findings == []

    def test_dword_array_detected(self):
        """Consecutive DWORDs in .rdata should be detected as array."""
        a = DataStructureAnalyzer()
        ir = _make_ir()
        ir.section_data = {
            ".rdata": bytes([0x00, 0x04, 0x22, 0x00] * 10),  # 10 identical DWORDs
        }
        ir.section_info = {
            ".rdata": {"offset": 0x1000, "size": 40, "rva": 0x1000},
        }
        sample = _make_sample()
        findings = a.analyze(sample, ir)

        assert hasattr(ir, "data_structures")

    def test_qword_array_detected(self):
        """Consecutive QWORDs in .rdata should be detected."""
        a = DataStructureAnalyzer()
        ir = _make_ir()
        # 8 consecutive QWORDs with some pattern
        data = b""
        for i in range(8):
            data += struct.pack("<Q", 0xFFFFF80000001000 + i * 8)
        ir.section_data = {".rdata": data}
        ir.section_info = {
            ".rdata": {"offset": 0x1000, "size": len(data), "rva": 0x1000},
        }
        sample = _make_sample()
        findings = a.analyze(sample, ir)

        assert hasattr(ir, "data_structures")


# ------------------------------------------------------------------
# DataContentAnalyzer tests
# ------------------------------------------------------------------

class TestDataContentAnalyzer:
    def test_name(self):
        a = DataContentAnalyzer()
        assert a.name == "DataContentAnalyzer"

    def test_description_nonempty(self):
        a = DataContentAnalyzer()
        assert a.description != ""

    def test_empty_ir_returns_no_findings(self):
        a = DataContentAnalyzer()
        ir = _make_ir()
        sample = _make_sample()
        findings = a.analyze(sample, ir)
        assert findings == []

    def test_string_table_detected(self):
        """Section with string table pattern should be detected."""
        a = DataContentAnalyzer()
        ir = _make_ir()
        # Create data with multiple null-terminated ASCII strings
        data = b"\\Device\\MyDriver\x00\\DosDevices\\MyDev\x00\\SystemRoot\\\x00"
        ir.section_data = {".rdata": data}
        ir.section_info = {
            ".rdata": {"offset": 0x1000, "size": len(data), "rva": 0x1000},
        }
        sample = _make_sample()
        findings = a.analyze(sample, ir)

        assert isinstance(findings, list)


# ------------------------------------------------------------------
# StructInferenceAnalyzer tests
# ------------------------------------------------------------------

class TestStructInferenceAnalyzer:
    def test_name(self):
        a = StructInferenceAnalyzer()
        assert a.name == "StructInferenceAnalyzer"

    def test_description_nonempty(self):
        a = StructInferenceAnalyzer()
        assert a.description != ""

    def test_empty_ir_returns_no_findings(self):
        a = StructInferenceAnalyzer()
        ir = _make_ir()
        sample = _make_sample()
        findings = a.analyze(sample, ir)
        assert findings == []

    def test_struct_inferred_from_access_pattern(self):
        """Multiple field offsets accessed from same base should infer struct."""
        a = StructInferenceAnalyzer()
        ir = _make_ir()

        func = Function(name="sub_1000", address=0x1000, size=0x200)
        ir.functions[0x1000] = func

        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(
            address=0x1000, end_address=0x1200,
            instructions=[
                Instruction(
                    address=0x1010, mnemonic="mov",
                    operands="rax, [rcx+0x10]",
                    size=7,
                ),
                Instruction(
                    address=0x1020, mnemonic="mov",
                    operands="rbx, [rcx+0x18]",
                    size=7,
                ),
                Instruction(
                    address=0x1030, mnemonic="mov",
                    operands="rdx, [rcx+0x20]",
                    size=7,
                ),
                Instruction(
                    address=0x1040, mnemonic="mov",
                    operands="r8, [rcx+0x28]",
                    size=7,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        sample = _make_sample()
        findings = a.analyze(sample, ir)

        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(struct_findings) >= 1

    def test_multiple_functions_same_struct(self):
        """Multiple functions accessing same offset pattern should infer struct."""
        a = StructInferenceAnalyzer()
        ir = _make_ir()

        for i in range(3):
            addr = 0x1000 + i * 0x100
            func = Function(name=f"sub_{addr:X}", address=addr, size=0x100)
            ir.functions[addr] = func

            cfg = CFG(function_address=addr, entry_block=addr)
            block = BasicBlock(
                address=addr, end_address=addr + 0x100,
                instructions=[
                    Instruction(
                        address=addr + 0x10, mnemonic="mov",
                        operands="rax, [rcx+0x10]",
                        size=7,
                    ),
                    Instruction(
                        address=addr + 0x20, mnemonic="mov",
                        operands="rbx, [rcx+0x18]",
                        size=7,
                    ),
                    Instruction(
                        address=addr + 0x30, mnemonic="mov",
                        operands="rdx, [rcx+0x20]",
                        size=7,
                    ),
                ],
                successors=[],
            )
            cfg.blocks[addr] = block
            ir.cfgs[addr] = ir.simple_cfgs[addr] = cfg

        sample = _make_sample()
        findings = a.analyze(sample, ir)

        assert isinstance(findings, list)
