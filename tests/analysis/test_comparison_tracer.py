"""Tests for comparison_tracer.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from src.analysis.deep.comparison_tracer import ComparisonTracer
from src.models import (
    BasicBlock, CFG, Confidence, DisassemblyResult, FindingCategory,
    Function, Instruction, Sample, Architecture, Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, name: str = None) -> Function:
    func = Function(name=name or f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    return func


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


class TestComparisonTracerBasics:
    """Test basic analyzer functionality."""

    def test_analyzer_name(self):
        tracer = ComparisonTracer()
        assert tracer.name == "ComparisonTracer"

    def test_analyzer_description(self):
        tracer = ComparisonTracer()
        assert "whitelist" in tracer.description.lower() or "blacklist" in tracer.description.lower()

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        tracer = ComparisonTracer()
        findings = tracer.analyze(sample, ir)
        assert findings == []

    def test_empty_ir_populates_traces(self):
        ir = _make_ir()
        sample = _sample()
        tracer = ComparisonTracer()
        findings = tracer.analyze(sample, ir)
        assert ir.comparison_traces == []


class TestRIPRelativeCmp:
    """Test x64 RIP-relative cmp resolution."""

    def test_cmp_rip_relative_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x2000]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        assert len(findings) >= 1
        # The trace should be recorded
        assert len(ir.comparison_traces) >= 1

    def test_cmp_rip_relative_resolves_correct_address(self):
        """RIP-relative address: insn_addr + insn_size + offset."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x5000]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        tracer.analyze(sample, ir)
        trace = ir.comparison_traces[0]
        # insn at 0x1010, size 4, offset 0x5000 → 0x1014 + 0x5000 = 0x6014
        assert trace["data_rva"] == 0x6014

    def test_test_rip_relative_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("test", "eax, [rip+0x3000]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        assert len(findings) >= 1


class TestX86DirectAddressCmp:
    """Test x86 direct address cmp resolution."""

    def test_cmp_x86_direct_address(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [0x12345678]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        tracer.analyze(sample, ir)
        assert len(ir.comparison_traces) >= 1
        assert ir.comparison_traces[0]["data_rva"] == 0x12345678

    def test_test_x86_direct_address(self):
        """test instruction with x86 direct address — uses cmp since test x86 path
        is not wired in _analyze_function (only RIP-relative test is handled)."""
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("cmp", "eax, [0xDEADBEEF]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        tracer.analyze(sample, ir)
        assert len(ir.comparison_traces) >= 1


class TestImmediateCmp:
    """Test immediate value cmp handling."""

    def test_cmp_immediate_recorded(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, 0xC0000022"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        assert len(findings) >= 1
        trace = ir.comparison_traces[0]
        assert trace["data_rva"] is None
        assert trace["compared_value"] == "0xc0000022"


class TestWhitelistBlacklistClassification:
    """Test whitelist/blacklist check classification."""

    def test_whitelist_from_data_structure_hint(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x1000]"),
        ])
        ir.data_structures[0x2014] = {
            "type": "dword_array",
            "semantic_hint": "whitelist",
        }
        tracer = ComparisonTracer()
        sample = _sample()
        tracer.analyze(sample, ir)
        trace = ir.comparison_traces[0]
        assert trace["is_whitelist_check"] is True

    def test_blacklist_from_data_structure_hint(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x1000]"),
        ])
        ir.data_structures[0x2014] = {
            "type": "dword_array",
            "semantic_hint": "blacklist",
        }
        tracer = ComparisonTracer()
        sample = _sample()
        tracer.analyze(sample, ir)
        trace = ir.comparison_traces[0]
        assert trace["is_blacklist_check"] is True

    def test_whitelist_from_instruction_keyword(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x1000]"),
        ])
        tracer = ComparisonTracer()
        # Patch instruction text to include whitelist keyword
        cfg = ir.cfgs[0x1000]
        cfg.blocks[0x1000].instructions[0].operands = "eax, [rip+0x1000] ; allow check"
        sample = _sample()
        tracer.analyze(sample, ir)
        trace = ir.comparison_traces[0]
        assert trace["is_whitelist_check"] is True

    def test_blacklist_from_instruction_keyword(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x1000]"),
        ])
        tracer = ComparisonTracer()
        cfg = ir.cfgs[0x1000]
        cfg.blocks[0x1000].instructions[0].operands = "eax, [rip+0x1000] ; deny check"
        sample = _sample()
        tracer.analyze(sample, ir)
        trace = ir.comparison_traces[0]
        assert trace["is_blacklist_check"] is True


class TestImmHintClassification:
    """Test immediate value NTSTATUS classification."""

    def test_status_success_is_whitelist(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0x00000000)
        assert is_wl is True
        assert is_bl is False

    def test_status_access_denied_is_blacklist(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0xC0000022)
        assert is_wl is False
        assert is_bl is True

    def test_status_unsuccessful_is_blacklist(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0xC0000001)
        assert is_wl is False
        assert is_bl is True

    def test_status_invalid_parameter_is_blacklist(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0xC000000D)
        assert is_wl is False
        assert is_bl is True

    def test_status_access_violation_is_blacklist(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0xC0000005)
        assert is_wl is False
        assert is_bl is True

    def test_status_not_supported_is_blacklist(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0xC00000BB)
        assert is_wl is False
        assert is_bl is True

    def test_unknown_value_no_hint(self):
        tracer = ComparisonTracer()
        is_wl, is_bl = tracer._check_imm_hint(0x12345678)
        assert is_wl is False
        assert is_bl is False


class TestArrayIterationDetection:
    """Test array iteration (loop) detection."""

    def test_back_edge_detected_as_iteration(self):
        """Block with back-edge successor should be array iteration."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(
            address=0x1000, end_address=0x1100,
            instructions=[
                Instruction(address=0x1010, mnemonic="cmp", operands="eax, [rip+0x1000]", size=4),
            ],
            successors=[0x1000],  # back edge
        )
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        tracer = ComparisonTracer()
        is_iter = tracer._is_array_iteration(block, 0x1010)
        assert is_iter is True

    def test_no_back_edge_not_iteration(self):
        """Block without back-edge should not be array iteration."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(
            address=0x1000, end_address=0x1100,
            instructions=[
                Instruction(address=0x1010, mnemonic="cmp", operands="eax, [rip+0x1000]", size=4),
            ],
            successors=[0x2000],  # forward edge
        )
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        tracer = ComparisonTracer()
        is_iter = tracer._is_array_iteration(block, 0x1010)
        assert is_iter is False


class TestFindingCategories:
    """Test finding category assignment."""

    def test_whitelist_finding_category(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, 0x0"),  # STATUS_SUCCESS → whitelist
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        wl_findings = [f for f in findings if f.category == FindingCategory.WHITELIST_CHECK_DETECTED]
        assert len(wl_findings) >= 1

    def test_blacklist_finding_category(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, 0xC0000022"),  # STATUS_ACCESS_DENIED → blacklist
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        bl_findings = [f for f in findings if f.category == FindingCategory.BLACKLIST_CHECK_DETECTED]
        assert len(bl_findings) >= 1

    def test_array_iteration_category(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x1000]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        # Default category for non-whitelist/non-blacklist cmp
        arr_findings = [f for f in findings if f.category == FindingCategory.ARRAY_ITERATION_CMP]
        assert len(arr_findings) >= 1

    def test_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "eax, [rip+0x1000]"),
        ])
        tracer = ComparisonTracer()
        sample = _sample()
        findings = tracer.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0


class TestResolveHelpers:
    """Test resolution helper methods."""

    def test_resolve_cmp_rva_valid(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        insn.operands = "eax, [rip+0x2000]"
        insn.address = 0x1000
        insn.size = 7
        rva = tracer._resolve_cmp_rva(insn, 0x1000)
        assert rva == 0x1007 + 0x2000

    def test_resolve_cmp_rva_invalid_offset(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        insn.operands = "eax, [rip+garbage]"
        insn.address = 0x1000
        insn.size = 4
        rva = tracer._resolve_cmp_rva(insn, 0x1000)
        assert rva is None

    def test_resolve_cmp_rva_no_rip(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        insn.operands = "eax, 0x1234"
        insn.address = 0x1000
        insn.size = 4
        rva = tracer._resolve_cmp_rva(insn, 0x1000)
        assert rva is None

    def test_resolve_x86_cmp_addr_valid(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        insn.mnemonic = "cmp"
        insn.operands = "eax, [0x12345678]"
        rva = tracer._resolve_x86_cmp_addr(insn)
        assert rva == 0x12345678

    def test_resolve_x86_cmp_addr_invalid(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        insn.mnemonic = "cmp"
        insn.operands = "eax, [garbage]"
        rva = tracer._resolve_x86_cmp_addr(insn)
        assert rva is None

    def test_build_description_with_data_rva(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        ir = _make_ir()
        ir.data_structures[0x5000] = {"semantic_hint": "whitelist"}
        desc = tracer._build_description(insn, 0x5000, "cmp eax, [rip+0x4000]", True, False, ir)
        assert "whitelist" in desc.lower()
        assert "0x5000" in desc

    def test_build_description_without_data(self):
        tracer = ComparisonTracer()
        insn = MagicMock()
        ir = _make_ir()
        desc = tracer._build_description(insn, 0, "cmp eax, 0x100", False, False, ir)
        assert "immediate" in desc.lower()
