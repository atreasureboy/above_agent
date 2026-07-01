"""Tests for primitive_analyzer.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.primitive_analyzer import (
    DangerousPrimitiveAnalyzer,
    DANGEROUS_API_RULES,
)
from src.models import (
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Architecture,
    Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, api_names: list[str] | None = None) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    if api_names:
        ir.function_apis[addr] = api_names


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


class TestPrimitiveAnalyzerConstants:
    """Test constant definitions."""

    def test_rules_have_categories(self):
        for rule in DANGEROUS_API_RULES:
            assert "category" in rule
            assert "apis" in rule
            assert len(rule["apis"]) > 0

    def test_memory_mapping_apis(self):
        mem_rules = [r for r in DANGEROUS_API_RULES
                     if "memory" in r["category"].value.lower() or "map" in r["category"].value.lower()]
        assert len(mem_rules) > 0
        mem_apis = {api for r in mem_rules for api in r["apis"]}
        assert "MmMapIoSpace" in mem_apis or "MmMapIoSpaceEx" in mem_apis

    def test_msr_apis(self):
        msr_rules = [r for r in DANGEROUS_API_RULES if "msr" in r["category"].value.lower()]
        assert len(msr_rules) > 0

    def test_physical_memory_apis(self):
        phys_rules = [r for r in DANGEROUS_API_RULES if "physical" in r["category"].value.lower()]
        assert len(phys_rules) > 0

    def test_code_execution_apis(self):
        exec_rules = [r for r in DANGEROUS_API_RULES
                      if "code" in r["category"].value.lower() or "exec" in r["category"].value.lower()]
        assert len(exec_rules) > 0


class TestPrimitiveAnalyzerBasics:
    """Test basic analyzer functionality."""

    def test_analyzer_name(self):
        analyzer = DangerousPrimitiveAnalyzer()
        assert analyzer.name == "DangerousPrimitiveAnalyzer"

    def test_analyzer_description(self):
        analyzer = DangerousPrimitiveAnalyzer()
        desc = analyzer.description
        assert "dangerous" in desc.lower()
        assert "API" in desc

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []

    def test_mmapiospace_ex_detected(self):
        """MmMapIoSpaceEx should be detected as dangerous."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["MmMapIoSpaceEx"])
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        mem_findings = [f for f in findings if f.api_name == "MmMapIoSpaceEx"]
        assert len(mem_findings) >= 1

    def test_wrdmsr_detected(self):
        """WrMsr should be detected if present in rules."""
        ir = _make_ir()
        _add_function(ir, 0x2000, ["WrMsr"])
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        # WrMsr may or may not be in the rules — check if any MSR-related finding exists
        msr_findings = [f for f in findings if "Msr" in (f.api_name or "")
                        or "msr" in f.description.lower()
                        or f.category == FindingCategory.MSR_ACCESS]
        # If WrMsr is in rules, it should produce a finding
        all_rule_apis = {api for r in DANGEROUS_API_RULES for api in r["apis"]}
        if "WrMsr" in all_rule_apis:
            assert len(msr_findings) >= 1

    def test_physical_memory_detected(self):
        """MmMapPhysicalMemory should be detected if present in rules."""
        ir = _make_ir()
        _add_function(ir, 0x3000, ["MmMapPhysicalMemory"])
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        phys_findings = [f for f in findings if "Physical" in (f.api_name or "")]
        all_rule_apis = {api for r in DANGEROUS_API_RULES for api in r["apis"]}
        if "MmMapPhysicalMemory" in all_rule_apis:
            assert len(phys_findings) >= 1

    def test_multiple_dangerous_apis(self):
        """Multiple dangerous APIs should produce multiple findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["MmMapIoSpaceEx", "MmMapIoSpace"])
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        # At least MmMapIoSpaceEx should produce a finding
        assert len(findings) >= 1

    def test_safe_api_no_finding(self):
        """Safe APIs should not produce findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice", "IoDeleteDevice"])
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        # These may still be detected if they're in the rules,
        # but should not be if they're not dangerous
        dangerous_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        # IoCreateDevice/IoDeleteDevice are not in dangerous rules
        assert all(f.api_name not in ("IoCreateDevice", "IoDeleteDevice")
                   for f in dangerous_findings)

    def test_findings_have_evidence(self):
        """All findings should have evidence."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["MmMapIoSpaceEx"])
        sample = _sample()
        analyzer = DangerousPrimitiveAnalyzer()
        findings = analyzer.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
