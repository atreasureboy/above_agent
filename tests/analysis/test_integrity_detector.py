"""Tests for Integrity Self-Check detection (Phase 6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.integrity_detector import (
    IntegrityDetector,
    CRC_APIS,
    CRC_STRINGS,
    PE_HEADER_STRINGS,
    detect_crc_apis,
    detect_crc_strings,
    detect_code_scanning,
    detect_pe_header_access,
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
    Severity,
    Sample,
    Architecture,
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


class TestIntegrityConstants:
    """Test integrity detection constant definitions."""

    def test_crc_apis_defined(self):
        assert "RtlComputeCrc32" in CRC_APIS
        assert "RtlComputeCrc64" in CRC_APIS
        assert "CheckSumMappedFile" in CRC_APIS

    def test_crc_strings_defined(self):
        assert "CRC32" in CRC_STRINGS
        assert "checksum" in CRC_STRINGS
        assert "integrity check" in CRC_STRINGS
        assert "tamper" in CRC_STRINGS

    def test_pe_header_strings_defined(self):
        assert "MZ" in PE_HEADER_STRINGS
        assert "CheckSum" in PE_HEADER_STRINGS
        assert "ImageSectionHeader" in PE_HEADER_STRINGS


class TestCrcApiDetection:
    """Test CRC/checksum API detection."""

    def test_crc32_api_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["RtlComputeCrc32"])
        findings = detect_crc_apis(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.CODE_SELF_CHECK

    def test_checksum_mapped_critical(self):
        """CheckSumMappedFile should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CheckSumMappedFile"])
        findings = detect_crc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_crc64_high(self):
        """CRC64 without CheckSumMappedFile should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["RtlComputeCrc64"])
        findings = detect_crc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_multiple_crc_functions(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["RtlComputeCrc32"])
        _add_function(ir, 0x2000, ["RtlComputeCrc64"])
        findings = detect_crc_apis(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["crc_functions"]) == 2

    def test_no_crc_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_crc_apis(ir)
        assert findings == []


class TestCrcStringDetection:
    """Test CRC/integrity string detection."""

    def test_crc32_string_detected(self):
        ir = _make_ir()
        ir.strings.append("CRC32 table lookup")
        findings = detect_crc_strings(ir)
        assert len(findings) == 1

    def test_integrity_check_high(self):
        """Integrity check string should be HIGH."""
        ir = _make_ir()
        ir.strings.append("integrity check failed")
        findings = detect_crc_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_tamper_and_integrity_critical(self):
        """Both tamper + integrity strings should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("tamper detected")
        ir.strings.append("integrity check failed")
        findings = detect_crc_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_generic_crc_medium(self):
        ir = _make_ir()
        ir.strings.append("crc32")
        findings = detect_crc_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_crc_strings(self):
        ir = _make_ir()
        ir.strings.append("hello world")
        findings = detect_crc_strings(ir)
        assert findings == []


class TestCodeScanningDetection:
    """Test code section scanning pattern detection."""

    def test_scanning_loop_detected(self):
        """Function with loop + sequential reads + XOR should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        # Create a complex CFG with multiple blocks
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        for i in range(10):
            block_addr = 0x1000 + i * 0x10
            insns = [
                Instruction(address=block_addr + 0x10, mnemonic="movzx", operands="eax, byte ptr [rsi+r12]", size=4),
                Instruction(address=block_addr + 0x20, mnemonic="xor", operands="ecx, eax", size=4),
                Instruction(address=block_addr + 0x30, mnemonic="rol", operands="ecx, 8", size=4),
                Instruction(address=block_addr + 0x40, mnemonic="jnz", operands="loop_start", size=4),
            ]
            block = BasicBlock(address=block_addr, end_address=block_addr + 0x50, instructions=insns, successors=[])
            cfg.blocks[block_addr] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        findings = detect_code_scanning(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.CODE_SELF_CHECK

    def test_high_score_critical(self):
        """High score scanning function should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        for i in range(12):
            block_addr = 0x1000 + i * 0x10
            insns = [
                Instruction(address=block_addr + 0x10, mnemonic="movzx", operands="al, byte ptr [rcx]", size=4),
                Instruction(address=block_addr + 0x20, mnemonic="xor", operands="edx, [rcx+eax]", size=4),
                Instruction(address=block_addr + 0x30, mnemonic="shl", operands="edx, 2", size=4),
                Instruction(address=block_addr + 0x40, mnemonic="jbe", operands="0x1000", size=4),
            ]
            block = BasicBlock(address=block_addr, end_address=block_addr + 0x50, instructions=insns, successors=[])
            cfg.blocks[block_addr] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        findings = detect_code_scanning(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_simple_function_not_flagged(self):
        """Simple function should not trigger scanning detection."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
            ("add", "rax, 8"),
        ])
        findings = detect_code_scanning(ir)
        assert findings == []

    def test_no_functions(self):
        ir = _make_ir()
        findings = detect_code_scanning(ir)
        assert findings == []


class TestPeHeaderAccessDetection:
    """Test PE header string detection."""

    def test_mz_string_detected(self):
        ir = _make_ir()
        ir.strings.append("MZ")
        findings = detect_pe_header_access(ir)
        assert len(findings) == 1

    def test_checksum_high(self):
        """CheckSum string should be HIGH."""
        ir = _make_ir()
        ir.strings.append("CheckSum field in PE header")
        findings = detect_pe_header_access(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_pe_signature_medium(self):
        """PE signature without checksum should be MEDIUM."""
        ir = _make_ir()
        ir.strings.append("PE\0\0")
        findings = detect_pe_header_access(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_pe_strings(self):
        ir = _make_ir()
        findings = detect_pe_header_access(ir)
        assert findings == []


class TestIntegrityDetectorIntegration:
    """Test IntegrityDetector end-to-end."""

    def test_analyzer_name(self):
        detector = IntegrityDetector()
        assert detector.name == "IntegrityDetector"

    def test_analyzer_description(self):
        detector = IntegrityDetector()
        desc = detector.description
        assert "integrity" in desc.lower()
        assert "CRC" in desc

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = IntegrityDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_crc_and_strings(self):
        """CRC APIs + integrity strings should produce findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["RtlComputeCrc32"])
        ir.strings.append("integrity check failed")
        ir.strings.append("tamper detected")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = IntegrityDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.CODE_SELF_CHECK in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CheckSumMappedFile"])
        ir.strings.append("CRC32")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = IntegrityDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
