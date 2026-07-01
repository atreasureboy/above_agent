"""Tests for ALPC/LPC cross-driver communication detection (Phase 5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.alpc_detector import (
    AlpcDetector,
    ALPC_APIS,
    LPC_APIS,
    ALPC_PORT_PATTERNS,
    SECTION_APIS,
    detect_alpc_apis,
    detect_lpc_apis,
    detect_alpc_port_names,
    detect_shared_memory,
    detect_alpc_message_patterns,
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


class TestAlpcConstants:
    """Test ALPC detection constant definitions."""

    def test_alpc_apis_defined(self):
        assert "AlpcSendWaitReceiveMessage" in ALPC_APIS
        assert "AlpcConnectPort" in ALPC_APIS
        assert "AlpcCreatePort" in ALPC_APIS
        assert "NtAlpcConnectPort" in ALPC_APIS
        assert "NtAlpcSendWaitReceiveMessage" in ALPC_APIS

    def test_lpc_apis_defined(self):
        assert "NtConnectPort" in LPC_APIS
        assert "NtCreatePort" in LPC_APIS
        assert "NtListenPort" in LPC_APIS
        assert "NtImpersonateClientOfPort" in LPC_APIS

    def test_alpc_port_patterns_defined(self):
        assert "\\RPC Control\\" in ALPC_PORT_PATTERNS
        assert "\\BaseNamedObjects\\" in ALPC_PORT_PATTERNS
        assert "360" in ALPC_PORT_PATTERNS
        assert "AntiHack" in ALPC_PORT_PATTERNS

    def test_section_apis_defined(self):
        assert "AlpcCreatePortSection" in SECTION_APIS
        assert "ZwCreateSection" in SECTION_APIS
        assert "ZwMapViewOfSection" in SECTION_APIS


class TestAlpcApiDetection:
    """Test ALPC API detection."""

    def test_connect_api_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcConnectPort"])
        findings = detect_alpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.ALPC_COMMUNICATION

    def test_send_receive_api_critical(self):
        """Connect + Send/Receive should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "AlpcConnectPort",
            "AlpcSendWaitReceiveMessage",
        ])
        findings = detect_alpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_multiple_alpc_functions(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcConnectPort"])
        _add_function(ir, 0x2000, ["AlpcSendWaitReceiveMessage"])
        _add_function(ir, 0x3000, ["AlpcCreatePort"])
        findings = detect_alpc_apis(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["alpc_functions"]) == 3

    def test_no_alpc_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_alpc_apis(ir)
        assert findings == []

    def test_connect_only_high(self):
        """Connect-only should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcConnectPort"])
        findings = detect_alpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_section_only_medium(self):
        """Section-only should be MEDIUM."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcCreatePortSection"])
        findings = detect_alpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestLpcApiDetection:
    """Test legacy LPC API detection."""

    def test_connect_port_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtConnectPort"])
        findings = detect_lpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.ALPC_COMMUNICATION

    def test_impersonate_critical(self):
        """LPC impersonation should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtImpersonateClientOfPort"])
        findings = detect_lpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_listen_port_high(self):
        """Listen port without impersonation should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtListenPort"])
        findings = detect_lpc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_no_lpc_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_lpc_apis(ir)
        assert findings == []


class TestAlpcPortNameDetection:
    """Test ALPC port name string detection."""

    def test_rpc_control_port(self):
        ir = _make_ir()
        ir.strings.append("\\RPC Control\\MyPort")
        findings = detect_alpc_port_names(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_360_port_critical(self):
        """360-named port should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("\\RPC Control\\360AntiHackPort")
        findings = detect_alpc_port_names(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_antihack_port_critical(self):
        ir = _make_ir()
        ir.strings.append("\\BaseNamedObjects\\AntiHackComm")
        findings = detect_alpc_port_names(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_generic_port_medium(self):
        ir = _make_ir()
        ir.strings.append("\\BaseNamedObjects\\SomePort")
        findings = detect_alpc_port_names(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_port_strings(self):
        ir = _make_ir()
        findings = detect_alpc_port_names(ir)
        assert findings == []


class TestSharedMemoryDetection:
    """Test shared memory section detection."""

    def test_alpc_section_high(self):
        """ALPC-specific section should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcCreatePortSection"])
        findings = detect_shared_memory(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].context["has_alpc_section"] is True

    def test_generic_section_medium(self):
        """ZwCreateSection without ALPC should be MEDIUM."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ZwCreateSection", "ZwMapViewOfSection"])
        findings = detect_shared_memory(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].context["has_alpc_section"] is False

    def test_multiple_section_functions(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcCreatePortSection", "AlpcCreateSectionView"])
        _add_function(ir, 0x2000, ["ZwCreateSection"])
        findings = detect_shared_memory(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["section_functions"]) == 2

    def test_no_section_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_shared_memory(ir)
        assert findings == []


class TestAlpcMessagePatternDetection:
    """Test ALPC message structure instruction-level detection."""

    def test_port_message_size_patterns(self):
        """Functions with PORT_MESSAGE size constants should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "word ptr [rax], 0x18"),
            ("mov", "word ptr [rax+2], 0x28"),
            ("mov", "dword ptr [rax+4], 0x30"),
        ])
        findings = detect_alpc_message_patterns(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.ALPC_MESSAGE

    def test_client_id_access(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, qword ptr [rcx+client_id]"),
            ("mov", "qword ptr [rdx+8+cid], rax"),
            ("mov", "word ptr [rdx], 0x18"),
        ])
        findings = detect_alpc_message_patterns(ir)
        assert len(findings) == 1

    def test_message_type_access(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "eax, dword ptr [rcx+message_type]"),
            ("mov", "dword ptr [rdx+message_type_field], 2"),
            ("mov", "word ptr [rax], 0x28"),
        ])
        findings = detect_alpc_message_patterns(ir)
        assert len(findings) == 1

    def test_low_score_not_flagged(self):
        """Few patterns should not trigger detection."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, 0x18"),
        ])
        findings = detect_alpc_message_patterns(ir)
        assert findings == []

    def test_no_functions(self):
        ir = _make_ir()
        findings = detect_alpc_message_patterns(ir)
        assert findings == []


class TestAlpcDetectorIntegration:
    """Test AlpcDetector end-to-end."""

    def test_analyzer_name(self):
        detector = AlpcDetector()
        assert detector.name == "AlpcDetector"

    def test_analyzer_description(self):
        detector = AlpcDetector()
        desc = detector.description
        assert "ALPC" in desc or "alpc" in desc.lower()
        assert "LPC" in desc

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = AlpcDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_alpc_and_port(self):
        """ALPC APIs + port names should produce multiple findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "AlpcConnectPort",
            "AlpcSendWaitReceiveMessage",
        ])
        ir.strings.append("\\RPC Control\\360AntiHackPort")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = AlpcDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.ALPC_COMMUNICATION in categories
        assert FindingCategory.ALPC_PORT_NAME in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["AlpcConnectPort"])
        ir.strings.append("\\RPC Control\\TestPort")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = AlpcDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
