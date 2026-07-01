"""Tests for correlator taint tracking integration."""

import pytest
from pathlib import Path

from src.models import (
    APICallInfo,
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
    Architecture,
)
from src.analysis.core.correlator import BYOVDChainCorrelator


def make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="test.sys",
        company="Test Corp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="abc123",
        size=8192,
    )


def make_ir_with_taint() -> DisassemblyResult:
    """Build IR where handler reads IRP SystemBuffer and calls MmMapIoSpace."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

    handler_addr = 0x1000
    ir.functions = {
        handler_addr: Function(name="Handler", address=handler_addr, size=0x200),
    }
    ir.irp_handlers = {0xE: handler_addr}
    ir.is_wdf_driver = False
    ir.function_apis[handler_addr] = ["MmMapIoSpace"]

    # Instructions: taint source → propagation → dangerous sink
    blocks = [
        BasicBlock(
            address=handler_addr,
            end_address=handler_addr + 0x100,
            instructions=[
                Instruction(
                    address=handler_addr + 0x10,
                    mnemonic="mov",
                    operands="rax, [rcx+0x60]",
                ),
                Instruction(
                    address=handler_addr + 0x18,
                    mnemonic="mov",
                    operands="rdx, rax",
                ),
                Instruction(
                    address=handler_addr + 0x20,
                    mnemonic="call",
                    operands="MmMapIoSpace",
                    api_info=APICallInfo(name="MmMapIoSpace", call_address=handler_addr + 0x20),
                    api_target="MmMapIoSpace",
                ),
            ],
            successors=[],
        ),
    ]

    ir.cfgs[handler_addr] = CFG(
        function_address=handler_addr,
        blocks={b.address: b for b in blocks},
        entry_block=blocks[0].address,
    )
    return ir


def make_sample_with_findings() -> Sample:
    sample = make_sample()
    sample.analysis_findings.append(
        Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="MmMapIoSpace found",
            function_address=0x1000,
            api_name="MmMapIoSpace",
            instruction_address=0x1020,
            context={"missing_checks": []},
        )
    )
    return sample


class TestTaintIntegration:
    """Tests for taint tracking integration in BYOVD chain correlator."""

    def setup_method(self):
        self.analyzer = BYOVDChainCorrelator()

    def test_taint_integration_basic(self):
        """Taint analysis confirms user input reaches MmMapIoSpace in handler."""
        ir = make_ir_with_taint()
        sample = make_sample_with_findings()

        findings = self.analyzer.analyze(sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN
                  and f.context.get("chain_type") == "byovd_complete"]
        assert len(chains) >= 1

    def test_taint_boosts_confidence(self):
        """When taint confirms user input reaches dangerous API, confidence is HIGH."""
        ir = make_ir_with_taint()
        sample = make_sample_with_findings()

        findings = self.analyzer.analyze(sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        # Taint + no validation = highest confidence
        assert chains[0].confidence == Confidence.HIGH

    def test_taint_no_false_positive_on_safe_driver(self):
        """Driver with no dangerous APIs should not produce attack chains."""
        ir = DisassemblyResult(sample_path=Path("safe.sys"), backend="capstone")
        ir.functions = {
            0x1000: Function(name="SafeFunc", address=0x1000, size=0x50),
        }
        ir.is_wdf_driver = False

        sample = make_sample()
        sample.name = "safe.sys"

        findings = self.analyzer.analyze(sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) == 0
