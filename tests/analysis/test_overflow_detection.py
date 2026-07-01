"""
Tests for M7: integer overflow bypass detection and M6: path-level CFG correlation.
"""

import pytest
from pathlib import Path

from src.models import (
    DisassemblyResult, Finding, FindingCategory,
    Severity, Confidence, Function, Sample, Architecture,
    BasicBlock, Instruction, CFG,
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


def make_ir_with_cfg_and_blocks(
    blocks: list[BasicBlock],
    handler_addr: int = 0x1000,
) -> DisassemblyResult:
    """Build a DisassemblyResult with a custom CFG for the handler."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    ir.functions = {
        handler_addr: Function(name="Handler", address=handler_addr, size=0x200),
    }
    ir.irp_handlers = {0xE: handler_addr}
    ir.is_wdf_driver = False
    ir.cfgs[handler_addr] = CFG(
        function_address=handler_addr,
        blocks={b.address: b for b in blocks},
        entry_block=blocks[0].address if blocks else 0,
    )
    return ir


class TestIntegerOverflowBypass:
    """M7: Tests for detecting arithmetic before cmp without overflow checks."""

    def setup_method(self):
        self.analyzer = BYOVDChainCorrelator()
        self.sample = make_sample()

    def _make_ir_with_overflow_cmp(self, handler_addr: int = 0x1000):
        """Create a CFG where an add instruction precedes a cmp — overflow risk."""
        blocks = [
            BasicBlock(
                address=handler_addr,
                end_address=handler_addr + 0x20,
                instructions=[
                    Instruction(
                        address=handler_addr,
                        mnemonic="mov",
                        operands="rax, rcx",
                        size=3,
                    ),
                    Instruction(
                        address=handler_addr + 0x10,
                        mnemonic="add",
                        operands="rax, 0x100",
                        size=4,
                    ),
                    Instruction(
                        address=handler_addr + 0x18,
                        mnemonic="cmp",
                        operands="rax, 0x10000",
                        size=4,
                    ),
                    Instruction(
                        address=handler_addr + 0x20,
                        mnemonic="ja",
                        operands="0x1050",
                        size=6,
                    ),
                ],
                successors=[handler_addr + 0x30],
            ),
            BasicBlock(
                address=handler_addr + 0x30,
                end_address=handler_addr + 0x50,
                instructions=[
                    Instruction(
                        address=handler_addr + 0x30,
                        mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6,
                        api_target="MmMapIoSpace",
                    ),
                ],
            ),
        ]
        return make_ir_with_cfg_and_blocks(blocks, handler_addr)

    def _make_ir_with_safe_cmp(self, handler_addr: int = 0x1000):
        """Create a CFG with a plain cmp (no preceding arithmetic) — genuine validation."""
        blocks = [
            BasicBlock(
                address=handler_addr,
                end_address=handler_addr + 0x20,
                instructions=[
                    Instruction(
                        address=handler_addr,
                        mnemonic="cmp",
                        operands="rcx, 0x1000",
                        size=4,
                    ),
                    Instruction(
                        address=handler_addr + 0x10,
                        mnemonic="ja",
                        operands="0x1050",
                        size=6,
                    ),
                ],
                successors=[handler_addr + 0x30],
            ),
            BasicBlock(
                address=handler_addr + 0x30,
                end_address=handler_addr + 0x50,
                instructions=[
                    Instruction(
                        address=handler_addr + 0x30,
                        mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6,
                        api_target="MmMapIoSpace",
                    ),
                ],
            ),
        ]
        return make_ir_with_cfg_and_blocks(blocks, handler_addr)

    def _make_ir_with_overflow_and_overflow_check(self, handler_addr: int = 0x1000):
        """Create a CFG where add precedes cmp but jo/jc protects it — safe."""
        blocks = [
            BasicBlock(
                address=handler_addr,
                end_address=handler_addr + 0x30,
                instructions=[
                    Instruction(
                        address=handler_addr,
                        mnemonic="mov",
                        operands="rax, rcx",
                        size=3,
                    ),
                    Instruction(
                        address=handler_addr + 0x10,
                        mnemonic="add",
                        operands="rax, 0x100",
                        size=4,
                    ),
                    Instruction(
                        address=handler_addr + 0x18,
                        mnemonic="jo",
                        operands="0x1100",
                        size=6,
                    ),
                    Instruction(
                        address=handler_addr + 0x20,
                        mnemonic="cmp",
                        operands="rax, 0x10000",
                        size=4,
                    ),
                    Instruction(
                        address=handler_addr + 0x28,
                        mnemonic="ja",
                        operands="0x1050",
                        size=6,
                    ),
                ],
                successors=[handler_addr + 0x40],
            ),
            BasicBlock(
                address=handler_addr + 0x40,
                end_address=handler_addr + 0x60,
                instructions=[
                    Instruction(
                        address=handler_addr + 0x40,
                        mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6,
                        api_target="MmMapIoSpace",
                    ),
                ],
            ),
        ]
        return make_ir_with_cfg_and_blocks(blocks, handler_addr)

    def test_overflow_bypass_detected(self):
        """When add precedes cmp without overflow check, the path is flagged as unprotected."""
        ir = self._make_ir_with_overflow_cmp()

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
                instruction_address=0x1030,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        # The missing_checks should include integer_overflow
        ctx = chains[0].context
        assert "integer_overflow" in ctx.get("missing_checks", [])

    def test_safe_cmp_not_flagged_as_overflow(self):
        """Plain cmp without preceding arithmetic should not flag overflow."""
        ir = self._make_ir_with_safe_cmp()

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
                instruction_address=0x1030,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        # May or may not have chain, but should NOT flag integer_overflow
        for c in chains:
            assert "integer_overflow" not in c.context.get("missing_checks", [])

    def test_overflow_with_jo_check_not_flagged(self):
        """add + cmp protected by jo (overflow check) should not flag overflow bypass."""
        ir = self._make_ir_with_overflow_and_overflow_check()

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
                instruction_address=0x1040,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        for c in chains:
            assert "integer_overflow" not in c.context.get("missing_checks", [])

    def test_mul_before_cmp_flags_overflow(self):
        """mul before cmp without overflow check should flag overflow bypass."""
        blocks = [
            BasicBlock(
                address=0x2000,
                end_address=0x2030,
                instructions=[
                    Instruction(address=0x2000, mnemonic="imul", operands="rax, rcx", size=4),
                    Instruction(address=0x2010, mnemonic="cmp", operands="rax, #0x1000", size=4),
                    Instruction(address=0x2018, mnemonic="jbe", operands="0x2100", size=6),
                ],
                successors=[0x2040],
            ),
            BasicBlock(
                address=0x2040,
                end_address=0x2060,
                instructions=[
                    Instruction(
                        address=0x2040, mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6, api_target="MmMapLockedPagesSpecifyCache",
                    ),
                ],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x2000)

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapLockedPagesSpecifyCache",
                function_address=0x2000,
                api_name="MmMapLockedPagesSpecifyCache",
                instruction_address=0x2040,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        assert "integer_overflow" in chains[0].context.get("missing_checks", [])

    def test_safe_arith_api_not_flagged(self):
        """RtlULongAdd before cmp should NOT flag overflow — it's a safe API."""
        blocks = [
            BasicBlock(
                address=0x3000,
                end_address=0x3030,
                instructions=[
                    Instruction(
                        address=0x3000, mnemonic="call",
                        operands="RtlULongAdd",
                        size=5, api_target="RtlULongAdd",
                    ),
                    Instruction(address=0x3010, mnemonic="cmp", operands="eax, #0x1000", size=4),
                    Instruction(address=0x3018, mnemonic="jbe", operands="0x3100", size=6),
                ],
                successors=[0x3040],
            ),
            BasicBlock(
                address=0x3040,
                end_address=0x3060,
                instructions=[
                    Instruction(
                        address=0x3040, mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6, api_target="MmMapIoSpace",
                    ),
                ],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x3000)

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x3000,
                api_name="MmMapIoSpace",
                instruction_address=0x3040,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        # Should NOT flag integer_overflow because RtlULongAdd is a safe API
        for c in chains:
            assert "integer_overflow" not in c.context.get("missing_checks", [])

    def test_infer_missing_checks_path_only(self):
        """_infer_missing_checks should only inspect blocks on the actual path,
        not unrelated branches that contain validation."""
        from src.analysis.core.correlator import _infer_missing_checks

        blocks = [
            # Entry block: arithmetic feeding cmp (risky pattern)
            BasicBlock(
                address=0x4000, end_address=0x4010,
                instructions=[
                    Instruction(address=0x4000, mnemonic="mov", operands="rax, rcx", size=3),
                    Instruction(address=0x4008, mnemonic="add", operands="rax, 0x100", size=4),
                    Instruction(address=0x400C, mnemonic="cmp", operands="rax, #0x1000", size=4),
                ],
                successors=[0x4010, 0x4030],  # Two paths: one to call, one to validation
            ),
            # Unprotected path to API call
            BasicBlock(
                address=0x4010, end_address=0x4020,
                instructions=[
                    Instruction(
                        address=0x4010, mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6, api_target="MmMapIoSpace",
                    ),
                ],
                successors=[],
            ),
            # Protected path: has cmp + privilege check (but NOT on the call path)
            BasicBlock(
                address=0x4030, end_address=0x4040,
                instructions=[
                    Instruction(address=0x4030, mnemonic="cmp", operands="rcx, #0x1000", size=4),
                    Instruction(
                        address=0x4038, mnemonic="call",
                        operands="SeSinglePrivilegeCheck",
                        size=5, api_target="SeSinglePrivilegeCheck",
                    ),
                ],
                successors=[],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x4000)

        checks = _infer_missing_checks(0x4000, 0x4010, ir)
        # The 0x4030 block has a cmp and privilege check, but it's NOT on the
        # path to 0x4010, so it should NOT suppress missing checks
        assert "privilege_check" in checks
        # size_check: the cmp in 0x4030 is NOT on the path, but the cmp in
        # 0x4000 IS on the path (it feeds from the add), so size_check found
        assert "size_check" not in checks
        # integer_overflow: add feeds cmp in 0x4000, no overflow check on path
        assert "integer_overflow" in checks

    def test_infer_missing_checks_does_not_false_positive(self):
        """When validation IS on the path, _infer_missing_checks should report it."""
        from src.analysis.core.correlator import _infer_missing_checks

        blocks = [
            BasicBlock(
                address=0x5000, end_address=0x5010,
                instructions=[
                    Instruction(address=0x5000, mnemonic="mov", operands="rax, rcx", size=3),
                    Instruction(address=0x5008, mnemonic="cmp", operands="rcx, #0x1000", size=4),
                ],
                successors=[0x5010],
            ),
            BasicBlock(
                address=0x5010, end_address=0x5020,
                instructions=[
                    Instruction(address=0x5010, mnemonic="jbe", operands="0x5100", size=6),
                    Instruction(
                        address=0x5018, mnemonic="call",
                        operands="SeSinglePrivilegeCheck",
                        size=5, api_target="SeSinglePrivilegeCheck",
                    ),
                ],
                successors=[0x5020],
            ),
            BasicBlock(
                address=0x5020, end_address=0x5030,
                instructions=[
                    Instruction(
                        address=0x5020, mnemonic="call",
                        operands="qword ptr [rip+0x1000]",
                        size=6, api_target="MmMapIoSpace",
                    ),
                ],
                successors=[],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x5000)

        checks = _infer_missing_checks(0x5000, 0x5020, ir)
        # All validation IS on the path, so should NOT be missing
        assert "privilege_check" not in checks
        assert "size_check" not in checks


class TestCorrelatorPathLevel:
    """M6: Tests for path-level CFG correlation."""

    def setup_method(self):
        self.analyzer = BYOVDChainCorrelator()
        self.sample = make_sample()

    def test_cfg_reachable_returns_true(self):
        """When target is in the handler function, _cfg_reachable returns True."""
        blocks = [
            BasicBlock(
                address=0x1000, end_address=0x1020,
                instructions=[Instruction(address=0x1000, mnemonic="mov", operands="rax, rcx", size=3)],
                successors=[0x1030],
            ),
            BasicBlock(
                address=0x1030, end_address=0x1050,
                instructions=[Instruction(address=0x1030, mnemonic="call", operands="qword ptr [rip+0x100]", size=6)],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x1000)
        assert self.analyzer._cfg_reachable(0x1000, 0x1030, ir) is True

    def test_cfg_reachable_returns_false_for_other_func(self):
        """When target is not reachable from handler, returns False."""
        blocks = [
            BasicBlock(
                address=0x1000, end_address=0x1020,
                instructions=[Instruction(address=0x1000, mnemonic="ret", operands="", size=1)],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x1000)
        # 0x9999 is not in the CFG at all
        assert self.analyzer._cfg_reachable(0x1000, 0x9999, ir) is False

    def test_filter_driver_all_functions_reachable(self):
        """Filter driver: all functions should be considered as handler entry points."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.functions = {
            0x1000: Function(name="FilterAttach", address=0x1000, size=0x200),
            0x2000: Function(name="FilterIoctl", address=0x2000, size=0x100),
        }
        ir.irp_handlers = {0x0: 0x1000}  # Only IRP_MJ_CREATE, no DEVICE_CONTROL
        ir.is_filter_driver = True

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x2000,
                api_name="MmMapIoSpace",
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        # The 0x2000 function should be considered as handler since it's a filter driver
        assert len(chains) >= 1

    def test_wdf_dispatch_marker_in_description(self):
        """WDF driver chains should include WDF marker in description."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.functions = {0x1000: Function(name="EvtIoDeviceControl", address=0x1000, size=0x200)}
        ir.irp_handlers = {0xE: 0x1000}
        ir.is_wdf_driver = True
        ir.wdf_dispatch_functions = {0x222000: [0x1000]}
        ir.ioctl_handlers = {0x222000: 0x1000}

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
            # Add unvalidated input finding to establish a validation gap
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Unvalidated user input reaches sub_1000",
                function_address=0x1000,
                context={"missing_checks": ["size_check", "privilege_check"]},
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        assert "WDF" in chains[0].description

    def test_deferred_callbacks_as_handlers(self):
        """Deferred callback functions should be considered as handler entry points."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.functions = {
            0x1000: Function(name="Handler", address=0x1000, size=0x200),
            0x2000: Function(name="DpcCallback", address=0x2000, size=0x100),
        }
        ir.irp_handlers = {0xE: 0x1000}
        ir.is_wdf_driver = False
        ir.deferred_callbacks = {
            0x2000: [{
                "queue_api": "KeInitializeDpc",
                "caller_func": 0x1000,
                "callback_type": "DPC callback",
            }],
        }

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace in callback",
                function_address=0x2000,
                api_name="MmMapIoSpace",
            ),
            # Add unvalidated input finding to establish a validation gap
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Unvalidated user input reaches sub_2000",
                function_address=0x2000,
                context={"missing_checks": ["size_check"]},
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        # Callback at 0x2000 should be considered as handler
        assert len(chains) >= 1
        handler_addrs = {c.function_address for c in chains}
        assert 0x2000 in handler_addrs


class TestARM64OverflowDetection:
    """ARM64-specific overflow bypass detection tests."""

    def setup_method(self):
        self.analyzer = BYOVDChainCorrelator()
        self.sample = Sample(
            path=Path("test.sys"),
            name="test.sys",
            company="Test Corp",
            version="1.0.0.0",
            arch=Architecture.ARM64,
            sha256="abc123",
            size=8192,
        )

    def test_arm64_adds_before_cmp_flags_overflow(self):
        """ARM64: adds (add with flags) before cmp without B.VS should flag overflow."""
        blocks = [
            BasicBlock(
                address=0x6000, end_address=0x6020,
                instructions=[
                    Instruction(address=0x6000, mnemonic="mov", operands="x0, x1", size=4),
                    Instruction(address=0x6008, mnemonic="adds", operands="x0, x0, #0x100", size=4),
                    Instruction(address=0x6010, mnemonic="cmp", operands="x0, #0x1000", size=4),
                    Instruction(address=0x6018, mnemonic="b.ls", operands="0x6100", size=4),
                ],
                successors=[0x6020],
            ),
            BasicBlock(
                address=0x6020, end_address=0x6040,
                instructions=[
                    Instruction(
                        address=0x6020, mnemonic="bl",
                        operands="MmMapIoSpace",
                        size=4, api_target="MmMapIoSpace",
                    ),
                ],
                successors=[],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x6000)
        ir.is_arm64 = True

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x6000,
                api_name="MmMapIoSpace",
                instruction_address=0x6020,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        assert "integer_overflow" in chains[0].context.get("missing_checks", [])

    def test_arm64_b_vs_protects_overflow(self):
        """ARM64: adds + cmp protected by B.VS (overflow check) should not flag."""
        blocks = [
            BasicBlock(
                address=0x7000, end_address=0x7030,
                instructions=[
                    Instruction(address=0x7000, mnemonic="mov", operands="x0, x1", size=4),
                    Instruction(address=0x7008, mnemonic="adds", operands="x0, x0, #0x100", size=4),
                    Instruction(address=0x7010, mnemonic="b.vs", operands="0x7200", size=4),
                    Instruction(address=0x7018, mnemonic="cmp", operands="x0, #0x1000", size=4),
                    Instruction(address=0x7020, mnemonic="b.ls", operands="0x7100", size=4),
                ],
                successors=[0x7030],
            ),
            BasicBlock(
                address=0x7030, end_address=0x7050,
                instructions=[
                    Instruction(
                        address=0x7030, mnemonic="bl",
                        operands="MmMapIoSpace",
                        size=4, api_target="MmMapIoSpace",
                    ),
                ],
                successors=[],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x7000)
        ir.is_arm64 = True

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x7000,
                api_name="MmMapIoSpace",
                instruction_address=0x7030,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        for c in chains:
            assert "integer_overflow" not in c.context.get("missing_checks", [])

    def test_arm64_mull_before_cmp_flags_overflow(self):
        """ARM64: smull (signed multiply long) before cmp should flag overflow."""
        blocks = [
            BasicBlock(
                address=0x8000, end_address=0x8020,
                instructions=[
                    Instruction(address=0x8000, mnemonic="smull", operands="x0, w1, w2", size=4),
                    Instruction(address=0x8008, mnemonic="cmp", operands="x0, #0x1000", size=4),
                    Instruction(address=0x8010, mnemonic="b.hi", operands="0x8100", size=4),
                ],
                successors=[0x8020],
            ),
            BasicBlock(
                address=0x8020, end_address=0x8040,
                instructions=[
                    Instruction(
                        address=0x8020, mnemonic="bl",
                        operands="MmMapIoSpace",
                        size=4, api_target="MmMapIoSpace",
                    ),
                ],
                successors=[],
            ),
        ]
        ir = make_ir_with_cfg_and_blocks(blocks, handler_addr=0x8000)
        ir.is_arm64 = True

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x8000,
                api_name="MmMapIoSpace",
                instruction_address=0x8020,
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        assert "integer_overflow" in chains[0].context.get("missing_checks", [])