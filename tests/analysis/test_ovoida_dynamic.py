"""Tests for OVOIDA engine and dynamic validator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    APICallInfo,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Severity,
    Confidence,
)


def _make_mock_ir() -> DisassemblyResult:
    """Create a minimal DisassemblyResult for testing."""
    ir = DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="capstone",
    )
    handler = Function(name="sub_140001000", address=0x140001000, size=0x200)
    handler.calls = [0x140002000]
    ir.functions[handler.address] = handler
    helper = Function(name="sub_140002000", address=0x140002000, size=0x100)
    ir.functions[helper.address] = helper
    cfg = CFG(function_address=handler.address, entry_block=0x140001000)
    block = BasicBlock(
        address=0x140001000,
        end_address=0x140001200,
        instructions=[
            MagicMock(address=0x140001010, mnemonic="mov", operands="rax, rcx", api_target=None, api_info=None),
        ],
        successors=[],
    )
    cfg.blocks[0x140001000] = block
    ir.cfgs[handler.address] = ir.simple_cfgs[handler.address] = cfg
    ir.ioctl_handlers[0x22A004] = handler.address
    ir.function_apis[helper.address] = ["MmMapIoSpaceEx"]
    ir.function_api_details[helper.address] = [
        APICallInfo(name="MmMapIoSpaceEx", call_address=0x140002050),
    ]
    return ir


def _make_mock_sample() -> MagicMock:
    """Create a mock Sample for testing."""
    sample = MagicMock()
    sample.name = "TestDriver"
    sample.driver_type = "TestDrv"
    sample.risk_score = 8.5
    sample.sha256 = "a" * 64
    return sample


# ---------------------------------------------------------------------------
# OVOIDA Engine Tests
# ---------------------------------------------------------------------------

class TestOvoidaEngine:
    """Test the OVOIDA deep analysis engine."""

    def test_init_default_backend(self):
        """Engine defaults to ghidra backend."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        assert engine.backend == "ghidra"

    def test_init_custom_backend(self):
        """Engine accepts custom backend."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine(backend="capstone")
        assert engine.backend == "capstone"

    def test_analyze_basic(self):
        """Engine produces OvoidaResult on analysis."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_ir = _make_mock_ir()
        mock_sample = _make_mock_sample()
        findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="MmMapIoSpaceEx without validation",
                function_address=0x140001000,
                api_name="MmMapIoSpaceEx",
                instruction_address=0x140001050,
            ),
        ]

        with patch("src.analysis.dataflow.input_tracker.run_taint_analysis") as mock_taint:
            mock_taint.return_value = MagicMock(
                tainted_reaches_dangerous_api=True,
                sources=[],
                sinks=[],
            )
            result = engine.analyze(mock_sample, mock_ir, phase1_findings=findings)

            assert result.sample_name == "TestDriver"
            assert result.risk_score == 8.5
            assert result.functions_analyzed >= 1
            assert result.elapsed >= 0

    def test_identify_critical_functions_from_findings(self):
        """Critical functions are identified from Phase 1 findings."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_ir = _make_mock_ir()
        mock_sample = _make_mock_sample()

        findings = [
            Finding(
                category=FindingCategory.MSR_ACCESS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="KeWriteMsr",
                function_address=0x140001000,
                api_name="KeWriteMsr",
            ),
        ]
        critical = engine._identify_critical_functions(mock_sample, mock_ir, findings)
        assert len(critical) >= 1
        assert critical[0]["address"] == 0x140001000
        assert critical[0]["severity"] == "critical"

    def test_build_exploit_chains(self):
        """Exploit chains are built from function analysis results."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140001000",
                "name": "sub_140001000",
                "api_calls": ["MmMapIoSpaceEx"],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": True,
                "taint_sources": ["SystemBuffer@0x60"],
                "taint_sinks": ["MmMapIoSpaceEx(rcx)"],
            },
        ]

        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) >= 1
        assert chains[0]["severity"] == "CRITICAL"
        assert chains[0]["user_controllable"] is True

    def test_build_exploit_chains_safe_function(self):
        """Functions with full validation are excluded from chains."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140001000",
                "name": "sub_140001000",
                "api_calls": ["MmMapIoSpaceEx"],
                "has_validation": True,
                "has_privilege_check": True,
                "has_size_check": True,
                "taint_reaches_api": False,
                "taint_sources": [],
                "taint_sinks": [],
            },
        ]

        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) == 0

    def test_exploit_chain_dma_primitive(self):
        """WdfDmaEnablerCreate should trigger exploit chain."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140003000",
                "name": "sub_140003000",
                "api_calls": ["WdfDmaEnablerCreate", "WdfDmaTransactionCreate"],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": True,
                "taint_sources": ["UserBuffer"],
                "taint_sinks": ["WdfDmaEnablerCreate"],
            },
        ]
        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) >= 1
        assert "WdfDmaEnablerCreate" in chains[0]["dangerous_apis"]

    def test_exploit_chain_interrupt_hooking(self):
        """IoConnectInterrupt should trigger exploit chain."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140004000",
                "name": "sub_140004000",
                "api_calls": ["IoConnectInterrupt"],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": True,
                "taint_sources": ["Input"],
                "taint_sinks": ["IoConnectInterrupt"],
            },
        ]
        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) >= 1
        assert "IoConnectInterrupt" in chains[0]["dangerous_apis"]

    def test_exploit_chain_callback_registration(self):
        """PsSetLoadImageNotifyRoutine should trigger exploit chain."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140005000",
                "name": "sub_140005000",
                "api_calls": ["PsSetLoadImageNotifyRoutine"],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": False,
                "taint_sources": [],
                "taint_sinks": [],
            },
        ]
        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) >= 1
        assert "PsSetLoadImageNotifyRoutine" in chains[0]["dangerous_apis"]

    def test_exploit_chain_physical_memory(self):
        """MmGetPhysicalAddress should trigger exploit chain."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140006000",
                "name": "sub_140006000",
                "api_calls": ["MmGetPhysicalAddress"],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": False,
                "taint_sources": [],
                "taint_sinks": [],
            },
        ]
        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) >= 1
        assert "MmGetPhysicalAddress" in chains[0]["dangerous_apis"]

    def test_exploit_chain_driver_loading(self):
        """ZwLoadDriver should trigger exploit chain."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        mock_sample = _make_mock_sample()
        mock_ir = _make_mock_ir()

        functions_detail = [
            {
                "address": "0x140007000",
                "name": "sub_140007000",
                "api_calls": ["ZwLoadDriver"],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": False,
                "taint_sources": [],
                "taint_sinks": [],
            },
        ]
        chains = engine._build_exploit_chains(functions_detail, mock_sample, mock_ir)
        assert len(chains) >= 1
        assert "ZwLoadDriver" in chains[0]["dangerous_apis"]

    def test_generate_poc_pseudocode_no_chains(self):
        """PoC pseudocode returns 'no chains' when empty."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        poc = engine._generate_poc_pseudocode([])
        assert "No exploit chains detected" in poc

    def test_generate_poc_pseudocode_with_chains(self):
        """PoC pseudocode is generated when chains exist."""
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        engine = OvoidaEngine()
        chains = [
            {
                "name": "TestDriver",
                "severity": "CRITICAL",
                "function": "0x140001000",
                "dangerous_apis": ["MmMapIoSpaceEx"],
                "validation": "none",
                "user_controllable": True,
            },
        ]
        poc = engine._generate_poc_pseudocode(chains)
        assert "CreateFile" in poc
        assert "DeviceIoControl" in poc


# ---------------------------------------------------------------------------
# Dynamic Validator Tests
# ---------------------------------------------------------------------------

class TestDynamicValidator:
    """Test the dynamic validation framework."""

    def test_init(self):
        """Validator initializes with empty device name."""
        from src.analysis.dynamic.validator import DynamicValidator
        v = DynamicValidator()
        assert v.device_name == ""

    def test_init_with_device(self):
        """Validator accepts device name."""
        from src.analysis.dynamic.validator import DynamicValidator
        v = DynamicValidator(device_name=r"\\.\TestDrv")
        assert v.device_name == r"\\.\TestDrv"

    def test_validate_findings_no_device(self):
        """Returns error when no device found and dynamic not enabled."""
        from src.analysis.dynamic.validator import DynamicValidator
        v = DynamicValidator()
        findings = [
            Finding(
                category=FindingCategory.ATTACK_CHAIN,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="test",
                function_address=0x140001000,
            ),
        ]
        results = v.validate_findings(findings)
        # Should return results with error since dynamic testing is disabled by default
        assert len(results) >= 1

    def test_send_ioctl_skipped_by_default(self):
        """IOCTL send returns 'skipped' when DRIVERSCOPE_DYNAMIC is not set."""
        import os
        # Ensure env var is not set
        old_val = os.environ.get("DRIVERSCOPE_DYNAMIC")
        if "DRIVERSCOPE_DYNAMIC" in os.environ:
            del os.environ["DRIVERSCOPE_DYNAMIC"]

        from src.analysis.dynamic.validator import DynamicValidator, IoctlTest
        v = DynamicValidator(device_name=r"\\.\TestDrv")
        test = IoctlTest(
            ioctl_code=0x22A004,
            input_buffer=b"",
            input_size=0,
            output_size=0,
            description="test",
        )
        result = v._send_ioctl(r"\\.\TestDrv", test, timeout=5)
        assert result == "skipped"

        # Restore
        if old_val is not None:
            os.environ["DRIVERSCOPE_DYNAMIC"] = old_val

    def test_load_driver_disabled_by_default(self):
        """Driver loading returns False when dynamic testing is disabled."""
        import os
        old_val = os.environ.get("DRIVERSCOPE_DYNAMIC")
        if "DRIVERSCOPE_DYNAMIC" in os.environ:
            del os.environ["DRIVERSCOPE_DYNAMIC"]

        from src.analysis.dynamic.validator import DynamicValidator
        v = DynamicValidator()
        assert v.load_driver(Path("nonexistent.sys")) is False

        if old_val is not None:
            os.environ["DRIVERSCOPE_DYNAMIC"] = old_val


class TestIoctlUtilities:
    """Test IOCTL code parsing and generation utilities."""

    def test_parse_ioctl_code(self):
        """Parse IOCTL code into components."""
        from src.analysis.dynamic.validator import parse_ioctl_code
        result = parse_ioctl_code(0x22A004)
        assert result["device_type"] == 0x22
        assert result["function"] == 0x801
        assert result["method"] == 0  # METHOD_BUFFERED

    def test_parse_ioctl_code_neither(self):
        """Parse METHOD_NEITHER IOCTL."""
        from src.analysis.dynamic.validator import parse_ioctl_code
        # METHOD_NEITHER = 3
        code = (0x22 << 16) | (3 << 14) | (0x801 << 2) | 3
        result = parse_ioctl_code(code)
        assert result["method"] == 3

    def test_method_name(self):
        """Get method name from code."""
        from src.analysis.dynamic.validator import method_name
        assert method_name(0) == "METHOD_BUFFERED"
        assert method_name(1) == "METHOD_IN_DIRECT"
        assert method_name(2) == "METHOD_OUT_DIRECT"
        assert method_name(3) == "METHOD_NEITHER"
        assert method_name(99) == "UNKNOWN(99)"

    def test_generate_ioctl_code(self):
        """Generate IOCTL code from components."""
        from src.analysis.dynamic.validator import generate_ioctl_code
        code = generate_ioctl_code(device_type=0x22, function=0x801, method=0)
        assert (code >> 16) & 0xFFFF == 0x22
        assert (code >> 2) & 0xFFF == 0x801
        assert code & 0x3 == 0

    def test_generate_and_parse_roundtrip(self):
        """Generated IOCTL can be parsed back to original components."""
        from src.analysis.dynamic.validator import generate_ioctl_code, parse_ioctl_code
        code = generate_ioctl_code(
            device_type=0x22,
            function=0xABC,
            method=3,
            access=1,
        )
        parsed = parse_ioctl_code(code)
        assert parsed["device_type"] == 0x22
        assert parsed["function"] == 0xABC
        assert parsed["method"] == 3
        assert parsed["access"] == 1
