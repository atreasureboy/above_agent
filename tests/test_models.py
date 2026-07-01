"""Tests for core data models: serialization, edge cases, defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models import (
    APICallInfo,
    Architecture,
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Report,
    RiskScore,
    Sample,
    Severity,
    SignatureStatus,
    score_level,
)


# ------------------------------------------------------------------
# Test SignatureStatus
# ------------------------------------------------------------------

class TestSignatureStatus:
    def test_all_values(self):
        assert SignatureStatus.UNSIGNED.value == "unsigned"
        assert SignatureStatus.SIGNED_VALID.value == "signed_valid"
        assert SignatureStatus.SIGNED_INVALID.value == "signed_invalid"
        assert SignatureStatus.SIGNED_EXPIRED.value == "signed_expired"
        assert SignatureStatus.SIGNED_UNTRUSTED.value == "signed_untrusted"


# ------------------------------------------------------------------
# Test Architecture
# ------------------------------------------------------------------

class TestArchitecture:
    def test_all_values(self):
        assert Architecture.X86.value == "x86"
        assert Architecture.X64.value == "x64"
        assert Architecture.ARM64.value == "arm64"
        assert Architecture.UNKNOWN.value == "unknown"


# ------------------------------------------------------------------
# Test Sample
# ------------------------------------------------------------------

class TestSample:
    def _make_sample(self, **kwargs) -> Sample:
        return Sample(
            path=Path("test.sys"),
            name="test.sys",
            company="TestCorp",
            version="1.0.0.0",
            arch=Architecture.X64,
            sha256="abc123",
            size=4096,
            **kwargs,
        )

    def test_defaults(self):
        s = self._make_sample()
        assert s.imports == []
        assert s.exports == []
        assert s.sections == []
        assert s.entry_point == 0
        assert s.compile_timestamp == 0
        assert s.debug_path == ""
        assert s.is_driver is False
        assert s.driver_type == ""
        assert s.subsystem == ""
        assert s.signature_status == SignatureStatus.UNSIGNED
        assert s.signer_name == ""
        assert s.disassembly_result is None
        assert s.analysis_findings == []
        assert s.risk_score == 0.0
        assert s.is_usermode is False
        assert s.binary_type == ""
        assert s.com_interfaces == []
        assert s.service_info == {}
        assert s.embedded_files == []
        assert s.dynamic_results == []

    def test_is_wdm(self):
        s = self._make_sample(driver_type="WDM")
        assert s.is_wdm() is True
        assert s.is_wdf() is False

    def test_is_wdf(self):
        s = self._make_sample(driver_type="WDF/KMDF")
        assert s.is_wdf() is True
        assert s.is_wdm() is False

    def test_is_wdf_umdf(self):
        s = self._make_sample(driver_type="WDF/UMDF")
        assert s.is_wdf() is True

    def test_is_not_wdm_or_wdf(self):
        s = self._make_sample(driver_type="")
        assert s.is_wdm() is False
        assert s.is_wdf() is False

    def test_usermode_fields(self):
        s = self._make_sample(
            is_usermode=True,
            binary_type="exe",
            com_interfaces=["{00000000-0000-0000-0000-000000000001}"],
        )
        assert s.is_usermode is True
        assert s.binary_type == "exe"
        assert len(s.com_interfaces) == 1


# ------------------------------------------------------------------
# Test Function
# ------------------------------------------------------------------

class TestFunction:
    def test_defaults(self):
        f = Function(name="sub_1000", address=0x1000, size=0x100)
        assert f.called_by == []
        assert f.calls == []
        assert f.is_entry is False
        assert f.is_ioctl_handler is False
        assert f.pseudo_code == ""
        assert f.signature == ""
        assert f.local_vars == []

    def test_full(self):
        f = Function(
            name="DriverEntry",
            address=0x1000,
            size=0x200,
            called_by=[0x2000],
            calls=[0x1500, 0x1600],
            is_entry=True,
            pseudo_code="NTSTATUS DriverEntry(...)",
            signature="NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)",
            local_vars=[{"name": "status", "type": "NTSTATUS", "stack_offset": -8}],
        )
        assert len(f.calls) == 2
        assert len(f.called_by) == 1
        assert "DriverEntry" in f.signature


# ------------------------------------------------------------------
# Test Instruction
# ------------------------------------------------------------------

class TestInstruction:
    def test_defaults(self):
        i = Instruction(address=0x100, mnemonic="mov", operands="eax, ebx")
        assert i.api_target == ""
        assert i.api_info is None
        assert i.size == 0

    def test_with_api(self):
        i = Instruction(
            address=0x100,
            mnemonic="call",
            operands="qword ptr [rip+0x100]",
            api_target="ntoskrnl.MmMapIoSpaceEx",
            api_info=APICallInfo(name="MmMapIoSpaceEx", call_address=0x100),
            size=6,
        )
        assert i.api_target != ""
        assert i.api_info is not None
        assert i.api_info.name == "MmMapIoSpaceEx"


# ------------------------------------------------------------------
# Test APICallInfo
# ------------------------------------------------------------------

class TestAPICallInfo:
    def test_defaults(self):
        a = APICallInfo(name="ZwCreateFile", call_address=0x1234)
        assert a.params_hint == ""
        assert a.user_controllable is False


# ------------------------------------------------------------------
# Test BasicBlock
# ------------------------------------------------------------------

class TestBasicBlock:
    def test_defaults(self):
        b = BasicBlock(address=0x1000, end_address=0x1050)
        assert b.successors == []
        assert b.predecessors == []
        assert b.instructions == []

    def test_with_instructions(self):
        insns = [
            Instruction(address=0x1000, mnemonic="push", operands="rbp", size=1),
            Instruction(address=0x1001, mnemonic="mov", operands="rbp, rsp", size=3),
        ]
        b = BasicBlock(
            address=0x1000, end_address=0x1004,
            instructions=insns,
            successors=[0x1010],
        )
        assert len(b.instructions) == 2
        assert b.successors == [0x1010]


# ------------------------------------------------------------------
# Test CFG
# ------------------------------------------------------------------

class TestCFG:
    def test_defaults(self):
        c = CFG(function_address=0x1000)
        assert c.blocks == {}
        assert c.entry_block == 0

    def test_with_blocks(self):
        c = CFG(function_address=0x1000, entry_block=0x1000)
        c.blocks[0x1000] = BasicBlock(address=0x1000, end_address=0x1010)
        c.blocks[0x1010] = BasicBlock(address=0x1010, end_address=0x1020)
        assert len(c.blocks) == 2


# ------------------------------------------------------------------
# Test DisassemblyResult
# ------------------------------------------------------------------

class TestDisassemblyResult:
    def test_defaults(self):
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        assert ir.functions == {}
        assert ir.cfgs == {}
        assert ir.simple_cfgs == {}
        assert ir.ioctl_codes == []
        assert ir.ioctl_dispatcher == 0
        assert ir.irp_handlers == {}
        assert ir.ioctl_handlers == {}
        assert ir.import_addresses == {}
        assert ir.function_apis == {}
        assert ir.function_api_details == {}
        assert ir.strings == []
        assert ir.is_wdf_driver is False
        assert ir.is_arm64 is False
        assert ir.is_filter_driver is False
        assert ir.dynamic_imports == {}
        assert ir.deferred_callbacks == {}
        assert ir.wdf_dispatch_functions == {}
        assert ir.wdf_context_objects == {}
        assert ir.wdf_io_queue_configs == []
        assert ir.fastio_handlers == {}
        assert ir.wmi_handlers == {}
        assert ir.minifilter_handlers == {}
        assert ir.is_minifilter is False
        assert ir.mmio_surfaces == []
        assert ir.data_xrefs == {}
        assert ir.struct_types == {}
        assert ir.type_info == {}
        assert ir.stack_strings == []
        assert ir.wide_strings == []
        assert ir.data_structures == {}
        assert ir.data_references == []
        assert ir.comparison_traces == []
        assert ir.string_locations == []
        assert ir.string_rvas == {}
        assert ir.callback_registrations == []
        assert ir.filter_callbacks == []


# ------------------------------------------------------------------
# Test Severity
# ------------------------------------------------------------------

class TestSeverity:
    def test_all_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


# ------------------------------------------------------------------
# Test Confidence
# ------------------------------------------------------------------

class TestConfidence:
    def test_all_values(self):
        assert Confidence.CERTAIN.value == 1.0
        assert Confidence.HIGH.value == 0.9
        assert Confidence.MEDIUM.value == 0.7
        assert Confidence.LOW.value == 0.4


# ------------------------------------------------------------------
# Test FindingCategory
# ------------------------------------------------------------------

class TestFindingCategory:
    def test_memory_categories(self):
        assert FindingCategory.ARBITRARY_MEMORY_MAP.value == "arbitrary_memory_map"
        assert FindingCategory.PHYSICAL_MEMORY_ACCESS.value == "physical_memory_access"

    def test_dataflow_categories(self):
        assert FindingCategory.UNVALIDATED_USER_INPUT.value == "unvalidated_user_input"
        assert FindingCategory.MISSING_SIZE_CHECK.value == "missing_size_check"
        assert FindingCategory.PARTIAL_VALIDATION.value == "partial_validation"

    def test_anti_debug_categories(self):
        assert FindingCategory.ANTI_DEBUG_TIMING.value == "anti_debug_timing"
        assert FindingCategory.ANTI_DEBUG_HYPERVISOR.value == "anti_debug_hypervisor"
        assert FindingCategory.CONTROL_FLOW_FLATTENING.value == "control_flow_flattening"

    def test_dynamic_categories(self):
        assert FindingCategory.DYNAMIC_CRASH_CONFIRMED.value == "dynamic_crash_confirmed"
        assert FindingCategory.DYNAMIC_IOCTL_VALIDATED.value == "dynamic_ioctl_validated"


# ------------------------------------------------------------------
# Test Evidence
# ------------------------------------------------------------------

class TestEvidence:
    def test_basic(self):
        e = Evidence(
            type="import",
            location="IAT@0x12340",
            snippet="ntoskrnl.MmMapIoSpace",
            rule_id="PRIM_001",
        )
        assert e.type == "import"
        assert e.rule_id == "PRIM_001"


# ------------------------------------------------------------------
# Test Finding
# ------------------------------------------------------------------

class TestFinding:
    def _make_finding(self, **kwargs) -> Finding:
        return Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Test",
            **kwargs,
        )

    def test_defaults(self):
        f = self._make_finding()
        assert f.function_address == 0
        assert f.instruction_address == 0
        assert f.api_name == ""
        assert f.ioctl_code == 0
        assert f.context == {}
        assert f.evidence == []

    def test_to_dict_basic(self):
        f = self._make_finding(
            function_address=0x1000,
            instruction_address=0x1050,
            api_name="MmMapIoSpaceEx",
            ioctl_code=0x22E004,
        )
        d = f.to_dict()
        assert d["category"] == "arbitrary_memory_map"
        assert d["severity"] == "critical"
        assert d["confidence"] == 0.9
        assert d["function_address"] == "0x1000"
        assert d["instruction_address"] == "0x1050"
        assert d["api_name"] == "MmMapIoSpaceEx"
        assert d["ioctl_code"] == "0x22e004"

    def test_to_dict_zero_addresses(self):
        f = self._make_finding()
        d = f.to_dict()
        assert d["function_address"] == 0
        assert d["instruction_address"] == 0
        assert d["ioctl_code"] == 0

    def test_to_dict_with_evidence(self):
        f = self._make_finding(
            evidence=[
                Evidence(type="import", location="IAT@0x12340", snippet="ntoskrnl.ZwXxx", rule_id="X001"),
            ]
        )
        d = f.to_dict()
        assert len(d["evidence"]) == 1
        assert d["evidence"][0]["type"] == "import"
        assert d["evidence"][0]["rule_id"] == "X001"

    def test_to_dict_with_context(self):
        f = self._make_finding(
            context={"capability": "memory_primitive", "validated": False}
        )
        d = f.to_dict()
        assert d["context"]["capability"] == "memory_primitive"
        assert d["context"]["validated"] is False

    def test_to_dict_evidence_as_dict(self):
        """Evidence already as dict should pass through."""
        f = self._make_finding(
            evidence=[{"type": "custom", "location": "X", "snippet": "Y", "rule_id": "Z"}]
        )
        d = f.to_dict()
        assert d["evidence"][0]["type"] == "custom"


# ------------------------------------------------------------------
# Test RiskScore
# ------------------------------------------------------------------

class TestRiskScore:
    def test_level_critical(self):
        assert RiskScore(overall=10.0, breakdown={}).level == "CRITICAL"

    def test_level_high(self):
        assert RiskScore(overall=7.0, breakdown={}).level == "HIGH"

    def test_level_medium(self):
        assert RiskScore(overall=4.0, breakdown={}).level == "MEDIUM"

    def test_level_low(self):
        assert RiskScore(overall=1.0, breakdown={}).level == "LOW"

    def test_level_none(self):
        assert RiskScore(overall=0.5, breakdown={}).level == "NONE"

    def test_breakdown(self):
        r = RiskScore(
            overall=8.5,
            breakdown={
                "primitive": 9.0,
                "validation": 7.0,
                "signature": 8.0,
            },
        )
        assert r.level == "HIGH"  # Based on overall=8.5, not breakdown max
        assert r.breakdown["primitive"] == 9.0


# ------------------------------------------------------------------
# Test score_level
# ------------------------------------------------------------------

class TestScoreLevel:
    @pytest.mark.parametrize("score,expected", [
        (10.0, "CRITICAL"),
        (9.0, "CRITICAL"),
        (8.5, "HIGH"),
        (7.0, "HIGH"),
        (5.0, "MEDIUM"),
        (4.0, "MEDIUM"),
        (2.0, "LOW"),
        (1.0, "LOW"),
        (0.9, "NONE"),
        (0.0, "NONE"),
    ])
    def test_boundaries(self, score, expected):
        assert score_level(score) == expected


# ------------------------------------------------------------------
# Test Report
# ------------------------------------------------------------------

class TestReport:
    def _make_sample(self, risk: float = 0.0) -> Sample:
        s = Sample(
            path=Path(f"test{int(risk)}.sys"),
            name=f"test{int(risk)}.sys",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256=f"hash{int(risk)}",
            size=1000,
        )
        s.risk_score = risk
        return s

    def test_defaults(self):
        r = Report(samples=[], timestamp="2026-01-01", tool_version="1.0", backend="capstone")
        assert r.total_analyzed == 0
        assert r.total_findings == 0
        assert r.summary == {}

    def test_top_n_empty(self):
        r = Report(samples=[], timestamp="T", tool_version="V", backend="capstone")
        assert r.top_n(10) == []

    def test_top_n_all_zero(self):
        samples = [self._make_sample(0.0) for _ in range(3)]
        r = Report(samples=samples, timestamp="T", tool_version="V", backend="capstone")
        assert r.top_n(10) == []  # risk_score == 0 filtered out

    def test_top_n_sorted(self):
        samples = [self._make_sample(3.0), self._make_sample(8.0), self._make_sample(5.0)]
        r = Report(samples=samples, timestamp="T", tool_version="V", backend="capstone")
        top = r.top_n(10)
        assert len(top) == 3
        assert top[0].risk_score == 8.0
        assert top[1].risk_score == 5.0
        assert top[2].risk_score == 3.0

    def test_top_n_limit(self):
        samples = [self._make_sample(i) for i in range(1, 6)]
        r = Report(samples=samples, timestamp="T", tool_version="V", backend="capstone")
        top = r.top_n(2)
        assert len(top) == 2
        assert top[0].risk_score == 5.0

    def test_top_n_more_than_available(self):
        samples = [self._make_sample(3.0)]
        r = Report(samples=samples, timestamp="T", tool_version="V", backend="capstone")
        top = r.top_n(100)
        assert len(top) == 1
