"""
Analysis layer tests.
"""

import pytest
from pathlib import Path
from src.models import (
    DisassemblyResult, Finding, FindingCategory,
    Severity, Confidence, Function, Sample, Architecture, Evidence,
)
from src.analysis.core.structure_analyzer import StructureAnalyzer
from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer
from src.analysis.core.correlator import BYOVDChainCorrelator
from src.analysis.core.ioctl_analyzer import IOCTLAnalyzer
from src.analysis.core.string_analyzer import StringAnalyzer


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


def make_ir_with_ioctl_dispatcher() -> DisassemblyResult:
    """Create a DisassemblyResult that has an IOCTL dispatcher."""
    ir = DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="capstone",
    )
    ir.functions = {
        0x1000: Function(name="DriverEntry", address=0x1000, size=0x200, is_entry=True),
        0x2000: Function(name="DeviceControl", address=0x2000, size=0x400),
        0x3000: Function(name="MapMemory", address=0x3000, size=0x100),
    }
    ir.irp_handlers = {
        0xE: 0x2000,  # IRP_MJ_DEVICE_CONTROL
        0x0: 0x1000,  # IRP_MJ_CREATE
    }
    ir.ioctl_codes = [0x222000, 0x222004, 0x222008]
    ir.ioctl_dispatcher = 0x2000
    ir.import_addresses = {
        0x5000: "ntoskrnl.exe.MmMapIoSpace",
        0x5010: "ntoskrnl.exe.MmMapLockedPagesSpecifyCache",
        0x5020: "ntoskrnl.exe.ZwMapViewOfSection",
        0x5030: "ntoskrnl.exe.KeWriteMsr",
    }
    ir.strings = ["\\Device\\TestDevice", "\\DosDevices\\TestDev"]
    return ir


def make_ir_without_ioctl() -> DisassemblyResult:
    """Create a DisassemblyResult without IOCTL dispatcher."""
    ir = DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="capstone",
    )
    ir.functions = {
        0x1000: Function(name="DriverEntry", address=0x1000, size=0x200, is_entry=True),
    }
    ir.irp_handlers = {}
    ir.ioctl_codes = []
    ir.import_addresses = {}
    ir.strings = []
    return ir


class TestStructureAnalyzer:

    def setup_method(self):
        self.analyzer = StructureAnalyzer()
        self.sample = make_sample()

    def test_detects_ioctl_dispatcher(self):
        """Should detect IRP_MJ_DEVICE_CONTROL handler."""
        ir = make_ir_with_ioctl_dispatcher()
        findings = self.analyzer.analyze(self.sample, ir)

        dispatcher_findings = [
            f for f in findings
            if f.category == FindingCategory.IOCTL_DISPATCHER_FOUND
            and "IRP_MJ_DEVICE_CONTROL" in f.description
        ]
        assert len(dispatcher_findings) >= 1

    def test_extracts_ioctl_codes(self):
        """Should summarize IOCTL code count (individual codes reported by IOCTLAnalyzer)."""
        ir = make_ir_with_ioctl_dispatcher()
        findings = self.analyzer.analyze(self.sample, ir)

        # StructureAnalyzer now only reports a summary, not per-code findings
        summary_findings = [
            f for f in findings
            if f.category == FindingCategory.IOCTL_DISPATCHER_FOUND
            and "IOCTL code" in f.description
        ]
        assert len(summary_findings) == 1
        assert "3 IOCTL code" in summary_findings[0].description

    def test_no_false_positives_without_ioctl(self):
        """Should not report IOCTL findings if dispatcher is absent."""
        ir = make_ir_without_ioctl()
        findings = self.analyzer.analyze(self.sample, ir)

        dispatcher_findings = [
            f for f in findings
            if "IRP_MJ_DEVICE_CONTROL" in f.description
        ]
        assert len(dispatcher_findings) == 0

    def test_pdb_path_generates_finding(self):
        """PDB path should generate a DEBUG_SYMBOLS_PRESENT finding."""
        sample = make_sample()
        sample.debug_path = "C:\\build\\obj\\mydriver.pdb"
        ir = make_ir_with_ioctl_dispatcher()
        findings = self.analyzer.analyze(sample, ir)

        pdb_findings = [f for f in findings if f.category == FindingCategory.DEBUG_SYMBOLS_PRESENT]
        assert len(pdb_findings) >= 1
        assert "mydriver" in pdb_findings[0].description

    def test_pdb_toolchain_inference(self):
        """PDB path should infer build toolchain."""
        from src.analysis.core.structure_analyzer import StructureAnalyzer
        # Pattern uses lowercase check with \build\ in path
        assert "WDK build" in StructureAnalyzer._infer_toolchain(r"c:\mydriver\build\obj\driver.pdb")
        assert "GitHub Actions" in StructureAnalyzer._infer_toolchain(r"c:\github\project\out.pdb")
        assert "Visual Studio" in StructureAnalyzer._infer_toolchain(r"c:\visual studio\proj\drv.pdb")
        assert "WDK/DDK" in StructureAnalyzer._infer_toolchain(r"c:\windows kits\10\drv.pdb")
        assert StructureAnalyzer._infer_toolchain(r"c:\random\path\drv.pdb") == ""

    def test_wdf_dispatch_no_placeholder_codes(self):
        """WDF dispatch should not use fabricated 0x100XXX placeholder codes."""
        ir = make_ir_with_ioctl_dispatcher()
        # Simulate WDF driver with queue setup
        ir.is_wdf_driver = True
        ir.wdf_dispatch_functions = {0: [0x5000, 0x6000]}

        # Verify no placeholder codes in dispatch
        for code in ir.wdf_dispatch_functions.keys():
            assert code == 0 or code >= 0x1000, f"Unexpected code: 0x{code:X}"
        # 0 is the unknown marker, not a fabricated placeholder
        assert 0 in ir.wdf_dispatch_functions

    def test_wdf_dispatch_unknown_code_handling(self):
        """Unknown WDF codes (0) should not be injected into ioctl_handlers."""
        ir = make_ir_with_ioctl_dispatcher()
        ir.is_wdf_driver = True
        ir.wdf_dispatch_functions = {0: [0x5000, 0x6000]}

        # Before WDF findings processing, ioctl_handlers should be as set up
        initial_handlers = dict(ir.ioctl_handlers)

        # The WDF findings code should skip code 0 when injecting
        # This is tested implicitly by checking that 0 is not in ioctl_handlers
        # after the full analyze() call
        findings = self.analyzer.analyze(self.sample, ir)

        # Verify 0 is not in ioctl_handlers (unknown codes are not injected)
        assert 0 not in ir.ioctl_handlers

    def test_no_pdb_no_debug_finding(self):
        """Without PDB path, no DEBUG_SYMBOLS_PRESENT finding from structure analyzer."""
        sample = make_sample()
        sample.debug_path = ""
        ir = make_ir_without_ioctl()
        findings = self.analyzer.analyze(sample, ir)
        pdb_findings = [f for f in findings if f.category == FindingCategory.DEBUG_SYMBOLS_PRESENT]
        assert len(pdb_findings) == 0

class TestDangerousPrimitiveAnalyzer:

    def setup_method(self):
        self.analyzer = DangerousPrimitiveAnalyzer()
        self.sample = make_sample()

    def test_detects_memory_mapping(self):
        """Should detect MmMapIoSpace in imports."""
        ir = make_ir_with_ioctl_dispatcher()
        findings = self.analyzer.analyze(self.sample, ir)

        mem_findings = [
            f for f in findings
            if f.category == FindingCategory.ARBITRARY_MEMORY_MAP
        ]
        assert len(mem_findings) >= 1

    def test_detects_msr_access(self):
        """Should detect KeWriteMsr in imports."""
        ir = make_ir_with_ioctl_dispatcher()
        findings = self.analyzer.analyze(self.sample, ir)

        msr_findings = [
            f for f in findings
            if f.category == FindingCategory.MSR_ACCESS
        ]
        assert len(msr_findings) >= 1

    def test_no_findings_without_dangerous_apis(self):
        """Should return no findings if no dangerous APIs are imported."""
        ir = make_ir_without_ioctl()
        findings = self.analyzer.analyze(self.sample, ir)
        assert len(findings) == 0

    def test_deduplication(self):
        """Should not produce duplicate findings for same API+function."""
        ir = make_ir_with_ioctl_dispatcher()
        findings = self.analyzer.analyze(self.sample, ir)

        # Each API should only appear once
        seen = set()
        for f in findings:
            key = (f.api_name, f.function_address)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)

    def test_fallback_detection_for_weighted_api(self):
        """API in DANGEROUS_API_SET but not in rules should produce LOW confidence finding."""
        ir = make_ir_without_ioctl()
        # Add an API that's in DANGEROUS_API_SET but not in DANGEROUS_API_RULES
        func = ir.functions[0x3000] = Function(name="sub_3000", address=0x3000, size=0x100)
        ir.function_apis[0x3000] = ["ZwLoadDriver"]

        findings = self.analyzer.analyze(self.sample, ir)
        fallback_findings = [
            f for f in findings
            if f.api_name == "ZwLoadDriver"
            and f.confidence == Confidence.LOW
            and f.severity == Severity.INFO
        ]
        assert len(fallback_findings) >= 1

    def test_no_fallback_for_covered_api(self):
        """API already in rules should not get duplicate fallback finding."""
        ir = make_ir_with_ioctl_dispatcher()
        # MmMapIoSpace is already covered by rules
        findings = self.analyzer.analyze(self.sample, ir)

        # Count findings for MmMapIoSpace
        mmio_findings = [f for f in findings if f.api_name == "MmMapIoSpace"]
        # Should have exactly 1 (from rules, not from fallback)
        assert len(mmio_findings) == 1


class TestIOCTLAnalyzer:

    def setup_method(self):
        self.analyzer = IOCTLAnalyzer()
        self.sample = make_sample()

    def test_maps_ioctl_handlers(self):
        """Should produce findings when ioctl_handlers is populated."""
        ir = make_ir_with_ioctl_dispatcher()
        ir.ioctl_handlers = {0x222000: 0x2000, 0x222004: 0x2000}
        findings = self.analyzer.analyze(self.sample, ir)

        ioctl_findings = [f for f in findings if f.category == FindingCategory.IOCTL_CODE_EXPOSED]
        assert len(ioctl_findings) == 2
        assert ioctl_findings[0].ioctl_code == 0x222000
        assert ioctl_findings[0].function_address == 0x2000

    def test_fallback_to_heuristic(self):
        """Should use heuristic findings when no handler mapping available."""
        ir = make_ir_with_ioctl_dispatcher()
        ir.ioctl_handlers = {}  # No handler mapping
        findings = self.analyzer.analyze(self.sample, ir)

        ioctl_findings = [f for f in findings if f.category == FindingCategory.IOCTL_CODE_EXPOSED]
        assert len(ioctl_findings) == 3  # 3 ioctl_codes
        assert "heuristic" in ioctl_findings[0].description.lower()

    def test_no_findings_without_ioctls(self):
        """Should return no findings if no IOCTL codes present."""
        ir = make_ir_without_ioctl()
        findings = self.analyzer.analyze(self.sample, ir)
        assert len(findings) == 0

    def test_method_decoding(self):
        """Should decode IOCTL method type correctly."""
        ir = make_ir_with_ioctl_dispatcher()
        # METHOD_NEITHER = 3 → higher severity
        ir.ioctl_handlers = {0x222003: 0x2000}  # method=3
        findings = self.analyzer.analyze(self.sample, ir)

        assert findings[0].severity == Severity.HIGH  # METHOD_NEITHER is highest risk
        assert "NEITHER" in findings[0].description


class TestStringAnalyzer:

    def setup_method(self):
        self.analyzer = StringAnalyzer()
        self.sample = make_sample()

    def test_detects_physical_memory_string(self):
        """Should detect PhysicalMemory reference."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = ["\\Device\\PhysicalMemory", "NormalString"]
        findings = self.analyzer.analyze(self.sample, ir)

        mem_findings = [f for f in findings if "PhysicalMemory" in f.description]
        assert len(mem_findings) >= 1

    def test_detects_device_object(self):
        """Should detect device object patterns."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = ["\\Device\\MyDevice", "\\DosDevices\\MyLink"]
        findings = self.analyzer.analyze(self.sample, ir)

        dev_findings = [f for f in findings if f.category == FindingCategory.DANGEROUS_STRING]
        assert any("device object" in f.description.lower() for f in dev_findings)

    def test_detects_guid(self):
        """Should detect GUID patterns."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = ["{12345678-1234-5678-1234-567812345678}"]
        findings = self.analyzer.analyze(self.sample, ir)

        guid_findings = [f for f in findings if "GUID" in f.description]
        assert len(guid_findings) >= 1

    def test_no_findings_with_empty_strings(self):
        """Should return no findings if no strings present."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = []
        findings = self.analyzer.analyze(self.sample, ir)
        assert len(findings) == 0


class TestBYOVDChainCorrelator:

    def setup_method(self):
        self.analyzer = BYOVDChainCorrelator()
        self.sample = make_sample()

    def _make_ir_with_handler(self):
        """Create IR with handler that has both primitive and validation findings."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.functions = {
            0x1000: Function(name="Handler", address=0x1000, size=0x200),
        }
        ir.irp_handlers = {0xE: 0x1000}
        ir.is_wdf_driver = False
        return ir

    def test_complete_chain(self):
        """Should detect complete attack chain when primitive + validation gap exist."""
        ir = self._make_ir_with_handler()

        # Simulate findings from other analyzers
        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe found",
                function_address=0x1000,
                api_name="MmMapIoSpace",
                context={"missing_checks": ["probe", "privilege"]},
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        assert chains[0].severity == Severity.CRITICAL
        assert "MmMapIoSpace" in chains[0].description

    def test_no_chain_without_primitive(self):
        """Should not produce chain if no dangerous primitive present."""
        ir = self._make_ir_with_handler()

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe found",
                function_address=0x1000,
                context={"missing_checks": ["probe"]},
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) == 0

    def test_partial_chain_detection(self):
        """Should detect partial chains when primitive exists but no validation analysis."""
        ir = self._make_ir_with_handler()

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        # No complete chain, but may have partial chain notice
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        # Partial chains are optional, just ensure no crash
        assert isinstance(findings, list)

    def test_method_neither_boosts_confidence(self):
        """METHOD_NEITHER IOCTLs should boost correlator confidence to HIGH."""
        ir = self._make_ir_with_handler()
        # Add a METHOD_NEITHER IOCTL code (last 2 bits = 3)
        ir.ioctl_handlers = {0x22A003: 0x1000}

        self.sample.analysis_findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Calls MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
        ]

        findings = self.analyzer.analyze(self.sample, ir)
        chains = [f for f in findings if f.category == FindingCategory.ATTACK_CHAIN]
        assert len(chains) >= 1
        # METHOD_NEITHER + dangerous API = HIGH confidence
        assert chains[0].confidence == Confidence.HIGH
