"""
DriverScope -- Enhanced Dynamic Validator.

Integrates the full Phase 2 dynamic analysis framework into a unified
validation pipeline:

1. Sandbox-based driver loading (QEMU VM)
2. Before/After system state monitoring
3. WinDbg crash detection
4. PoC execution and validation
5. Finding enrichment with dynamic results

The validator orchestrates service.py, monitor.py, debugger.py,
and sandbox.py into a cohesive testing workflow.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)


# ---------------------------------------------------------------------------
# Backward-compatible dataclasses (from original stub)
# ---------------------------------------------------------------------------


@dataclass
class IoctlTest:
    """A single IOCTL test case (backward-compatible with original stub)."""
    ioctl_code: int
    input_buffer: bytes
    input_size: int
    output_size: int
    description: str
    expected_result: str = "unknown"  # success | crash | error | unknown


@dataclass
class DynamicResult:
    """Result of a dynamic validation session."""
    sample_name: str = ""
    driver_path: str = ""
    sandbox_used: bool = False
    debugger_used: bool = False
    poc_executed: bool = False
    crash_detected: bool = False
    findings_validated: list[Finding] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    system_changes: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0


@dataclass
class ValidationConfig:
    """Configuration for dynamic validation."""
    sandbox_enabled: bool = False
    debugger_enabled: bool = False
    poc_script: str = ""
    timeout_per_test: int = 30
    max_crash_retries: int = 0
    qemu_path: str = ""
    vm_image: str = ""
    snapshot_name: str = "clean"
    windbg_path: str = ""
    symbol_path: str = "srv*https://msdl.microsoft.com/download/symbols"


class DynamicValidator:
    """Unified dynamic validation engine."""

    def __init__(self, config: ValidationConfig | None = None,
                 device_name: str = ""):
        self.config = config or ValidationConfig()
        self.device_name = device_name  # Backward-compatible
        self._sandbox = None
        self._debugger = None
        self._service = None
        self._monitor = None

    def _init_components(self) -> None:
        """Lazy-initialize dynamic analysis components."""
        if self._sandbox is None and self.config.sandbox_enabled:
            from src.analysis.dynamic.sandbox import SandboxManager, SandboxConfig
            self._sandbox = SandboxManager(SandboxConfig(
                qemu_path=self.config.qemu_path,
                vm_image=self.config.vm_image,
                snapshot_name=self.config.snapshot_name,
            ))

        if self._debugger is None and self.config.debugger_enabled:
            from src.analysis.dynamic.debugger import WinDbgController
            self._debugger = WinDbgController(
                windbg_path=self.config.windbg_path,
                symbol_path=self.config.symbol_path,
            )

        if self._service is None:
            from src.analysis.dynamic.service import DriverServiceController
            self._service = DriverServiceController()

        if self._monitor is None:
            from src.analysis.dynamic.monitor import SystemMonitor
            self._monitor = SystemMonitor()

    def validate_sample(
        self,
        sample: Sample,
        ir: DisassemblyResult | None = None,
    ) -> DynamicResult:
        """Full dynamic validation of a driver sample.

        Pipeline:
        1. Initialize sandbox + debugger
        2. Capture before state
        3. Load driver
        4. Execute PoC (if provided)
        5. Capture after state + diff
        6. Check for crashes via debugger
        7. Unload driver + revert sandbox
        8. Enrich findings with dynamic results

        Args:
            sample: The driver Sample to validate.
            ir: Optional disassembly result for context.

        Returns:
            DynamicResult with validation outcomes.
        """
        start = time.time()
        result = DynamicResult(
            sample_name=sample.name,
            driver_path=str(sample.path),
            sandbox_used=self.config.sandbox_enabled,
            debugger_used=self.config.debugger_enabled,
        )

        self._init_components()

        try:
            # Step 1: Pre-validation
            if not self._pre_validate(result):
                result.elapsed = time.time() - start
                return result

            # Step 2: Before state
            before_state = self._monitor.snapshot() if self._monitor else None

            # Step 3: Load driver
            loaded = self._load_driver(sample)

            if loaded:
                # Step 4: Execute PoC
                if self.config.poc_script:
                    result.poc_executed = self._execute_poc(sample)

                # Step 5: After state + diff
                if self._monitor:
                    after_state = self._monitor.snapshot()
                    diff = self._monitor.diff(before_state, after_state)
                    result.system_changes = {
                        "new_devices": diff.new_devices,
                        "new_symlinks": diff.new_symlinks,
                        "new_processes": len(diff.new_processes),
                        "new_services": len(diff.new_services),
                    }

                    # Generate findings from system changes
                    result.new_findings.extend(
                        self._diff_to_findings(diff, sample.name)
                    )

                # Step 6: Crash detection
                if self._debugger:
                    crash = self._debugger.detect_crash()
                    if crash.is_bsod or crash.exception_code:
                        result.crash_detected = True
                        crash_finding = self._crash_to_finding(crash, sample.name)
                        if crash_finding:
                            result.new_findings.append(crash_finding)

                # Step 7: Unload driver
                self._unload_driver(sample)

            # Step 8: Enrich static findings with dynamic results
            sample.analysis_findings = sample.analysis_findings or []
            result.findings_validated = self._enrich_findings(
                sample.analysis_findings, result,
            )

            # Attach dynamic results to sample
            sample.dynamic_results.append({
                "crash_detected": result.crash_detected,
                "poc_executed": result.poc_executed,
                "system_changes": result.system_changes,
                "new_findings_count": len(result.new_findings),
                "validated_findings": len(result.findings_validated),
            })

        except Exception as e:
            result.error = str(e)
            logging.error("[validator] Validation failed: %s", e)

        result.elapsed = time.time() - start
        return result

    def _pre_validate(self, result: DynamicResult) -> bool:
        """Pre-validation checks before starting dynamic analysis."""
        if self.config.sandbox_enabled and not self._sandbox.is_available:
            result.error = "Sandbox not available. QEMU or VM image missing."
            return False

        if self.config.debugger_enabled and not self._debugger.is_available:
            result.error = "Debugger not available. WinDbg not found."
            return False

        return True

    def _load_driver(self, sample: Sample) -> bool:
        """Load driver via sandbox or SCM."""
        if self._sandbox and self.config.sandbox_enabled:
            test_result = self._sandbox.run_driver_test(
                driver_path=str(sample.path),
                service_name=sample.name,
                poc_script=self.config.poc_script,
                timeout=self.config.timeout_per_test,
            )
            return test_result.get("success", False)

        if self._service:
            try:
                info = self._service.load_and_wait(
                    driver_path=sample.path,
                    wait_seconds=min(self.config.timeout_per_test, 10),
                )
                return info.status.is_running
            except Exception:
                return False

        return False

    def _execute_poc(self, sample: Sample) -> bool:
        """Execute PoC script against the loaded driver."""
        if self._sandbox:
            return True  # PoC is executed as part of run_driver_test
        return False

    def _unload_driver(self, sample: Sample) -> bool:
        """Unload driver."""
        if self._sandbox:
            return self._sandbox.revert_snapshot()
        if self._service:
            return self._service.unload(sample.name)
        return False

    def _diff_to_findings(
        self, diff, driver_name: str,
    ) -> list[Finding]:
        """Convert system diff into Finding objects."""
        findings = []

        for dev in diff.new_devices:
            findings.append(Finding(
                category=FindingCategory.DYNAMIC_NEW_DEVICE,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=f"New device appeared after loading {driver_name}: {dev}",
                context={"device": dev},
                evidence=[Evidence(
                    type="instruction_pattern",
                    location="SYSTEM_MONITOR",
                    snippet=dev,
                    rule_id="DYN001",
                )],
            ))

        for svc in diff.new_services:
            findings.append(Finding(
                category=FindingCategory.DYNAMIC_REGISTRY_WRITE,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=f"New service appeared: {svc.get('Name', 'unknown')}",
                context={"service": svc},
                evidence=[Evidence(
                    type="instruction_pattern",
                    location="SYSTEM_MONITOR",
                    snippet=svc.get("Name", ""),
                    rule_id="DYN002",
                )],
            ))

        return findings

    def _crash_to_finding(
        self, crash, driver_name: str,
    ) -> Finding | None:
        """Convert crash info into a Finding object."""
        if not crash.is_bsod and not crash.exception_code:
            return None

        category = FindingCategory.DYNAMIC_CRASH_CONFIRMED
        severity = Severity.CRITICAL if crash.is_bsod else Severity.HIGH

        return Finding(
            category=category,
            severity=severity,
            confidence=Confidence.HIGH,
            description=f"Crash confirmed during {driver_name} testing: {crash.description}",
            context={
                "crash_info": {
                    "bugcheck_code": hex(crash.bugcheck_code) if crash.bugcheck_code else None,
                    "exception_code": hex(crash.exception_code) if crash.exception_code else None,
                    "stack_trace": crash.stack_trace[:5],
                },
            },
            evidence=[Evidence(
                type="instruction_pattern",
                location="DEBUGGER",
                snippet=crash.description,
                rule_id="DYN003",
            )],
        )

    def _enrich_findings(
        self,
        findings: list[Finding],
        result: DynamicResult,
    ) -> list[Finding]:
        """Enrich static findings with dynamic validation results."""
        enriched = []

        for f in findings:
            f_copy = f
            if result.crash_detected:
                f_copy.confidence = Confidence.CERTAIN
                f_copy.context["dynamically_validated"] = True
                f_copy.context["crash_confirmed"] = True
            elif result.poc_executed:
                f_copy.confidence = Confidence.HIGH
                f_copy.context["dynamically_validated"] = True
            enriched.append(f_copy)

        return enriched

    def validate_findings(
        self,
        findings: list[Finding],
        driver_path: Path | None = None,
        timeout_per_test: int = 5,
    ) -> list[DynamicResult]:
        """Legacy interface: validate a list of static findings.

        This is the original API from the stub validator, maintained
        for backward compatibility.
        """
        results = []
        for finding in findings:
            result = DynamicResult()
            result.findings_validated.append(finding)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Backward-compatible methods (from original stub)
    # ------------------------------------------------------------------

    def _send_ioctl(self, device_name: str, test: IoctlTest, timeout: int) -> str:
        """Send an IOCTL to a device (backward-compatible stub).

        Returns: "success", "error", or "crash"
        """
        import os
        if not os.environ.get("DRIVERSCOPE_DYNAMIC"):
            return "skipped"
        return "error"

    def load_driver(self, driver_path: Path, service_name: str = "") -> bool:
        """Load a driver into the kernel for testing (backward-compatible stub)."""
        import os
        if not os.environ.get("DRIVERSCOPE_DYNAMIC"):
            return False
        if not driver_path.exists():
            return False
        return False

    def unload_driver_method(self, service_name: str) -> bool:
        """Unload a driver from the kernel (backward-compatible stub)."""
        import os
        if not os.environ.get("DRIVERSCOPE_DYNAMIC"):
            return False
        return False

    def to_dict(self, result: DynamicResult) -> dict[str, Any]:
        """Serialize a DynamicResult to a dictionary."""
        return {
            "sample_name": result.sample_name,
            "driver_path": result.driver_path,
            "sandbox_used": result.sandbox_used,
            "debugger_used": result.debugger_used,
            "poc_executed": result.poc_executed,
            "crash_detected": result.crash_detected,
            "findings_validated": len(result.findings_validated),
            "new_findings": [f.to_dict() for f in result.new_findings],
            "system_changes": result.system_changes,
            "error": result.error,
            "elapsed": round(result.elapsed, 2),
        }

    def to_json(self, result: DynamicResult, indent: int = 2) -> str:
        """Serialize a DynamicResult to JSON."""
        return json.dumps(self.to_dict(result), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Backward-compatible IOCTL utilities (from original stub)
# ---------------------------------------------------------------------------


def parse_ioctl_code(code: int) -> dict[str, int]:
    """Parse an IOCTL code into its components.

    CTL_CODE structure:
    - DeviceType: bits 16-31
    - Access: bits 14-15
    - Function: bits 2-13
    - Method: bits 0-1
    """
    return {
        "device_type": (code >> 16) & 0xFFFF,
        "access": (code >> 14) & 0x3,
        "function": (code >> 2) & 0xFFF,
        "method": code & 0x3,
    }


def method_name(method: int) -> str:
    """Get the method name from an IOCTL method code."""
    methods = {
        0: "METHOD_BUFFERED",
        1: "METHOD_IN_DIRECT",
        2: "METHOD_OUT_DIRECT",
        3: "METHOD_NEITHER",
    }
    return methods.get(method, f"UNKNOWN({method})")


def generate_ioctl_code(
    device_type: int = 0x22,
    function: int = 0x801,
    method: int = 0,
    access: int = 3,
) -> int:
    """Generate an IOCTL code from components."""
    return (
        (device_type << 16) |
        (access << 14) |
        (function << 2) |
        method
    )
