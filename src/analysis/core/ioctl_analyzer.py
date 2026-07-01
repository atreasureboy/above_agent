"""
DriverScope — IOCTL Analyzer.

Precisely extracts IOCTL code to handler mappings from disassembled
driver code. Each IOCTL code is linked to the function that handles it,
enabling per-handler vulnerability analysis.
"""

from __future__ import annotations

from src.models import Confidence, DisassemblyResult, Evidence, Finding, FindingCategory, Sample, Severity
from src.analysis.analyzer import Analyzer


class IOCTLAnalyzer(Analyzer):
    """Maps IOCTL codes to their handler functions.

    Uses the DisassemblyResult's ioctl_codes and ioctl_handlers (populated
    by the Capstone backend) to produce structured findings about which
    IOCTL codes are exposed and which functions handle them.
    """

    @property
    def name(self) -> str:
        return "IOCTLAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Maps exposed IOCTL codes to their handler functions and "
            "identifies potential attack surface per IOCTL."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # If we have ioctl_handlers from the backend (code -> func mapping),
        # use those directly for precision.
        if ir.ioctl_handlers:
            for ioctl_code, handler_addr in ir.ioctl_handlers.items():
                method = ioctl_code & 0x3
                access = (ioctl_code >> 14) & 0x3
                function = (ioctl_code >> 2) & 0xFFF
                device_type = (ioctl_code >> 16) & 0xFFFF

                method_names = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
                access_names = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}

                # Severity based on IOCTL transfer method:
                # BUFFERED/IN_DIRECT = safe (kernel buffers input) → LOW
                # OUT_DIRECT = moderate → MEDIUM
                # NEITHER = dangerous (direct user pointer) → HIGH
                if method == 3:
                    severity = Severity.HIGH
                elif method == 2:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                findings.append(
                    Finding(
                        category=FindingCategory.IOCTL_CODE_EXPOSED,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        description=(
                            f"IOCTL 0x{ioctl_code:X} → handler sub_{handler_addr:X} "
                            f"(method={method_names.get(method, str(method))}, "
                            f"access={access_names.get(access, str(access))}, "
                            f"function=0x{function:X}, device=0x{device_type:X})"
                        ),
                        function_address=handler_addr,
                        ioctl_code=ioctl_code,
                        evidence=[
                            Evidence(
                                type="cfg_path",
                                location=f"sub_{handler_addr:X}",
                                snippet=f"IOCTL 0x{ioctl_code:X} dispatch target",
                                rule_id="IOCTL_HANDLER_MAP",
                            )
                        ],
                    )
                )

        # If we only have ioctl_codes (from heuristic detection) but no handler mapping,
        # report them at lower confidence.
        if not ir.ioctl_handlers and ir.ioctl_codes:
            for ioctl_code in ir.ioctl_codes:
                method = ioctl_code & 0x3
                function = (ioctl_code >> 2) & 0xFFF
                device_type = (ioctl_code >> 16) & 0xFFFF

                findings.append(
                    Finding(
                        category=FindingCategory.IOCTL_CODE_EXPOSED,
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        description=(
                            f"IOCTL code 0x{ioctl_code:X} detected (heuristic, "
                            f"method={method}, function=0x{function:X}, "
                            f"device=0x{device_type:X}). "
                            "Handler mapping not available."
                        ),
                        ioctl_code=ioctl_code,
                        evidence=[
                            Evidence(
                                type="instruction_pattern",
                                location="unknown",
                                snippet=f"cmp/test with 0x{ioctl_code:X}",
                                rule_id="IOCTL_HEURISTIC",
                            )
                        ],
                    )
                )

        return findings
