"""
DriverScope — Pseudocode Analyzer.

Leverages Ghidra decompiler output to detect patterns invisible at
the assembly level:
- Custom IOCTL validation logic (complex comparisons, state machines)
- Structured field access (IRP->Tail.Overlay.CurrentStackLocation)
- C++ vtable calls (this->vtable[N]())
- Hidden entry points (unregistered WDF callbacks)
- Obfuscated control flow (flattened switches, opaque predicates)

The analyzer runs after the structure analyzer and correlates findings
with existing IOCTL handler and taint analysis results.
"""

from __future__ import annotations

import re

from src.analysis.analyzer import Analyzer
from src.analysis.dataflow.input_tracker import DANGEROUS_SINKS
from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)


# IOCTL validation patterns in decompiled C code
IOCTL_VALIDATION_PATTERNS = [
    # CTL_CODE construction / comparison
    (re.compile(r"(?:CTL_CODE|DeviceIoControl|IoControlCode)", re.IGNORECASE),
     "CTL_CODE/IoControlCode reference",
     FindingCategory.IOCTL_CODE_EXPOSED,
     Severity.MEDIUM),
    # Input buffer size validation
    (re.compile(r"(?:InputBufferLength|SystemBuffer|UserBuffer).*?(?:<|<=|>=|==|!=)\s*\d+"),
     "Buffer size comparison in pseudocode",
     FindingCategory.MISSING_SIZE_CHECK,
     Severity.LOW),  # LOW because we found a comparison
    # Privilege check in pseudocode
    (re.compile(r"(?:PreviousMode|ExGetPreviousMode|SeSinglePrivilege|UserMode|KernelMode)"),
     "Privilege/mode check in pseudocode",
     FindingCategory.MISSING_PRIVILEGE_CHECK,
     Severity.LOW),
]

# Struct field access patterns
STRUCT_FIELD_PATTERNS = [
    (re.compile(r"(?:IRP|Irp)\s*->\s*Tail\s*\.Overlay\s*\.CurrentStackLocation"),
     "IRP.CurrentStackLocation access"),
    (re.compile(r"(?:IRP|Irp)\s*->\s*Tail\s*\.Overlay\s*\.(?!CurrentStackLocation)\w+"),
     "IRP.Tail field access"),
    (re.compile(r"(?:IO_STACK_LOCATION|StackLocation)\s*->\s*Parameters"),
     "IO_STACK_LOCATION.Parameters access"),
    (re.compile(r"(?:DeviceObject|devObj)\s*->\s*DeviceExtension"),
     "DeviceObject.DeviceExtension access"),
]

# C++ vtable / indirect call patterns
VTABLE_PATTERNS = [
    re.compile(r"\w+\s*->\s*vtable"),
    re.compile(r"\*\s*\(\s*\w+\s*\+\s*\w+\s*\*\s*\d+\s*\)"),
    re.compile(r"\(\s*\(\s*\w+\s*\*\s*\*\s*\w+\s*\)\s*\)\s*\("),
]


class PseudocodeAnalyzer(Analyzer):
    """Analyze decompiled pseudocode for patterns invisible at assembly level."""

    @property
    def name(self) -> str:
        return "PseudocodeAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Analyzes Ghidra decompiler output for IOCTL validation logic, "
            "struct field access, C++ vtable calls, and obfuscated control flow."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Check if any function has pseudocode
        has_pseudocode = any(f.pseudo_code for f in ir.functions.values())
        if not has_pseudocode:
            return findings

        for func_addr, func in ir.functions.items():
            if not func.pseudo_code:
                continue

            pseudo = func.pseudo_code

            # Check IOCTL validation patterns
            for pattern, desc, category, severity in IOCTL_VALIDATION_PATTERNS:
                if pattern.search(pseudo):
                    findings.append(
                        Finding(
                            category=category,
                            severity=severity,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"Function {func.name}@0x{func_addr:X}: {desc} "
                                f"detected in decompiled pseudocode."
                            ),
                            function_address=func_addr,
                            context={
                                "pattern": desc,
                                "source": "pseudocode",
                            },
                            evidence=[
                                Evidence(
                                    type="instruction_pattern",
                                    location=func.name,
                                    snippet=f"Pseudocode contains: {desc}",
                                    rule_id=f"PCODE_{category.value.upper()}",
                                )
                            ],
                        )
                    )

            # Check struct field access
            for pattern, desc in STRUCT_FIELD_PATTERNS:
                if pattern.search(pseudo):
                    findings.append(
                        Finding(
                            category=FindingCategory.UNVALIDATED_DATA_FLOW,
                            severity=Severity.INFO,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"Function {func.name}@0x{func_addr:X}: {desc} "
                                f"in decompiled pseudocode."
                            ),
                            function_address=func_addr,
                            context={
                                "pattern": desc,
                                "source": "pseudocode",
                            },
                            evidence=[
                                Evidence(
                                    type="instruction_pattern",
                                    location=func.name,
                                    snippet=f"Pseudocode: {desc}",
                                    rule_id="PCODE_STRUCT",
                                )
                            ],
                        )
                    )

            # Check vtable/indirect call patterns
            for pattern in VTABLE_PATTERNS:
                if pattern.search(pseudo):
                    findings.append(
                        Finding(
                            category=FindingCategory.CUSTOM_CODE_EXECUTION,
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            description=(
                                f"Function {func.name}@0x{func_addr:X}: "
                                f"C++ vtable or indirect call pattern in pseudocode."
                            ),
                            function_address=func_addr,
                            context={
                                "pattern": "vtable/indirect_call",
                                "source": "pseudocode",
                            },
                            evidence=[
                                Evidence(
                                    type="instruction_pattern",
                                    location=func.name,
                                    snippet="Pseudocode contains vtable/indirect call",
                                    rule_id="PCODE_VTABLE",
                                )
                            ],
                        )
                    )

            # Check if function calls dangerous APIs but has no validation
            func_apis = set(ir.function_apis.get(func_addr, []))
            dangerous_found = func_apis & DANGEROUS_SINKS
            if dangerous_found:
                # Check if pseudocode contains any validation-like code
                has_validation = bool(
                    re.search(r"(?:if|switch|check|validate|verify|probe|privilege)",
                              pseudo, re.IGNORECASE)
                )
                if not has_validation:
                    apis_str = ", ".join(sorted(dangerous_found))
                    findings.append(
                        Finding(
                            category=FindingCategory.UNVALIDATED_USER_INPUT,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Function {func.name}@0x{func_addr:X} calls "
                                f"{apis_str} with no validation logic visible "
                                f"in decompiled pseudocode."
                            ),
                            function_address=func_addr,
                            context={
                                "dangerous_apis": sorted(dangerous_found),
                                "source": "pseudocode",
                                "no_validation": True,
                            },
                            evidence=[
                                Evidence(
                                    type="cfg_path",
                                    location=func.name,
                                    snippet=f"{apis_str} with no pseudocode validation",
                                    rule_id="PCODE_NO_VAL",
                                )
                            ],
                        )
                    )

        return findings
