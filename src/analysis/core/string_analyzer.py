"""
DriverScope — String Analyzer.

Examines extracted driver strings for indicators of dangerous behavior,
driver type classification, and development artifacts that may reveal
attack surface or debugging entry points.
"""

from __future__ import annotations

import re

from src.models import Confidence, DisassemblyResult, Evidence, Finding, FindingCategory, Sample, Severity
from src.analysis.analyzer import Analyzer


# Dangerous string patterns grouped by risk category
DANGEROUS_STRING_PATTERNS: list[tuple[str, str, Severity, str]] = [
    # Physical device access
    ("\\Device\\PhysicalMemory", "References \\Device\\PhysicalMemory — may create mapping for physical memory access", Severity.HIGH, "STR_PHYSICAL_MEMORY"),
    ("PhysicalDrive", "References PhysicalDrive — may expose raw disk access primitive", Severity.HIGH, "STR_PHYSICAL_DRIVE"),

    # Registry manipulation
    ("\\Registry\\Machine", "Accesses HKLM registry — may persist driver or modify system config", Severity.MEDIUM, "STR_REGISTRY_HKLM"),
    ("CurrentControlSet\\Services", "References driver service registry path", Severity.MEDIUM, "STR_SERVICE_PATH"),
    ("Parameters\\", "References driver parameters registry key", Severity.LOW, "STR_PARAMETERS"),

    # Debug / development artifacts
    ("DbgPrint", "Uses DbgPrint — debug output, may leak kernel info", Severity.LOW, "STR_DBGPRINT"),
    ("DEBUG", "Contains DEBUG string — may indicate debug build", Severity.LOW, "STR_DEBUG"),
    ("ASSERT", "Contains ASSERT — may indicate debug/development build", Severity.LOW, "STR_ASSERT"),
    ("TODO", "Contains TODO comment — incomplete implementation", Severity.INFO, "STR_TODO"),
    ("FIXME", "Contains FIXME — known issue not addressed", Severity.LOW, "STR_FIXME"),

    # Code execution hints
    ("ShellExecute", "References ShellExecute — unusual in kernel driver, may indicate user-mode bridge", Severity.MEDIUM, "STR_SHELLEXEC"),
    ("cmd.exe", "References cmd.exe — command execution capability", Severity.HIGH, "STR_CMD"),
    ("powershell", "References PowerShell — scripting execution capability", Severity.HIGH, "STR_POWERSHELL"),
]

# Driver device/symbolic link patterns — indicate user-visible attack surface
DEVICE_PATTERNS: list[tuple[str, str, Severity, str]] = [
    (r"\\Device\\[A-Za-z]", "Exposes a device object — potential IOCTL entry point", Severity.MEDIUM, "STR_DEVICE_OBJ"),
    (r"\\DosDevices\\", "Creates a symbolic link — user-visible device name", Severity.MEDIUM, "STR_DOS_DEVICES"),
    (r"\\\?\?\\", "Uses \\??\\ path format — legacy device access", Severity.LOW, "STR_LEGACY_PATH"),
]

# GUID patterns — device interface exposure
GUID_PATTERN = (r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
                "Contains GUID — may register a device interface", Severity.LOW, "STR_GUID")

# ACPI namespace patterns
ACPI_PATTERNS: list[tuple[str, str, Severity, str]] = [
    (r"\\_SB\\", "References ACPI _SB (System Bus) namespace", Severity.LOW, "STR_ACPI_SB"),
    (r"\\_PR\\", "References ACPI _PR (Processor) namespace", Severity.LOW, "STR_ACPI_PR"),
    ("ACPI", "References ACPI — may interact with firmware/BIOS", Severity.INFO, "STR_ACPI"),
]


class StringAnalyzer(Analyzer):
    """Analyzes driver strings for behavioral indicators."""

    @property
    def name(self) -> str:
        return "StringAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Scans extracted strings for indicators of dangerous behavior, "
            "driver type, and development artifacts."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []
        matched_categories: list[str] = []

        # 1. Dangerous patterns (exact substring match)
        for pattern, description, severity, rule_id in DANGEROUS_STRING_PATTERNS:
            for s in ir.strings:
                if pattern.lower() in s.lower():
                    matched_categories.append(rule_id)
                    findings.append(
                        Finding(
                            category=FindingCategory.DANGEROUS_STRING,
                            severity=severity,
                            confidence=Confidence.LOW,
                            description=description,
                            context={"matched_string": s, "pattern": pattern},
                            evidence=[
                                Evidence(
                                    type="string",
                                    location=".rdata/.data",
                                    snippet=s[:120],
                                    rule_id=rule_id,
                                )
                            ],
                        )
                    )
                    break

        # 2. Device object patterns (regex match)
        for pattern, description, severity, rule_id in DEVICE_PATTERNS:
            regex = re.compile(pattern)
            for s in ir.strings:
                if regex.search(s):
                    matched_categories.append(rule_id)
                    findings.append(
                        Finding(
                            category=FindingCategory.DANGEROUS_STRING,
                            severity=severity,
                            confidence=Confidence.LOW,
                            description=description,
                            context={"matched_string": s},
                            evidence=[
                                Evidence(
                                    type="string",
                                    location=".rdata/.data",
                                    snippet=s[:120],
                                    rule_id=rule_id,
                                )
                            ],
                        )
                    )
                    break

        # 3. GUID pattern
        guid_regex = re.compile(GUID_PATTERN[0])
        guids_found = set()
        for s in ir.strings:
            m = guid_regex.search(s)
            if m:
                guids_found.add(m.group(0))

        if guids_found:
            matched_categories.append(GUID_PATTERN[3])
            findings.append(
                Finding(
                    category=FindingCategory.DANGEROUS_STRING,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    description=f"Found {len(guids_found)} GUID(s) — device interface registration: {', '.join(sorted(guids_found)[:3])}",
                    context={"guids": sorted(guids_found)},
                    evidence=[
                        Evidence(
                            type="string",
                            location=".rdata/.data",
                            snippet=f"{len(guids_found)} GUID(s) found",
                            rule_id=GUID_PATTERN[3],
                        )
                    ],
                )
            )

        # 4. ACPI patterns
        for pattern, description, severity, rule_id in ACPI_PATTERNS:
            regex = re.compile(pattern)
            for s in ir.strings:
                if regex.search(s):
                    matched_categories.append(rule_id)
                    findings.append(
                        Finding(
                            category=FindingCategory.DANGEROUS_STRING,
                            severity=severity,
                            confidence=Confidence.LOW,
                            description=description,
                            context={"matched_string": s},
                            evidence=[
                                Evidence(
                                    type="string",
                                    location=".rdata/.data",
                                    snippet=s[:120],
                                    rule_id=rule_id,
                                )
                            ],
                        )
                    )
                    break

        # 5. Summary
        if matched_categories:
            findings.append(
                Finding(
                    category=FindingCategory.DANGEROUS_STRING,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"String analysis found {len(matched_categories)} indicator(s) "
                        f"across {len(ir.strings)} strings."
                    ),
                    context={
                        "matched_categories": matched_categories,
                        "total_strings": len(ir.strings),
                    },
                )
            )

        return findings
