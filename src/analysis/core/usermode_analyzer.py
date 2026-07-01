"""
DriverScope — User-mode PE analyzer.

Analyzes .exe/.dll files for:
- Dangerous imports (process injection, service manipulation, NtQuerySystemInformation)
- COM interface exposure (DllGetClassObject, IDispatch patterns)
- Service registration entry points (ServiceMain)
- Embedded resources (potential driver droppers)
- String patterns (URLs, registry paths, file paths, device paths)

This analyzer feeds user-mode findings into the main pipeline alongside
kernel-mode driver analysis.
"""

from __future__ import annotations

import re
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)


DANGEROUS_USERMODE_APIS = {
    "VirtualAlloc": (Severity.HIGH, "Memory allocation — potential shellcode staging"),
    "VirtualAllocEx": (Severity.HIGH, "Remote memory allocation — process injection"),
    "VirtualProtect": (Severity.HIGH, "Memory protection change — shellcode execution"),
    "VirtualProtectEx": (Severity.HIGH, "Remote memory protection change"),
    "WriteProcessMemory": (Severity.HIGH, "Remote memory write — process injection"),
    "ReadProcessMemory": (Severity.MEDIUM, "Remote memory read"),
    "CreateRemoteThread": (Severity.CRITICAL, "Remote thread creation — code execution"),
    "NtQuerySystemInformation": (Severity.HIGH, "System information leak — reconnaissance"),
    "NtLoadDriver": (Severity.CRITICAL, "Kernel driver load — privilege escalation"),
    "NtUnloadDriver": (Severity.HIGH, "Kernel driver unload"),
    "RtlCreateUserThread": (Severity.CRITICAL, "Thread creation — code execution"),
    "CreateServiceA": (Severity.HIGH, "Service creation — persistence"),
    "CreateServiceW": (Severity.HIGH, "Service creation — persistence"),
    "StartServiceA": (Severity.MEDIUM, "Service start"),
    "StartServiceW": (Severity.MEDIUM, "Service start"),
    "OpenProcess": (Severity.MEDIUM, "Process handle acquisition"),
    "OpenProcessToken": (Severity.MEDIUM, "Token access — privilege manipulation"),
    "AdjustTokenPrivileges": (Severity.HIGH, "Token privilege adjustment"),
}


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
REG_PATH_PATTERN = re.compile(r"(?:HKEY_[A-Z_]+\\[^\s\"']{10,})", re.IGNORECASE)
FILE_PATH_PATTERN = re.compile(r"[A-Z]:\\(?:[\w\\]+[\w.]+)", re.IGNORECASE)
DEVICE_PATH_PATTERN = re.compile(r"\\\\\.\\[\w]+")


class UserModeAnalyzer(Analyzer):
    """Analyze user-mode .exe/.dll for dangerous capabilities."""

    @property
    def name(self) -> str:
        return "UserModeAnalyzer"

    @property
    def description(self) -> str:
        return "Analyze user-mode binaries for dangerous imports, COM interfaces, service entry points, and embedded drivers"

    @property
    def enabled(self) -> bool:
        return True

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Dangerous import detection
        findings.extend(self._check_dangerous_imports(sample))

        # 2. COM interface analysis
        findings.extend(self._check_com_interfaces(sample))

        # 3. Service entry point analysis
        findings.extend(self._check_service_entrypoints(sample))

        # 4. Embedded resource detection
        findings.extend(self._check_embedded_resources(sample))

        # 5. String pattern analysis
        findings.extend(self._check_strings(sample, ir))

        return findings

    def _check_dangerous_imports(self, sample: Sample) -> list[Finding]:
        findings = []
        imports_lower_map = {}
        for imp in sample.imports:
            imports_lower_map[imp.lower()] = imp

        for api_lower, (severity, desc) in DANGEROUS_USERMODE_APIS.items():
            if api_lower.lower() in imports_lower_map:
                original = imports_lower_map[api_lower.lower()]
                findings.append(Finding(
                    category=FindingCategory.DANGEROUS_USERMODE_IMPORT,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    description=f"Dangerous user-mode API import: {original} — {desc}",
                    api_name=original,
                    evidence=[Evidence(
                        type="import",
                        location="IAT",
                        snippet=original,
                        rule_id="UM001",
                    )],
                ))
        return findings

    def _check_com_interfaces(self, sample: Sample) -> list[Finding]:
        findings = []
        if sample.com_interfaces:
            findings.append(Finding(
                category=FindingCategory.COM_INTERFACE_EXPOSED,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"COM interfaces exposed: {', '.join(sample.com_interfaces)}",
                context={"com_interfaces": sample.com_interfaces},
                evidence=[Evidence(
                    type="export",
                    location="EXPORTS",
                    snippet=", ".join(sample.com_interfaces),
                    rule_id="UM002",
                )],
            ))
        return findings

    def _check_service_entrypoints(self, sample: Sample) -> list[Finding]:
        findings = []
        service_info = sample.service_info
        if service_info and service_info.get("has_service_entry"):
            findings.append(Finding(
                category=FindingCategory.SERVICE_REGISTRATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"Service entry points detected: {', '.join(service_info['service_exports'])}",
                context={"service_info": service_info},
                evidence=[Evidence(
                    type="export",
                    location="EXPORTS",
                    snippet=", ".join(service_info["service_exports"]),
                    rule_id="UM003",
                )],
            ))
        return findings

    def _check_embedded_resources(self, sample: Sample) -> list[Finding]:
        findings = []
        if sample.embedded_files:
            findings.append(Finding(
                category=FindingCategory.EMBEDDED_DRIVER,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=f"Embedded PE files detected in resources ({len(sample.embedded_files)} files)",
                context={"embedded_count": len(sample.embedded_files)},
                evidence=[Evidence(
                    type="resource",
                    location="RESOURCE_SECTION",
                    snippet=f"{len(sample.embedded_files)} embedded PE files",
                    rule_id="UM004",
                )],
            ))
        return findings

    def _check_strings(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings = []
        all_strings = set(ir.strings) if ir else set()

        # Add strings from imports/exports as context
        all_strings.update(sample.imports)
        all_strings.update(sample.exports)

        urls = []
        reg_paths = []
        file_paths = []
        device_paths = []

        for s in all_strings:
            if not s or len(s) < 8:
                continue
            if URL_PATTERN.search(s):
                urls.append(s)
            if REG_PATH_PATTERN.search(s):
                reg_paths.append(s)
            if FILE_PATH_PATTERN.search(s):
                file_paths.append(s)
            if DEVICE_PATH_PATTERN.search(s):
                device_paths.append(s)

        if device_paths:
            findings.append(Finding(
                category=FindingCategory.USERMODE_KERNEL_BRIDGE,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=f"Device path strings suggest kernel communication: {device_paths[:5]}",
                context={"device_paths": device_paths[:10]},
                evidence=[Evidence(
                    type="string",
                    location=".rdata",
                    snippet=device_paths[0] if device_paths else "",
                    rule_id="UM005",
                )],
            ))

        if urls:
            findings.append(Finding(
                category=FindingCategory.DANGEROUS_STRING,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=f"URL strings found in user-mode binary ({len(urls)} URLs)",
                context={"urls": urls[:10]},
                evidence=[Evidence(
                    type="string",
                    location=".rdata",
                    snippet=urls[0] if urls else "",
                    rule_id="UM006",
                )],
            ))

        return findings


def get_usermode_analyzer() -> UserModeAnalyzer:
    """Factory function for the user-mode analyzer."""
    return UserModeAnalyzer()
