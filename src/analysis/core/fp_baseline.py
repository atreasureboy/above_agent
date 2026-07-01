"""DriverScope — False Positive Baseline Filter.

Establishes a "safety baseline" from known-good Microsoft-signed drivers
and filters out findings that match baseline patterns.

Strategy:
1. Build a baseline from known safe drivers (Microsoft WHQL certified)
   - Record which APIs are commonly present but benign
   - Record which validation patterns are "good enough" in practice
2. For each new driver, compare its findings against the baseline
   - Downgrade findings that match baseline patterns
   - Keep high severity for deviations from baseline

This significantly reduces false positives from drivers that use dangerous
APIs in safe, validated ways (e.g., standard storage/network drivers).

Usage:
    from src.analysis.core.fp_baseline import BaselineFilter, load_baseline
    baseline = load_baseline()  # or build from known-good samples
    filtered = baseline.filter_findings(findings, sample, ir)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


# ---------------------------------------------------------------------------
# Known-good API patterns — these APIs in these contexts are typically benign
# ---------------------------------------------------------------------------

# APIs that are commonly present in safe Microsoft drivers
BENIGN_API_CONTEXTS: dict[str, set[str]] = {
    # Memory APIs that are normal in storage/display drivers
    "MmMapIoSpace": {"storport.sys", "disk.sys", "dxgkrnl.sys"},
    "MmMapIoSpaceEx": {"storport.sys", "disk.sys", "dxgkrnl.sys"},
    "MmGetPhysicalAddress": {"dxgkrnl.sys", "dxgmms1.sys", "dxgmms2.sys"},
    "MmAllocateContiguousMemory": {"dxgkrnl.sys", "portcls.sys"},
    # Pool allocation is universal — not a BYOVD indicator alone
    "ExAllocatePoolWithTag": set(),  # Always benign as standalone finding
    "ExAllocatePool2": set(),
    "ExAllocatePool3": set(),
    "ExFreePool": set(),
    "ExFreePoolWithTag": set(),
    # String/memory operations are universal
    "RtlCopyMemory": set(),
}

# Validation patterns that are considered "sufficient" in production drivers
# If a driver has these patterns, findings are downgraded
SUFFICIENT_VALIDATION_PATTERNS = {
    # If driver has both probe AND privilege check, it's likely safe
    "probe_and_privilege": {"ProbeForRead", "ProbeForWrite", "SeSinglePrivilegeCheck"},
    # If driver uses MmProbeAndLockPages, memory access is validated
    "locked_pages": {"MmProbeAndLockPages", "MmProbeAndLockProcessPages"},
    # If driver checks PreviousMode AND does size check
    "mode_and_size": {"ExGetPreviousMode"},
}

# Known safe driver patterns — findings from drivers matching these
# are automatically downgraded
SAFE_DRIVER_SIGNATURES = {
    # Microsoft company name keywords
    "microsoft corporation",
    "microsoft windows",
    "microsoft",
    # Well-known safe driver categories
    "windows driver",
    "wdk sample",
}

# Minimum validation APIs that suggest a driver is "careful"
MIN_VALIDATION_APIS = 2


@dataclass
class BaselineProfile:
    """A baseline profile for a known-good driver or driver family."""
    name: str                          # Driver name or family identifier
    sha256: str = ""                   # Specific driver hash (optional)
    company: str = ""                  # Company name
    known_safe_apis: set[str] = field(default_factory=set)  # APIs this driver uses safely
    validation_patterns: set[str] = field(default_factory=set)  # Validation patterns present
    driver_category: str = ""          # e.g., "storage", "network", "display"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sha256": self.sha256,
            "company": self.company,
            "known_safe_apis": sorted(self.known_safe_apis),
            "validation_patterns": sorted(self.validation_patterns),
            "driver_category": self.driver_category,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BaselineProfile":
        return cls(
            name=d["name"],
            sha256=d.get("sha256", ""),
            company=d.get("company", ""),
            known_safe_apis=set(d.get("known_safe_apis", [])),
            validation_patterns=set(d.get("validation_patterns", [])),
            driver_category=d.get("driver_category", ""),
        )


class BaselineFilter:
    """Filters findings against a safety baseline."""

    def __init__(self, profiles: list[BaselineProfile] | None = None):
        self.profiles = profiles or []
        self._index_by_name: dict[str, BaselineProfile] = {}
        self._index_by_sha: dict[str, BaselineProfile] = {}
        for p in self.profiles:
            self._index_by_name[p.name.lower()] = p
            if p.sha256:
                self._index_by_sha[p.sha256.lower()] = p

    def filter_findings(
        self,
        findings: list[Finding],
        sample: Sample,
        ir: DisassemblyResult,
    ) -> list[Finding]:
        """Filter findings against baseline, downgrading false positives.

        Returns a new list of findings with adjusted severity/confidence.
        Original findings are not modified.
        """
        filtered: list[Finding] = []

        # Check if this driver matches a known-safe baseline
        safe_profile = self._index_by_sha.get(getattr(sample, "sha256", "").lower())
        if not safe_profile:
            safe_profile = self._index_by_name.get(getattr(sample, "name", "").lower())

        # Check for safe company signature or baseline profile match
        is_known_safe = safe_profile is not None
        if sample.signature_status.value in ("signed_valid",):
            is_known_safe = True

        # Collect validation APIs present in this driver
        all_apis = set()
        for func_apis in ir.function_apis.values():
            all_apis.update(func_apis)

        validation_count = 0
        for v_pattern in SUFFICIENT_VALIDATION_PATTERNS.values():
            if all_apis & v_pattern:
                validation_count += 1

        for f in findings:
            new_finding = self._adjust_finding(f, is_known_safe, validation_count, all_apis, ir)
            filtered.append(new_finding)

        return filtered

    def _adjust_finding(
        self,
        f: Finding,
        is_known_safe: bool,
        validation_count: int,
        all_apis: set[str],
        ir: DisassemblyResult,
    ) -> Finding:
        """Adjust a single finding based on baseline matching."""
        # Don't adjust critical attack chains
        if f.category == FindingCategory.ATTACK_CHAIN:
            return f

        # Don't adjust taint-confirmed findings
        ctx = f.context or {}
        if ctx.get("taint_confirmed"):
            return f

        # Downgrade findings for known-safe drivers
        if is_known_safe:
            if f.severity in (Severity.LOW, Severity.INFO):
                return f  # Already low, no change
            new_severity = self._downgrade_severity(f.severity)
            new_confidence = self._downgrade_confidence(f.confidence)
            return self._clone_finding(f, severity=new_severity, confidence=new_confidence,
                                       description=f"[BASELINE] {f.description}")

        # Downgrade findings for drivers with sufficient validation
        if validation_count >= MIN_VALIDATION_APIS:
            if f.category in (FindingCategory.MISSING_PRIVILEGE_CHECK, FindingCategory.MISSING_SIZE_CHECK):
                # Driver has multiple validation patterns, likely has implicit checks
                return self._clone_finding(f, severity=self._downgrade_severity(f.severity),
                                           description=f"[PARTIAL-OK] {f.description}")

        # Downgrade standalone pool allocation findings (always benign alone)
        if f.api_name in BENIGN_API_CONTEXTS and not BENIGN_API_CONTEXTS[f.api_name]:
            if f.category in (FindingCategory.ARBITRARY_MEMORY_MAP, FindingCategory.DMA_PRIMITIVE):
                return self._clone_finding(f, severity=Severity.LOW, confidence=Confidence.LOW,
                                           description=f"[COMMON-API] {f.description}")

        return f

    @staticmethod
    def _downgrade_severity(sev: Severity) -> Severity:
        """Downgrade severity by one level."""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        idx = order.index(sev) if sev in order else 2
        return order[min(idx + 1, len(order) - 1)]

    @staticmethod
    def _downgrade_confidence(conf: Confidence) -> Confidence:
        """Downgrade confidence by one level."""
        order = [Confidence.CERTAIN, Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
        idx = order.index(conf) if conf in order else 2
        return order[min(idx + 1, len(order) - 1)]

    @staticmethod
    def _clone_finding(
        f: Finding,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        description: str | None = None,
    ) -> Finding:
        """Clone a finding with adjusted properties."""
        return Finding(
            category=f.category,
            severity=severity or f.severity,
            confidence=confidence or f.confidence,
            description=description or f.description,
            function_address=f.function_address,
            api_name=f.api_name,
            instruction_address=f.instruction_address,
            context=dict(f.context) if f.context else None,
            evidence=list(f.evidence) if f.evidence else None,
        )

    def add_profile(self, profile: BaselineProfile) -> None:
        """Add a baseline profile."""
        self.profiles.append(profile)
        self._index_by_name[profile.name.lower()] = profile
        if profile.sha256:
            self._index_by_sha[profile.sha256.lower()] = profile

    def to_json(self) -> str:
        """Serialize all profiles to JSON."""
        return json.dumps([p.to_dict() for p in self.profiles], indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "BaselineFilter":
        """Deserialize profiles from JSON."""
        profiles = [BaselineProfile.from_dict(d) for d in json.loads(json_str)]
        return cls(profiles)


def load_baseline(path: Path | None = None) -> BaselineFilter:
    """Load baseline profiles from a JSON file.

    If no path is provided, checks ~/.driverscope/baseline.json.
    Returns an empty BaselineFilter if no file found.
    """
    if path is None:
        path = Path.home() / ".driverscope" / "baseline.json"

    if path.exists():
        return BaselineFilter.from_json(path.read_text(encoding="utf-8"))
    return BaselineFilter()


def build_default_baseline() -> BaselineFilter:
    """Build a default baseline from known-safe Microsoft driver patterns."""
    bf = BaselineFilter()

    # Add a generic Microsoft driver baseline
    bf.add_profile(BaselineProfile(
        name="microsoft_generic",
        company="Microsoft Corporation",
        known_safe_apis={
            "MmMapIoSpace", "MmMapIoSpaceEx",
            "ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool3",
            "RtlCopyMemory",
        },
        validation_patterns={"probe_and_privilege", "locked_pages"},
        driver_category="generic",
    ))

    # Storage driver baseline
    bf.add_profile(BaselineProfile(
        name="storport_generic",
        company="Microsoft Corporation",
        known_safe_apis={
            "MmMapIoSpace", "MmMapIoSpaceEx",
            "MmAllocateContiguousMemory",
            "ExAllocatePoolWithTag",
        },
        validation_patterns={"probe_and_privilege"},
        driver_category="storage",
    ))

    # Display driver baseline
    bf.add_profile(BaselineProfile(
        name="dxgkrnl_generic",
        company="Microsoft Corporation",
        known_safe_apis={
            "MmGetPhysicalAddress", "MmMapIoSpace",
            "MmAllocateContiguousMemory",
            "ExAllocatePoolWithTag",
        },
        validation_patterns={"locked_pages"},
        driver_category="display",
    ))

    return bf
