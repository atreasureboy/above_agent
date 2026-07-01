"""Tests for SARIF v2.1.0 report generation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.models import (
    Architecture,
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    Report,
    Sample,
    Severity,
)
from src.report.sarif import (
    SEVERITY_TO_SARIF,
    _parse_location_hex,
    _rule_id,
    _rule_from_finding,
    _result_from_finding,
    generate_sarif,
    write_sarif,
)


def _make_sample(name="test.sys", sha256="abc123") -> Sample:
    return Sample(
        path=Path(f"samples/unknown/{name}"),
        name=name,
        company="Test Corp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256=sha256,
        size=8192,
        is_driver=True,
        driver_type="WDM",
    )


def _make_finding(
    category=FindingCategory.ARBITRARY_MEMORY_MAP,
    severity=Severity.HIGH,
    description="MmMapIoSpace without validation",
    function_address=0x1000,
    api_name="MmMapIoSpace",
    instruction_address=0x1020,
    context=None,
    evidence=None,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        description=description,
        function_address=function_address,
        api_name=api_name,
        instruction_address=instruction_address,
        context=context or {},
        evidence=evidence or [],
    )


def _make_report(samples=None) -> Report:
    return Report(
        samples=samples or [],
        timestamp="2026-05-25T10:00:00Z",
        tool_version="0.1.0",
        backend="ghidra",
        total_analyzed=len(samples or []),
        total_findings=sum(len(s.analysis_findings) for s in (samples or [])),
    )


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestParseLocationHex:
    """Test hex address extraction from location strings."""

    def test_iat_location(self):
        assert _parse_location_hex("IAT@0x140014130") == 0x140014130

    def test_plain_hex(self):
        assert _parse_location_hex("0xDEAD") == 0xDEAD

    def test_no_at_sign(self):
        assert _parse_location_hex("no_address") == 0

    def test_empty_string(self):
        assert _parse_location_hex("") == 0

    def test_none_input(self):
        assert _parse_location_hex(None) == 0

    def test_invalid_hex(self):
        assert _parse_location_hex("IAT@not_hex") == 0


class TestSeverityMapping:
    """Test severity → SARIF level mapping."""

    def test_critical_is_error(self):
        assert SEVERITY_TO_SARIF["critical"] == "error"

    def test_high_is_error(self):
        assert SEVERITY_TO_SARIF["high"] == "error"

    def test_medium_is_warning(self):
        assert SEVERITY_TO_SARIF["medium"] == "warning"

    def test_low_is_note(self):
        assert SEVERITY_TO_SARIF["low"] == "note"

    def test_info_is_note(self):
        assert SEVERITY_TO_SARIF["info"] == "note"


class TestRuleId:
    """Test rule ID generation."""

    def test_arbitrary_memory_map(self):
        f = _make_finding(category=FindingCategory.ARBITRARY_MEMORY_MAP)
        assert _rule_id(f) == "DRIVERSCOPE_ARBITRARY_MEMORY_MAP"

    def test_attack_chain(self):
        f = _make_finding(category=FindingCategory.ATTACK_CHAIN)
        assert _rule_id(f) == "DRIVERSCOPE_ATTACK_CHAIN"


# ---------------------------------------------------------------------------
# Rule generation tests
# ---------------------------------------------------------------------------

class TestRuleFromFinding:
    """Test SARIF rule generation from findings."""

    def test_basic_rule_structure(self):
        f = _make_finding()
        rule = _rule_from_finding(f)

        assert rule["id"] == "DRIVERSCOPE_ARBITRARY_MEMORY_MAP"
        assert rule["name"] == "arbitrary_memory_map"
        assert "shortDescription" in rule
        assert "defaultConfiguration" in rule
        assert rule["defaultConfiguration"]["level"] == "error"

    def test_rule_severity_mapping(self):
        f = _make_finding(severity=Severity.LOW)
        rule = _rule_from_finding(f)
        assert rule["defaultConfiguration"]["level"] == "note"

    def test_attack_chain_rule_has_properties(self):
        f = _make_finding(
            category=FindingCategory.ATTACK_CHAIN,
            context={
                "primitive_apis": ["MmMapIoSpaceEx"],
                "missing_checks": ["size_check"],
                "ioctl_codes": ["0x22A004"],
            },
        )
        rule = _rule_from_finding(f)

        assert "properties" in rule
        assert rule["properties"]["primitive_apis"] == ["MmMapIoSpaceEx"]
        assert rule["properties"]["missing_checks"] == ["size_check"]
        assert rule["properties"]["ioctl_codes"] == ["0x22A004"]

    def test_attack_chain_rich_description(self):
        f = _make_finding(
            category=FindingCategory.ATTACK_CHAIN,
            context={
                "primitive_apis": ["MmMapIoSpaceEx", "MmCopyVirtualMemory"],
                "missing_checks": ["size_check", "privilege_check"],
                "ioctl_codes": ["0x22A004"],
            },
        )
        rule = _rule_from_finding(f)

        assert "MmMapIoSpaceEx" in rule["fullDescription"]["text"]
        assert "size_check" in rule["fullDescription"]["text"]
        assert "0x22A004" in rule["fullDescription"]["text"]

    def test_non_attack_chain_no_properties(self):
        f = _make_finding()
        rule = _rule_from_finding(f)
        assert "properties" not in rule


# ---------------------------------------------------------------------------
# Result generation tests
# ---------------------------------------------------------------------------

class TestResultFromFinding:
    """Test SARIF result entry generation."""

    def test_basic_result_structure(self):
        sample = _make_sample()
        f = _make_finding()
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        assert result["ruleId"] == "DRIVERSCOPE_ARBITRARY_MEMORY_MAP"
        assert result["level"] == "error"
        assert "message" in result
        assert "locations" in result
        assert "properties" in result

    def test_result_properties(self):
        sample = _make_sample(sha256="deadbeef")
        f = _make_finding()
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        props = result["properties"]
        assert props["sample_name"] == "test.sys"
        assert props["sample_sha256"] == "deadbeef"
        assert props["sample_company"] == "Test Corp"
        assert props["function_address"] == "0x1000"
        assert props["api_name"] == "MmMapIoSpace"
        assert props["confidence"] == 0.9  # Confidence.HIGH maps to 0.9

    def test_result_location_uri(self):
        sample = _make_sample()
        f = _make_finding()
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        loc = result["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        # Normalize path separators for cross-platform comparison
        assert uri.replace("\\", "/") == "samples/unknown/test.sys"
        assert loc["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_attack_chain_result_has_tags(self):
        sample = _make_sample()
        f = _make_finding(
            category=FindingCategory.ATTACK_CHAIN,
            context={
                "primitive_apis": ["MmMapIoSpaceEx"],
                "missing_checks": ["size_check"],
                "ioctl_codes": ["0x22A004"],
                "ovoida_confirmed": True,
            },
        )
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ATTACK_CHAIN")

        assert "tags" in result
        assert "ovoida-confirmed" in result["tags"]
        assert any(t.startswith("ioctl:") for t in result["tags"])

    def test_attack_chain_message_format(self):
        sample = _make_sample()
        f = _make_finding(
            category=FindingCategory.ATTACK_CHAIN,
            context={
                "primitive_apis": ["MmMapIoSpaceEx"],
                "missing_checks": ["size_check"],
                "ioctl_codes": ["0x22A004"],
            },
        )
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ATTACK_CHAIN")

        assert "BYOVD Attack Chain" in result["message"]["text"]
        assert "MmMapIoSpaceEx" in result["message"]["text"]

    def test_evidence_adds_related_locations(self):
        sample = _make_sample()
        f = _make_finding(
            evidence=[Evidence(
                type="instruction",
                location="0x140001020",
                snippet="mov rcx, [rax]",
                rule_id="DRIVERSCOPE_ARBITRARY_MEMORY_MAP",
            )],
        )
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        assert "relatedLocations" in result
        assert result["relatedLocations"][0]["physicalLocation"]["address"]["absoluteAddress"] == 0x140001020

    def test_iat_evidence(self):
        sample = _make_sample()
        f = _make_finding(
            evidence=[Evidence(
                type="instruction",
                location="IAT@0x140014130",
                snippet="call MmMapIoSpace",
                rule_id="DRIVERSCOPE_ARBITRARY_MEMORY_MAP",
            )],
        )
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        assert "relatedLocations" in result
        assert result["relatedLocations"][0]["physicalLocation"]["address"]["absoluteAddress"] == 0x140014130

    def test_no_evidence_no_related_locations(self):
        sample = _make_sample()
        f = _make_finding(evidence=[])
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        assert "relatedLocations" not in result

    def test_null_fields_handled(self):
        sample = _make_sample()
        f = Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="test",
            function_address=None,
            api_name=None,
            ioctl_code=None,
        )
        result = _result_from_finding(sample, f, "DRIVERSCOPE_ARBITRARY_MEMORY_MAP")

        props = result["properties"]
        assert props["function_address"] is None
        assert props["api_name"] is None
        assert props["ioctl_code"] is None


# ---------------------------------------------------------------------------
# Full SARIF generation tests
# ---------------------------------------------------------------------------

class TestGenerateSarif:
    """Test full SARIF log generation."""

    def test_sarif_schema_version(self):
        sample = _make_sample()
        sample.analysis_findings.append(_make_finding())
        report = _make_report(samples=[sample])

        sarif = generate_sarif(report)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif

    def test_sarif_has_runs(self):
        report = _make_report(samples=[])
        sarif = generate_sarif(report)
        assert len(sarif["runs"]) == 1

    def test_tool_driver_info(self):
        report = _make_report(samples=[])
        sarif = generate_sarif(report)
        driver = sarif["runs"][0]["tool"]["driver"]

        assert driver["name"] == "DriverScope"
        assert "rules" in driver

    def test_invocation_info(self):
        report = _make_report(samples=[])
        sarif = generate_sarif(report)
        invocation = sarif["runs"][0]["invocations"][0]

        assert invocation["executionSuccessful"] is True
        assert "ghidra" in invocation["commandLine"]

    def test_rules_and_results_populated(self):
        sample = _make_sample()
        sample.analysis_findings.append(_make_finding())
        sample.analysis_findings.append(_make_finding(
            category=FindingCategory.MSR_ACCESS,
            description="KeWriteMsr without validation",
            api_name="KeWriteMsr",
        ))
        report = _make_report(samples=[sample])

        sarif = generate_sarif(report)
        run = sarif["runs"][0]

        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2

    def test_duplicate_findings_deduplicate_rules(self):
        """Same finding category on multiple samples should produce unique results but one rule."""
        s1 = _make_sample("driver1.sys", "sha256_1")
        s1.analysis_findings.append(_make_finding())

        s2 = _make_sample("driver2.sys", "sha256_2")
        s2.analysis_findings.append(_make_finding())

        report = _make_report(samples=[s1, s2])
        sarif = generate_sarif(report)
        run = sarif["runs"][0]

        assert len(run["tool"]["driver"]["rules"]) == 1  # Deduplicated
        assert len(run["results"]) == 2  # Both results present

    def test_empty_report_produces_valid_sarif(self):
        report = _make_report(samples=[])
        sarif = generate_sarif(report)
        run = sarif["runs"][0]

        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []

    def test_samples_without_findings_skipped(self):
        sample = _make_sample()
        # No findings added
        report = _make_report(samples=[sample])
        sarif = generate_sarif(report)
        run = sarif["runs"][0]

        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []


# ---------------------------------------------------------------------------
# Write SARIF tests
# ---------------------------------------------------------------------------

class TestWriteSarif:
    """Test SARIF file writing."""

    def test_write_sarif_creates_file(self, tmp_path):
        report = _make_report(samples=[])
        out = tmp_path / "report.sarif"

        write_sarif(report, out)
        assert out.exists()

    def test_write_sarif_valid_json(self, tmp_path):
        report = _make_report(samples=[])
        out = tmp_path / "report.sarif"

        write_sarif(report, out)
        content = json.loads(out.read_text(encoding="utf-8"))
        assert content["version"] == "2.1.0"

    def test_write_sarif_with_findings(self, tmp_path):
        sample = _make_sample()
        sample.analysis_findings.append(_make_finding())
        report = _make_report(samples=[sample])
        out = tmp_path / "report.sarif"

        write_sarif(report, out)
        content = json.loads(out.read_text(encoding="utf-8"))
        run = content["runs"][0]
        assert len(run["results"]) == 1
