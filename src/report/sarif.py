"""SARIF v2.1.0 report generator for DriverScope.

Produces output conforming to the OASIS SARIF specification:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import src
from src.models import Finding, Report, Sample


def _parse_location_hex(location: str) -> int:
    """Extract a hex address from a location string like 'IAT@0x140014130' or '0x140014130'."""
    if not location:
        return 0
    # Bare hex address
    if location.startswith("0x") and "@" not in location:
        try:
            return int(location, 16)
        except ValueError:
            return 0
    if "@" not in location:
        return 0
    hex_part = location.split("@")[-1]
    if not hex_part:
        return 0
    try:
        return int(hex_part, 16)
    except ValueError:
        return 0


SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif(report: Report) -> dict[str, Any]:
    """Convert a DriverScope Report to a SARIF v2.1.0 log object."""
    rules, results = _build_rules_and_results(report)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DriverScope",
                        "version": src.__version__,
                        "informationUri": "https://github.com/atreasureboy/BYOVD_DETECT",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.timestamp,
                        "commandLine": f"driverscope scan --backend {report.backend}",
                    }
                ],
            }
        ],
    }
    return sarif


def _build_rules_and_results(
    report: Report,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract unique rules and build result entries from all findings."""
    rule_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for sample in report.samples:
        if not sample.analysis_findings:
            continue

        for finding in sample.analysis_findings:
            rule_id = _rule_id(finding)
            if rule_id not in rule_map:
                rule_map[rule_id] = _rule_from_finding(finding)

            result = _result_from_finding(sample, finding, rule_id)
            results.append(result)

    return list(rule_map.values()), results


def _rule_id(finding: Finding) -> str:
    """Generate a stable rule ID from a finding."""
    cat = finding.category.value.upper()
    return f"DRIVERSCOPE_{cat}"


def _rule_from_finding(finding: Finding) -> dict[str, Any]:
    """Create a SARIF reportingConfiguration (rule) from a finding."""
    rule = {
        "id": _rule_id(finding),
        "name": finding.category.value,
        "shortDescription": {"text": finding.description[:200]},
        "defaultConfiguration": {
            "level": SEVERITY_TO_SARIF.get(finding.severity.value, "note"),
        },
        "helpUri": "https://github.com/DriverScope",
        "fullDescription": {
            "text": finding.description,
        },
    }
    # Enrich attack_chain rules with metadata
    if finding.category.value == "attack_chain" and finding.context:
        ctx = finding.context
        rule["properties"] = {
            "primitive_apis": ctx.get("primitive_apis", []),
            "missing_checks": ctx.get("missing_checks", []),
            "ioctl_codes": ctx.get("ioctl_codes", []),
        }
        rule["fullDescription"]["text"] = (
            f"Complete BYOVD attack chain: IOCTL handler calls dangerous "
            f"kernel APIs ({', '.join(ctx.get('primitive_apis', []))}) "
            f"without input validation ({', '.join(ctx.get('missing_checks', []))}). "
            f"Exposed IOCTLs: {', '.join(ctx.get('ioctl_codes', []))}."
        )
    return rule


def _result_from_finding(
    sample: Sample,
    finding: Finding,
    rule_id: str,
) -> dict[str, Any]:
    """Create a SARIF result entry from a sample + finding."""
    # Build rich properties dict
    props: dict[str, Any] = {
        "sample_name": sample.name,
        "sample_sha256": sample.sha256,
        "sample_company": sample.company,
        "sample_driver_type": sample.driver_type,
        "risk_score": sample.risk_score,
        "function_address": hex(finding.function_address) if finding.function_address else None,
        "api_name": finding.api_name or None,
        "ioctl_code": hex(finding.ioctl_code) if finding.ioctl_code else None,
        "confidence": finding.confidence.value,
    }

    # Add context for attack chain findings
    if finding.context:
        for key, val in finding.context.items():
            if key not in ("dangerous_apis", "missing_checks", "validation_found"):
                props[f"context_{key}"] = val

    result = {
        "ruleId": rule_id,
        "level": SEVERITY_TO_SARIF.get(finding.severity.value, "note"),
        "message": {
            "text": finding.description,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(sample.path),
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
        ],
        "properties": props,
    }

    # Add evidence as code locations if available
    if finding.evidence:
        for ev in finding.evidence:
            if ev.location.startswith(("0x", "IAT@")):
                loc = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(sample.path),
                        },
                        "address": {
                            "absoluteAddress": _parse_location_hex(ev.location),
                        },
                    },
                }
                result.setdefault("relatedLocations", []).append(loc)

    # For attack chain findings, add a rich text snippet and tags
    if finding.category.value == "attack_chain" and finding.context:
        apis = finding.context.get("primitive_apis", [])
        missing = finding.context.get("missing_checks", [])
        ioctls = finding.context.get("ioctl_codes", [])
        result["message"]["text"] = (
            f"BYOVD Attack Chain: {' + '.join(apis)} "
            f"without validation ({', '.join(missing)})"
        )
        # Add tags for OVOIDA-confirmed chains
        tags = []
        if finding.context.get("ovoida_confirmed") or finding.context.get("ovoida_session"):
            tags.append("ovoida-confirmed")
        if ioctls:
            tags.extend([f"ioctl:{c}" for c in ioctls[:5]])
        if tags:
            result["tags"] = tags
        # Add relatedLocations for IOCTL codes
        if ioctls:
            for code in ioctls[:5]:
                result.setdefault("relatedLocations", []).append({
                    "id": f"ioctl-{code}",
                    "message": {"text": f"IOCTL code {code}"},
                })

    return result


def write_sarif(report: Report, output_path: Path) -> None:
    """Generate and write a SARIF report."""
    sarif = generate_sarif(report)
    output_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False))
