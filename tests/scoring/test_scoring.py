"""
Scoring engine tests.
"""

import pytest
from src.models import (
    Finding, FindingCategory, Severity, Confidence,
    RiskScore, Sample, Architecture,
)
from src.scoring.engine import DefaultScoringEngine
from pathlib import Path


def make_sample(name="test.sys") -> Sample:
    return Sample(
        path=Path(name),
        name=name,
        company="Test",
        version="1.0",
        arch=Architecture.X64,
        sha256="hash",
        size=1000,
    )


class TestDefaultScoringEngine:

    def setup_method(self):
        self.engine = DefaultScoringEngine()
        self.sample = make_sample()

    def test_empty_findings_zero_score(self):
        """No findings should result in zero score."""
        score = self.engine.score(self.sample, [])
        assert score.overall == 0.0

    def test_critical_finding_high_score(self):
        """A critical finding with high confidence should score high."""
        findings = [
            Finding(
                category=FindingCategory.CODE_EXECUTION_PRIMITIVE,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Test",
            )
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall > 0.0
        assert "code_execution_primitive" in score.breakdown

    def test_multiple_findings_accumulate(self):
        """Multiple findings should accumulate score."""
        findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Test 1",
            ),
            Finding(
                category=FindingCategory.MSR_ACCESS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Test 2",
            ),
        ]
        score1 = self.engine.score(self.sample, findings[:1])
        score2 = self.engine.score(self.sample, findings)
        assert score2.overall > score1.overall

    def test_low_confidence_reduces_impact(self):
        """Low confidence findings should score less than high confidence."""
        high_conf = Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="High conf",
        )
        low_conf = Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            description="Low conf",
        )
        score_high = self.engine.score(self.sample, [high_conf])
        score_low = self.engine.score(self.sample, [low_conf])
        assert score_high.overall > score_low.overall

    def test_info_severity_zero_weight(self):
        """Info severity findings should contribute zero to the score."""
        findings = [
            Finding(
                category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description="Test",
            )
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall == 0.0

    def test_score_capped_at_ten(self):
        """Score should never exceed 10.0 regardless of finding count."""
        findings = [
            Finding(
                category=FindingCategory.CODE_EXECUTION_PRIMITIVE,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description=f"Finding {i}",
            )
            for i in range(100)
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall <= 10.0

    def test_explain_returns_high_severity_only(self):
        """Explain should only return high/critical findings."""
        findings = [
            Finding(
                category=FindingCategory.CODE_EXECUTION_PRIMITIVE,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Critical finding",
            ),
            Finding(
                category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description="Info finding",
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        assert len(explanation) >= 1
        assert "Critical finding" in explanation[0]

    def test_category_weights_differ(self):
        """Different categories should have different weights."""
        mem_finding = Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Memory",
        )
        exec_finding = Finding(
            category=FindingCategory.CODE_EXECUTION_PRIMITIVE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Exec",
        )
        score_mem = self.engine.score(self.sample, [mem_finding])
        score_exec = self.engine.score(self.sample, [exec_finding])
        # Code execution has higher category weight
        assert score_exec.overall > score_mem.overall

    def test_attack_chain_weight(self):
        """Attack chain findings should contribute significant weight."""
        findings = [
            Finding(
                category=FindingCategory.ATTACK_CHAIN,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Complete BYOVD chain",
                function_address=0x1000,
                context={"primitive_apis": ["MmMapIoSpace"], "missing_checks": ["probe"]},
            ),
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall > 0.0
        assert "attack_chain" in score.breakdown

    def test_validation_amplifier(self):
        """Dangerous primitive + no validation should amplify score."""
        # Scenario 1: Just a memory map finding
        findings_1 = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
        ]
        # Scenario 2: Same + unvalidated input + multiple functions
        findings_2 = findings_1 + [
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe",
                function_address=0x2000,
                api_name="MmMapIoSpace",
            ),
        ]
        score_1 = self.engine.score(self.sample, findings_1)
        score_2 = self.engine.score(self.sample, findings_2)
        # Amplifier + count multiplier should make score_2 significantly higher
        assert score_2.overall > score_1.overall

    def test_known_vulnerable_hash_dominates(self):
        """LOLDrivers hash match should produce a non-zero score."""
        findings = [
            Finding(
                category=FindingCategory.KNOWN_VULNERABLE_HASH,
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                description="Known vulnerable",
            ),
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall > 0.0
        assert "known_vulnerable_hash" in score.breakdown


class TestExplainSummary:
    """Tests for the explain() summary enhancement."""

    def setup_method(self):
        self.engine = DefaultScoringEngine()
        self.sample = make_sample()

    def test_summary_with_attack_chain(self):
        """When attack chains exist, explain should include summary."""
        findings = [
            Finding(
                category=FindingCategory.ATTACK_CHAIN,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Complete BYOVD chain",
                function_address=0x1000,
                context={
                    "chain_type": "byovd_complete",
                    "primitive_apis": ["MmMapIoSpace", "KeWriteMsr"],
                    "missing_checks": ["probe"],
                },
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        summary_lines = [l for l in explanation if "SUMMARY" in l]
        assert len(summary_lines) >= 1
        assert "MmMapIoSpace" in " ".join(summary_lines)

    def test_summary_with_dangerous_apis(self):
        """When dangerous APIs exist without chains, explain should include summary."""
        findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        summary_lines = [l for l in explanation if "SUMMARY" in l]
        assert len(summary_lines) >= 1

    def test_no_summary_when_no_findings(self):
        """Empty findings should not produce a summary line."""
        explanation = self.engine.explain(self.sample, [])
        summary_lines = [l for l in explanation if "SUMMARY" in l]
        assert len(summary_lines) == 0


# ------------------------------------------------------------------
# Wave 1-3: Scoring engine awareness tests
# ------------------------------------------------------------------

class TestWave1Scoring:
    """Tests for string decryption impact on scoring."""

    def setup_method(self):
        self.engine = DefaultScoringEngine()
        self.sample = make_sample()

    def test_decrypted_string_contributes_score(self):
        """String decryption findings should contribute to score."""
        findings = [
            Finding(
                category=FindingCategory.STRING_DECRYPTED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Decrypted: \\Device\\MyDriver",
            ),
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall > 0.0
        assert "string_decrypted" in score.breakdown

    def test_dangerous_decrypted_string_amplifies(self):
        """Dangerous decrypted strings should trigger amplifier."""
        findings_base = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
        ]
        score_without = self.engine.score(self.sample, findings_base)

        findings_with = findings_base + [
            Finding(
                category=FindingCategory.STRING_DECRYPTED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Decrypted: ObRegisterCallbacks",
            ),
        ]
        score_with = self.engine.score(self.sample, findings_with)
        assert score_with.overall >= score_without.overall

    def test_explain_reports_dangerous_strings(self):
        """Explain should mention dangerous decrypted strings."""
        findings = [
            Finding(
                category=FindingCategory.STRING_DECRYPTED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Decrypted: \\Device\\EvilDriver",
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        text = " ".join(explanation)
        assert "Decrypted" in text or "HIGH" in text


class TestWave2Scoring:
    """Tests for extended API hash resolution impact on scoring."""

    def setup_method(self):
        self.engine = DefaultScoringEngine()
        self.sample = make_sample()

    def test_resolved_api_hash_contributes_score(self):
        """API hash resolution findings should contribute to score."""
        findings = [
            Finding(
                category=FindingCategory.API_HASH_RESOLVED_EXTENDED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="sub_1000: Extended hash resolution → ZwCreateFile, ZwClose",
                context={"resolved_apis": ["ZwCreateFile", "ZwClose"], "algorithms": ["djb2", "ror13"]},
            ),
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall > 0.0
        assert "api_hash_resolved_extended" in score.breakdown

    def test_explain_reports_resolved_apis(self):
        """Explain should mention resolved APIs."""
        findings = [
            Finding(
                category=FindingCategory.API_HASH_RESOLVED_EXTENDED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="sub_1000: MmMapIoSpaceEx resolved",
                context={"resolved_apis": ["MmMapIoSpaceEx"], "algorithms": ["fnv1a_64"]},
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        text = " ".join(explanation)
        assert "MmMapIoSpaceEx" in text


class TestWave3Scoring:
    """Tests for advanced taint analysis impact on scoring."""

    def setup_method(self):
        self.engine = DefaultScoringEngine()
        self.sample = make_sample()

    def test_unvalidated_data_flow_contributes_score(self):
        """Advanced taint findings should contribute to score."""
        findings = [
            Finding(
                category=FindingCategory.UNVALIDATED_DATA_FLOW,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Taint path: UserBuffer → rcx → MmMapIoSpaceEx",
                context={"taint_source": "UserBuffer", "sink": "MmMapIoSpaceEx"},
            ),
        ]
        score = self.engine.score(self.sample, findings)
        assert score.overall > 0.0
        assert "unvalidated_data_flow" in score.breakdown

    def test_advanced_taint_amplifies_base_score(self):
        """Advanced taint should amplify existing BYOVD findings."""
        findings_base = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="MmMapIoSpace",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
            Finding(
                category=FindingCategory.UNVALIDATED_USER_INPUT,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="No probe",
                function_address=0x1000,
                api_name="MmMapIoSpace",
            ),
        ]
        score_without = self.engine.score(self.sample, findings_base)

        findings_with = findings_base + [
            Finding(
                category=FindingCategory.UNVALIDATED_DATA_FLOW,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Taint: UserBuffer → __writemsr",
                context={"taint_source": "UserBuffer", "sink": "__writemsr"},
            ),
        ]
        score_with = self.engine.score(self.sample, findings_with)
        assert score_with.overall >= score_without.overall

    def test_explain_reports_taint_findings(self):
        """Explain should mention advanced taint analysis."""
        findings = [
            Finding(
                category=FindingCategory.UNVALIDATED_DATA_FLOW,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Shadow space taint: rcx → MmMapIoSpaceEx",
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        text = " ".join(explanation)
        assert "taint" in text.lower()


class TestWave123CombinedScoring:
    """Tests for combined Wave 1+2+3 amplifier."""

    def setup_method(self):
        self.engine = DefaultScoringEngine()
        self.sample = make_sample()

    def test_combined_waves_higher_than_individual(self):
        """All three waves together should score higher than any single wave."""
        findings_wave1 = [
            Finding(
                category=FindingCategory.STRING_DECRYPTED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Decrypted: \\Device\\Evil",
            ),
        ]
        findings_wave2 = [
            Finding(
                category=FindingCategory.API_HASH_RESOLVED_EXTENDED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Resolved: MmMapIoSpaceEx",
                context={"resolved_apis": ["MmMapIoSpaceEx"], "algorithms": ["ror13"]},
            ),
        ]
        findings_wave3 = [
            Finding(
                category=FindingCategory.UNVALIDATED_DATA_FLOW,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Taint: rcx → __writemsr",
            ),
        ]
        score_1 = self.engine.score(self.sample, findings_wave1)
        score_2 = self.engine.score(self.sample, findings_wave2)
        score_3 = self.engine.score(self.sample, findings_wave3)
        score_combined = self.engine.score(
            self.sample, findings_wave1 + findings_wave2 + findings_wave3
        )
        # Combined should be higher than any individual
        assert score_combined.overall >= score_1.overall
        assert score_combined.overall >= score_2.overall
        assert score_combined.overall >= score_3.overall

    def test_explain_reports_all_wave_features(self):
        """Explain should mention all active wave features."""
        findings = [
            Finding(
                category=FindingCategory.STRING_DECRYPTED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Decrypted: ObRegisterCallbacks",
            ),
            Finding(
                category=FindingCategory.API_HASH_RESOLVED_EXTENDED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Resolved: FltRegisterFilter",
                context={"resolved_apis": ["FltRegisterFilter"], "algorithms": ["fnv1a"]},
            ),
            Finding(
                category=FindingCategory.UNVALIDATED_DATA_FLOW,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Taint: UserBuffer → MmMapIoSpaceEx",
            ),
        ]
        explanation = self.engine.explain(self.sample, findings)
        text = " ".join(explanation)
        assert "ENHANCED" in text
        assert "string decryption" in text or "API hash" in text or "taint" in text

    def test_score_capped_with_waves(self):
        """Score should still be capped at 10.0 with wave amplifiers."""
        findings = []
        for i in range(50):
            findings.extend([
                Finding(
                    category=FindingCategory.STRING_DECRYPTED,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=f"Decrypted string {i}",
                ),
                Finding(
                    category=FindingCategory.API_HASH_RESOLVED_EXTENDED,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=f"Resolved API {i}",
                    context={"resolved_apis": [f"Api{i}"], "algorithms": ["djb2"]},
                ),
                Finding(
                    category=FindingCategory.UNVALIDATED_DATA_FLOW,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=f"Taint path {i}",
                ),
            ])
        score = self.engine.score(self.sample, findings)
        assert score.overall <= 10.0
