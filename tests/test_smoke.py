"""
Smoke tests — verify all imports, basic functionality, and pipeline integrity.
"""

import pytest


def test_import_models():
    """Verify core models can be imported."""
    from src.models import (
        Sample, Finding, Report, RiskScore, Evidence,
        Architecture, Severity, Confidence,
        FindingCategory, Function, BasicBlock,
        Instruction, CFG, DisassemblyResult,
        SignatureStatus,
    )

    assert Architecture.X64.value == "x64"
    assert Severity.CRITICAL.value == "critical"
    assert Confidence.HIGH.value == 0.9
    assert FindingCategory.ARBITRARY_MEMORY_MAP.value == "arbitrary_memory_map"


def test_import_analyzer():
    """Verify analyzer interface can be imported."""
    from src.analysis.analyzer import Analyzer
    assert Analyzer is not None


def test_import_disassembly_backend():
    """Verify disassembly backend interface can be imported."""
    from src.disassembly.backend import DisassemblyBackend
    assert DisassemblyBackend is not None


def test_import_capstone_backend():
    """Verify Capstone backend is available."""
    from src.disassembly.capstone_backend import CapstoneBackend
    backend = CapstoneBackend()
    assert backend.is_available()
    assert backend.name == "capstone"


def test_import_scoring():
    """Verify scoring engine can be imported."""
    from src.scoring.engine import DefaultScoringEngine
    engine = DefaultScoringEngine()
    assert engine is not None


def test_import_ingestion():
    """Verify ingestion layer can be imported."""
    from src.ingestion.pe_parser import ingest, ingest_directory
    assert ingest is not None
    assert ingest_directory is not None


def test_import_pipeline():
    """Verify pipeline orchestrator can be imported."""
    from src.analysis.pipeline import run_single, run_batch
    assert run_single is not None
    assert run_batch is not None


def test_analyzer_discovery():
    """Verify analyzers are auto-discovered."""
    from src.analysis.core.registry import list_analyzers, get_registered_analyzers

    analyzers = list_analyzers()
    assert len(analyzers) >= 2

    names = [a["name"] for a in analyzers]
    assert "StructureAnalyzer" in names
    assert "DangerousPrimitiveAnalyzer" in names


def test_risk_score_level():
    """Verify risk score level mapping."""
    from src.models import RiskScore
    score = RiskScore(overall=9.5, breakdown={})
    assert score.level == "CRITICAL"

    score = RiskScore(overall=7.5, breakdown={})
    assert score.level == "HIGH"

    score = RiskScore(overall=5.0, breakdown={})
    assert score.level == "MEDIUM"

    score = RiskScore(overall=2.0, breakdown={})
    assert score.level == "LOW"

    score = RiskScore(overall=0.0, breakdown={})
    assert score.level == "NONE"


def test_report_top_n():
    """Verify report top-N sorting."""
    from src.models import Sample, Architecture, Report

    samples = []
    for i in range(5):
        s = Sample(
            path=__import__("pathlib").Path(f"test{i}.sys"),
            name=f"test{i}.sys",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256=f"hash{i}",
            size=1000,
        )
        s.risk_score = float(i * 2)
        samples.append(s)

    report = Report(
        samples=samples,
        timestamp="2026-01-01",
        tool_version="0.0.1",
        backend="capstone",
    )

    top3 = report.top_n(3)
    assert len(top3) == 3
    assert top3[0].risk_score >= top3[1].risk_score >= top3[2].risk_score


def test_finding_to_dict():
    """Verify finding serialization."""
    from src.models import Finding, FindingCategory, Severity, Confidence, Evidence

    f = Finding(
        category=FindingCategory.ARBITRARY_MEMORY_MAP,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="Test finding",
        function_address=0x1000,
        api_name="MmMapIoSpace",
        evidence=[
            Evidence(
                type="import",
                location="IAT@0x12340",
                snippet="ntoskrnl.MmMapIoSpace",
                rule_id="PRIM_ARBITRARY_MEMORY_MAP",
            )
        ],
    )

    d = f.to_dict()
    assert d["category"] == "arbitrary_memory_map"
    assert d["severity"] == "high"
    assert d["confidence"] == 0.7
    assert d["function_address"] == "0x1000"
    assert d["api_name"] == "MmMapIoSpace"
    assert len(d["evidence"]) == 1
    assert d["evidence"][0]["type"] == "import"


def test_import_funnel_chain():
    """Verify filter chain classes can be imported."""
    from src.analysis.funnel import (
        FilterPipeline, FilterStage, FilterResult,
        WhitelistStage, ImportScoreStage, LightDisasmStage, LOLMatchStage,
        run_funnel,
    )
    assert FilterPipeline is not None
    assert WhitelistStage is not None
    assert ImportScoreStage is not None
    assert LightDisasmStage is not None
    assert LOLMatchStage is not None
    assert run_funnel is not None


def test_import_intel_layer():
    """Verify threat intel layer can be imported."""
    from src.intel.base import ThreatIntelProvider, MatchResult
    from src.intel.loldrivers import LOLDriversProvider
    assert ThreatIntelProvider is not None
    assert LOLDriversProvider is not None


def test_import_sarif():
    """Verify SARIF generator can be imported."""
    from src.report.sarif import generate_sarif, write_sarif
    assert generate_sarif is not None
    assert write_sarif is not None


def test_import_calibration():
    """Verify calibration module can be imported."""
    from src.scoring.calibration import calibrate, CalibrationResult
    assert calibrate is not None
    assert CalibrationResult is not None
