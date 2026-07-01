"""Deep reverse engineering analyzers.

Provides a convenience function to run the full analysis pipeline
with Ghidra as the disassembly backend for maximum decompilation quality.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.disassembly.ghidra_backend import GhidraBackend
from src.ingestion.pe_parser import ingest
from src.analysis.core.registry import run_all_analyzers
from src.scoring.engine import DefaultScoringEngine


def run_deep_analysis(
    sample_path: Path,
    verbose: bool = True,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run full analysis pipeline with Ghidra backend.

    Args:
        sample_path: Path to the .sys file.
        verbose: Print progress messages.
        timeout: Max seconds for Ghidra analysis.

    Returns:
        Dict with keys: risk_score, findings, ir, ghidra_version.

    Raises:
        RuntimeError: If Ghidra is not available.
    """
    backend = GhidraBackend()
    if not backend.is_available():
        raise RuntimeError(
            "Ghidra analyzeHeadless not found. "
            "Set GHIDRA_INSTALL_DIR or add analyzeHeadless to PATH."
        )

    if verbose:
        print(f"[deep] Ghidra {backend.get_version()}")
        print(f"[deep] Analyzing {sample_path.name}...")

    # Layer 1: Ingest
    sample = ingest(sample_path)

    # Layer 2: Ghidra disassembly
    ir = backend.analyze(sample_path)
    sample.disassembly_result = ir

    if verbose:
        print(f"[deep] Functions: {len(ir.functions)}")
        print(f"[deep] IOCTL codes: {len(ir.ioctl_codes)}")

    # Layer 3: Run all analyzers
    findings = run_all_analyzers(sample, ir)
    sample.analysis_findings = findings

    # Layer 4: Scoring
    engine = DefaultScoringEngine()
    score_result = engine.score(sample, findings)
    sample.risk_score = score_result.overall

    if verbose:
        print(f"[deep] Risk score: {score_result.overall}/10")

    return {
        "risk_score": score_result.overall,
        "findings": findings,
        "ir": ir,
        "ghidra_version": backend.get_version(),
    }
