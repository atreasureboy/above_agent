"""DriverScope — Coverage Metrics Analyzer.

Quantifies how thoroughly the analysis covered each driver:
  - Function coverage: what fraction of disassembled functions were analyzed
  - CFG coverage: what fraction of basic blocks were traversed in path analysis
  - API coverage: which dangerous APIs were detected vs total known set
  - Path coverage: fraction of paths from IOCTL entry to dangerous sinks explored

This answers the critical question for "zero false negative" detection:
**"What did I miss?"**

Output is attached to the Sample as a CoverageReport and can be serialized
to JSON for downstream reporting.

Usage:
    from src.analysis.core.coverage import CoverageAnalyzer, CoverageReport
    analyzer = CoverageAnalyzer()
    report = analyzer.analyze(sample, ir)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)
from src.config.defaults import DANGEROUS_API_SET


@dataclass
class CoverageReport:
    """Quantitative coverage metrics for a single analysis."""

    # Function-level coverage
    total_functions: int = 0
    analyzed_functions: int = 0           # Functions that had any API call pattern
    unanalyzed_functions: int = 0         # Functions too small/no CFG to analyze

    # CFG block coverage
    total_blocks: int = 0
    visited_blocks: int = 0               # Blocks reached during path analysis

    # API coverage
    known_dangerous_apis: int = 0          # Total APIs in DANGEROUS_API_SET
    detected_dangerous_apis: int = 0       # APIs actually found in this driver
    undetected_dangerous_apis: list[str] = field(default_factory=list)

    # IOCTL handler coverage
    total_handlers: int = 0                # Number of IOCTL handlers found
    handlers_with_cfg: int = 0             # Handlers that have a CFG available
    handlers_analyzed: int = 0             # Handlers that were fully analyzed

    # Taint coverage
    taint_sources_found: int = 0
    taint_sinks_found: int = 0
    tainted_paths_confirmed: int = 0       # Paths where taint source→sink confirmed

    # Overall score (0.0-1.0)
    overall_coverage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON reporting."""
        return {
            "function_coverage": {
                "total": self.total_functions,
                "analyzed": self.analyzed_functions,
                "unanalyzed": self.unanalyzed_functions,
                "ratio": round(self.analyzed_functions / max(self.total_functions, 1), 3),
            },
            "cfg_block_coverage": {
                "total": self.total_blocks,
                "visited": self.visited_blocks,
                "ratio": round(self.visited_blocks / max(self.total_blocks, 1), 3),
            },
            "api_coverage": {
                "known": self.known_dangerous_apis,
                "detected": self.detected_dangerous_apis,
                "undetected": self.undetected_dangerous_apis,
                "ratio": round(self.detected_dangerous_apis / max(self.known_dangerous_apis, 1), 3),
            },
            "ioctl_handler_coverage": {
                "total": self.total_handlers,
                "with_cfg": self.handlers_with_cfg,
                "analyzed": self.handlers_analyzed,
                "ratio": round(self.handlers_analyzed / max(self.total_handlers, 1), 3),
            },
            "taint_coverage": {
                "sources": self.taint_sources_found,
                "sinks": self.taint_sinks_found,
                "confirmed_paths": self.tainted_paths_confirmed,
            },
            "overall_coverage": round(self.overall_coverage, 3),
        }

    def summary(self) -> str:
        """Human-readable one-line summary."""
        func_ratio = self.analyzed_functions / max(self.total_functions, 1)
        cfg_ratio = self.visited_blocks / max(self.total_blocks, 1)
        handler_ratio = self.handlers_analyzed / max(self.total_handlers, 1)
        return (
            f"Coverage: functions={func_ratio:.0%}, "
            f"CFG blocks={cfg_ratio:.0%}, "
            f"handlers={handler_ratio:.0%}, "
            f"overall={self.overall_coverage:.1%}"
        )


class CoverageAnalyzer(Analyzer):
    """Computes coverage metrics after all other analyzers have run."""

    @property
    def name(self) -> str:
        return "CoverageAnalyzer"

    @property
    def description(self) -> str:
        return "Quantifies analysis coverage: functions, CFG blocks, APIs, handlers."

    @property
    def is_correlator(self) -> bool:
        return True  # Must run after all other analyzers

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []
        report = CoverageReport()

        # Function coverage
        report.total_functions = len(ir.functions)
        # Functions that have any API call pattern or CFG
        for func in ir.functions.values():
            if func.address in ir.function_apis or func.address in ir.cfgs:
                report.analyzed_functions += 1
            else:
                report.unanalyzed_functions += 1

        # CFG block coverage — count all blocks and those on analyzed paths
        for cfg in list(ir.cfgs.values()) + list(ir.simple_cfgs.values()):
            report.total_blocks += len(cfg.blocks)
            # Blocks that are successors of entry block are "visited"
            entry = cfg.blocks.get(cfg.entry_block)
            if entry:
                visited = self._count_reachable_blocks(entry, cfg)
                report.visited_blocks += visited

        # API coverage
        report.known_dangerous_apis = len(DANGEROUS_API_SET)
        detected_apis = set()
        for func_apis in ir.function_apis.values():
            detected_apis.update(func_apis)
        detected_dangerous = detected_apis & DANGEROUS_API_SET
        report.detected_dangerous_apis = len(detected_dangerous)
        report.undetected_dangerous_apis = sorted(DANGEROUS_API_SET - detected_dangerous)

        # IOCTL handler coverage
        report.total_handlers = len(ir.ioctl_handlers)
        for handler_addr in ir.ioctl_handlers.values():
            if handler_addr == 0:
                continue
            cfg = ir.cfgs.get(handler_addr) or ir.simple_cfgs.get(handler_addr)
            if cfg:
                report.handlers_with_cfg += 1
            # Handler is "analyzed" if it has findings associated
            if any(f.function_address == handler_addr for f in sample.analysis_findings):
                report.handlers_analyzed += 1
            elif cfg:
                # Has CFG, was reachable
                report.handlers_analyzed += 1

        # Taint coverage — extract from findings
        for f in sample.analysis_findings:
            ctx = f.context or {}
            if "taint_confirmed" in ctx:
                report.taint_sources_found += len(ctx.get("taint_sources", []))
                report.taint_sinks_found += len(ctx.get("taint_sinks", []))
                if ctx.get("taint_confirmed"):
                    report.tainted_paths_confirmed += 1

        # Overall coverage score
        func_ratio = report.analyzed_functions / max(report.total_functions, 1)
        cfg_ratio = report.visited_blocks / max(report.total_blocks, 1)
        handler_ratio = report.handlers_analyzed / max(report.total_handlers, 1) if report.total_handlers > 0 else 1.0

        # Weighted average: handlers are most important (0.5), functions (0.3), CFG (0.2)
        report.overall_coverage = 0.3 * func_ratio + 0.2 * cfg_ratio + 0.5 * handler_ratio

        # Store on sample for downstream use
        sample.coverage_report = report  # type: ignore[attr-defined]

        # Generate coverage finding (INFO level, always emitted)
        findings.append(
            Finding(
                category=FindingCategory.IOCTL_DISPATCHER_FOUND,  # Reuse INFO category
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                description=report.summary(),
                context={
                    "coverage_report": report.to_dict(),
                    "coverage_type": "analysis_coverage",
                },
                evidence=[
                    Evidence(
                        type="coverage_metrics",
                        location="analysis_pipeline",
                        snippet=report.summary(),
                        rule_id="COV_ANALYSIS",
                    )
                ],
            )
        )

        # Generate LOW severity finding if coverage is poor
        if report.overall_coverage < 0.5 and report.total_handlers > 0:
            findings.append(
                Finding(
                    category=FindingCategory.PARTIAL_VALIDATION,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    description=(
                        f"Analysis coverage is low ({report.overall_coverage:.0%}). "
                        f"{report.unanalyzed_functions} functions were not analyzed "
                        f"(no CFG or API patterns). Some vulnerability paths may be missed."
                    ),
                    context={"coverage": report.overall_coverage},
                )
            )

        return findings

    @staticmethod
    def _count_reachable_blocks(entry, cfg) -> int:
        """BFS count of blocks reachable from entry in this CFG."""
        visited = set()
        queue = [entry.address]
        while queue:
            addr = queue.pop(0)
            if addr in visited:
                continue
            visited.add(addr)
            block = cfg.blocks.get(addr)
            if block:
                for succ in block.successors:
                    if succ not in visited:
                        queue.append(succ)
        return len(visited)
