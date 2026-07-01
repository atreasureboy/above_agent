"""
DriverScope — Analyzer plugin interface.

Every analysis engine (structure, primitive, dataflow, dynamic)
implements this interface. The analysis core discovers and runs all
registered analyzers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.models import DisassemblyResult, Finding, Sample


class Analyzer(ABC):
    """Base class for all analyzers.

    Each analyzer is an independent plugin that:
    1. Receives a Sample (with its DisassemblyResult attached)
    2. Returns a list of Findings with confidence scores
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable analyzer name, e.g. 'DangerousPrimitiveAnalyzer'."""

    @property
    @abstractmethod
    def description(self) -> str:
        """What this analyzer looks for."""

    @property
    def enabled(self) -> bool:
        """Whether this analyzer is active. Override to implement feature flags."""
        return True

    @property
    def is_correlator(self) -> bool:
        """Whether this analyzer needs all other findings populated first."""
        return False

    @abstractmethod
    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        """Run analysis on a single sample.

        Args:
            sample: The enriched Sample object (from ingestion layer).
            ir: The disassembly result (from disassembly layer).

        Returns:
            List of findings, each with category, severity, and confidence.
        """

    def get_metadata(self) -> dict[str, Any]:
        """Return analyzer metadata for reporting."""
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
        }
