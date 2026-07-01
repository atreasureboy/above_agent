"""Filter stage interface and result types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.models import Sample


@dataclass
class FilterResult:
    """Output of a single filter stage."""
    passed: list
    rejected: list[tuple[Sample, str]]  # (sample, reason)

    @property
    def filtered_count(self) -> int:
        return len(self.rejected)

    @property
    def passed_count(self) -> int:
        return len(self.passed)


class FilterStage(ABC):
    """Base class for a single funnel filtering stage."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable stage name, e.g. 'L1: Signature whitelist'."""
        ...

    @property
    @abstractmethod
    def cost(self) -> str:
        """Approximate cost per sample: 'μs' | 'ms' | 's' | 'min'."""
        ...

    @abstractmethod
    def apply(self, samples: list) -> FilterResult:
        """Run this stage's filtering logic.

        Args:
            samples: Input items (Sample objects or enriched dicts).

        Returns:
            FilterResult with passed and rejected items.
        """
        ...

    def format_summary(self, result: FilterResult) -> str:
        """Return a one-line summary of this stage's result."""
        inp = result.passed_count + result.filtered_count
        pct = f"{result.filtered_count / inp * 100:.0f}%" if inp else "0%"
        return (
            f"  {self.name}: {inp} → {result.passed_count} "
            f"(filtered {result.filtered_count}, {pct} removed)"
        )
