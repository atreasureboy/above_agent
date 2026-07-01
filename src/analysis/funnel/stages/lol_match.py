"""L2: LOLDrivers threat intel blacklist filter stage.

Samples matching LOLDrivers entries are immediately flagged as known-vulnerable.
Uses the ThreatIntelProvider interface for multi-source matching.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.analysis.funnel.stages import FilterStage, FilterResult
from src.intel.loldrivers import LOLDriversProvider

if TYPE_CHECKING:
    from src.models import Sample


class LOLMatchStage(FilterStage):
    """L2: Check samples against LOLDrivers known-vulnerable database.

    Runs after L1 whitelist. A SHA256 match immediately flags the sample
    as known-vulnerable — it can be either skipped (already known) or
    flagged for priority analysis depending on the use case.

    Default behavior: pass through (include in candidates) but annotate
    with threat intel match info so downstream stages can prioritize.
    """

    def __init__(self, skip_known: bool = False) -> None:
        """
        Args:
            skip_known: If True, reject matched samples (they're already
                documented vulnerabilities). If False, pass them through
                with a threat_intel_match annotation.
        """
        self.skip_known = skip_known
        self._provider: LOLDriversProvider | None = None

    def _get_provider(self) -> LOLDriversProvider:
        """Lazy-init the provider — only fetch network data on first use."""
        if self._provider is None:
            self._provider = LOLDriversProvider()
            self._provider.refresh()
        return self._provider

    @property
    def name(self) -> str:
        return "L2: LOLDrivers threat intel"

    @property
    def cost(self) -> str:
        return "ms"

    def apply(self, samples: list) -> FilterResult:
        passed: list = []
        rejected: list = []

        for item in samples:
            # Handle both Sample objects and enriched dicts from previous stages
            if hasattr(item, "sha256"):
                sha256 = item.sha256
                company = item.company
                filename = item.name
            elif isinstance(item, dict):
                sample_obj = item.get("sample")
                if sample_obj is None:
                    passed.append(item)
                    continue
                sha256 = sample_obj.sha256
                company = sample_obj.company
                filename = sample_obj.name
            else:
                passed.append(item)
                continue

            match = self._get_provider().match(
                sha256=sha256,
                company=company,
                filename=filename,
            )
            if match:
                # Annotate with threat intel info
                if hasattr(item, "__dict__"):
                    item.threat_intel_match = match
                elif isinstance(item, dict):
                    item["threat_intel_match"] = match

                if self.skip_known:
                    target = item if hasattr(item, "name") else item.get("sample", item)
                    rejected.append((target, f"LOLDrivers match: {match.driver_id}"))
                else:
                    passed.append(item)
            else:
                passed.append(item)

        return FilterResult(passed=passed, rejected=rejected)
