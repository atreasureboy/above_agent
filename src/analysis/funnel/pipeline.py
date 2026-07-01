"""FilterPipeline — chains FilterStages together into a funnel."""

from __future__ import annotations

import time
from typing import Any

from src.analysis.funnel.stages import FilterStage, FilterResult


class FilterPipeline:
    """Orchestrates a sequence of FilterStage instances.

    Each stage receives the output of the previous stage's `passed` list.
    Rejected items accumulate across all stages for reporting.
    """

    def __init__(self, stages: list[FilterStage]) -> None:
        self.stages = stages

    def run(
        self,
        samples: list,
        verbose: bool = True,
        cap: int = 0,
    ) -> dict[str, Any]:
        """Run all stages sequentially.

        Args:
            samples: Initial sample list.
            verbose: Print per-layer stats.
            cap: Maximum number of survivors to return (0 = unlimited).

        Returns:
            Dict with {"survivors": [...], "stats": {...}, "layers": [...]}.
        """
        start = time.time()
        l0_count = len(samples)
        current = samples
        layer_results: list[dict] = []
        all_rejected: list = []

        if verbose:
            print(f"\n{'=' * 60}")
            print(f"  Filter Pipeline — Progressive Filtering")
            print(f"{'=' * 60}")
            print(f"  L0: {l0_count} driver(s) enumerated")

        for stage in self.stages:
            result = stage.apply(current)
            all_rejected.extend(result.rejected)

            layer_results.append({
                "stage": stage.name,
                "cost": stage.cost,
                "input": result.passed_count + result.filtered_count,
                "passed": result.passed_count,
                "rejected": result.filtered_count,
                "rejected_items": [
                    {"name": s.name, "reason": r} for s, r in result.rejected[:10]
                ],
            })

            if verbose:
                total = result.passed_count + result.filtered_count
                pct = f"{result.filtered_count / total * 100:.0f}%" if total else "0%"
                print(f"  {stage.name}: {total} → "
                      f"{result.passed_count} (filtered {result.filtered_count}, "
                      f"{pct} removed)")

            current = result.passed
            if not current:
                break

        # Apply cap
        survivors = current
        if cap > 0:
            survivors = survivors[:cap]

        elapsed = time.time() - start

        # Build summary chain
        summary_parts = [f"L0: {l0_count}"]
        for i, lr in enumerate(layer_results, 1):
            summary_parts.append(f"L{i}: {lr['passed']}")

        if verbose:
            print(f"\n  {'=' * 56}")
            print(f"  Pipeline Summary:")
            print(f"    {' → '.join(summary_parts)} → Final: {len(survivors)}")
            print(f"  Time: {elapsed:.1f}s")
            print(f"  {'=' * 60}")

        stats = {
            "l0_enumerated": l0_count,
            "layers": layer_results,
            "total_filtered": len(all_rejected),
            "total_survivors": len(current),
            "final_capped": len(survivors),
            "elapsed": round(elapsed, 1),
        }

        return {
            "survivors": survivors,
            "stats": stats,
            "layers": layer_results,
        }
