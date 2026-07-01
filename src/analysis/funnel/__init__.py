"""Filter Chain — composable, testable funnel stages."""

from __future__ import annotations

from typing import Any

from src.analysis.funnel.pipeline import FilterPipeline
from src.analysis.funnel.stages import FilterStage, FilterResult
from src.analysis.funnel.stages.whitelist import WhitelistStage
from src.analysis.funnel.stages.import_score import ImportScoreStage, L2_DEFAULT_THRESHOLD
from src.analysis.funnel.stages.light_disasm import LightDisasmStage
from src.analysis.funnel.stages.lol_match import LOLMatchStage

__all__ = [
    "FilterStage",
    "FilterResult",
    "FilterPipeline",
    "WhitelistStage",
    "LOLMatchStage",
    "ImportScoreStage",
    "LightDisasmStage",
    "run_funnel",
    "L2_DEFAULT_THRESHOLD",
]


def run_funnel(
    samples,
    l2_threshold: int = L2_DEFAULT_THRESHOLD,
    l4_max: int = 5,
    verbose: bool = True,
    use_loldrivers: bool = False,
) -> dict[str, Any]:
    """Run the complete filter funnel (compatibility wrapper).

    Builds the stage pipeline and runs it, returning data in the same
    format as the old funnel.py for backwards compatibility.

    Args:
        samples: List of ingested Sample objects.
        l2_threshold: Minimum import score to pass L2.
        l4_max: Max survivors to return.
        verbose: Print per-layer stats.
        use_loldrivers: If True, insert LOLDrivers threat intel stage
            after WhitelistStage. Default False because it requires network
            access and adds latency to the fast-path funnel.

    Returns:
        Dict with "survivors" (list of Sample objects) and "stats".
    """
    stages: list[FilterStage] = [
        WhitelistStage(max_size_kb=200),
        ImportScoreStage(threshold=l2_threshold),
        LightDisasmStage(),
    ]

    if use_loldrivers:
        stages.insert(1, LOLMatchStage(skip_known=False))

    pipeline = FilterPipeline(stages)
    result = pipeline.run(samples, verbose=verbose, cap=l4_max)

    # Convert survivors (enriched dicts) to Sample objects for pipeline.py
    l4_candidates = []
    for item in result["survivors"]:
        if hasattr(item, "sha256"):
            l4_candidates.append(item)
        elif isinstance(item, dict) and "sample" in item:
            l4_candidates.append(item["sample"])

    # Build backwards-compatible stats
    stats = {
        "l0_enumerated": result["stats"]["l0_enumerated"],
        "l4_candidates": len(l4_candidates),
        "elapsed": result["stats"]["elapsed"],
    }

    # Map layer results to old-style keys
    layers = result["layers"]
    if len(layers) >= 1:
        stats["l1_signature_filtered"] = layers[0]["rejected"]
        stats["l1_survivors"] = layers[0]["passed"]
    if len(layers) >= 2:
        stats["l2_import_filtered"] = layers[1]["rejected"]
        stats["l2_survivors"] = layers[1]["passed"]
    if len(layers) >= 3:
        stats["l3_disasm_filtered"] = layers[2]["rejected"]
        stats["l3_survivors"] = layers[2]["passed"]

    return {
        "survivors": l4_candidates,
        "stats": stats,
    }
