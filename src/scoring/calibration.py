"""Scoring calibration — validate risk thresholds against known samples.

Uses the production DefaultScoringEngine to score labeled finding data,
ensuring calibration results match production behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.models import Finding, Sample, Architecture
from src.scoring.engine import DefaultScoringEngine


@dataclass
class CalibrationResult:
    """Result of a calibration run."""
    threshold_recommended: float
    precision: float
    recall: float
    f1: float
    auc_roc: float
    total_samples: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    per_threshold: list[dict] = field(default_factory=list)


def _score_findings(findings: list[Finding]) -> float:
    """Score a finding list using the production engine."""
    engine = DefaultScoringEngine()
    # Create a minimal sample — only needed for engine interface
    sample = Sample(
        path=Path("calibration"),
        name="calibration",
        company="",
        version="",
        arch=Architecture.X64,
        sha256="",
        size=0,
    )
    score = engine.score(sample, findings)
    return score.overall


def calibrate(
    vulnerable_findings: list[list[Finding]] | None = None,
    clean_findings: list[list[Finding]] | None = None,
    corpus_path: Path | None = None,
) -> CalibrationResult:
    """Run calibration on labeled finding data.

    Args:
        vulnerable_findings: List of finding lists for known-vulnerable samples.
        clean_findings: List of finding lists for known-clean samples.
        corpus_path: Path to labeled sample directory (future).

    Returns:
        CalibrationResult with recommended threshold and metrics.
    """
    if vulnerable_findings is None:
        vulnerable_findings = []
    if clean_findings is None:
        clean_findings = []

    if not vulnerable_findings and not clean_findings:
        return CalibrationResult(
            threshold_recommended=7.0,
            precision=0.0, recall=0.0, f1=0.0, auc_roc=0.0,
            total_samples=0,
            true_positives=0, true_negatives=0,
            false_positives=0, false_negatives=0,
            per_threshold=[],
        )

    vuln_scores = [_score_findings(f) for f in vulnerable_findings]
    clean_scores = [_score_findings(f) for f in clean_findings]

    n_vuln = len(vuln_scores)
    n_clean = len(clean_scores)
    total = n_vuln + n_clean

    best_f1 = 0.0
    best_threshold = 7.0
    per_threshold = []

    for t_int in range(0, 21):
        t = t_int * 0.5
        tp = sum(1 for s in vuln_scores if s >= t)
        fn = n_vuln - tp
        fp = sum(1 for s in clean_scores if s >= t)
        tn = n_clean - fp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        per_threshold.append({
            "threshold": t,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        })

        if f1 > best_f1:
            best_f1 = f1
            best_threshold = t

    auc = _compute_auc_roc(per_threshold)
    best_row = next(
        (r for r in per_threshold if r["threshold"] == best_threshold),
        {},
    )

    return CalibrationResult(
        threshold_recommended=best_threshold,
        precision=best_row.get("precision", 0.0),
        recall=best_row.get("recall", 0.0),
        f1=best_row.get("f1", 0.0),
        auc_roc=round(auc, 3),
        total_samples=total,
        true_positives=best_row.get("tp", 0),
        true_negatives=best_row.get("tn", 0),
        false_positives=best_row.get("fp", 0),
        false_negatives=best_row.get("fn", 0),
        per_threshold=per_threshold,
    )


def _compute_auc_roc(per_threshold: list[dict]) -> float:
    """Compute AUC-ROC via trapezoidal integration over the ROC curve."""
    if not per_threshold:
        return 0.0

    sorted_pts = sorted(per_threshold, key=lambda x: x["threshold"], reverse=True)

    points = []
    for pt in sorted_pts:
        tpr = pt["tp"] / (pt["tp"] + pt["fn"]) if (pt["tp"] + pt["fn"]) > 0 else 0.0
        fpr = pt["fp"] / (pt["fp"] + pt["tn"]) if (pt["fp"] + pt["tn"]) > 0 else 0.0
        points.append((fpr, tpr))

    if points[0] != (0.0, 0.0):
        points.insert(0, (0.0, 0.0))
    if points[-1] != (1.0, 1.0):
        points.append((1.0, 1.0))

    auc = 0.0
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        avg_y = (points[i][1] + points[i - 1][1]) / 2.0
        auc += dx * avg_y

    return max(0.0, min(1.0, auc))
