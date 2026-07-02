"""
DriverScope — Lab Sample Analysis Runner.

Automated script for running the full analysis pipeline on lab/target samples.
Handles packed, obfuscated, and protected samples through Phase 0-3.

Usage:
    # Analyze a single sample
    python -m src.lab_runner analyze path/to/sample.sys

    # Analyze a directory of samples
    python -m src.lab_runner batch path/to/samples/

    # Quick scan (Phase 1 only)
    python -m src.lab_runner scan path/to/sample.sys

    # Analyze with CAPE sandbox integration
    python -m src.lab_runner analyze path/to/sample.sys --cape

    # Analyze with full anti-evasion
    python -m src.lab_runner analyze path/to/sample.sys --evasion-level 3
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab_runner",
        description="Lab Sample Analysis Runner — full pipeline for packed/obfuscated samples",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── analyze subcommand ──
    p = sub.add_parser("analyze", help="Run full Phase 0-3 analysis on a sample")
    p.add_argument("target", help="Path to .sys/.exe/.dll sample")
    p.add_argument("--workspace", "-w", default="lab_workspace", help="Output workspace")
    p.add_argument("--backend", default="capstone", choices=["capstone", "ghidra"])
    p.add_argument("--cape", action="store_true", help="Use CAPE sandbox for unpacking")
    p.add_argument("--cape-url", default="http://localhost:8090", help="CAPE API URL")
    p.add_argument("--dynamic-unpack", action="store_true", help="Enable dynamic unpacking (requires QEMU + Frida)")
    p.add_argument("--evasion-level", type=int, default=0, choices=[0, 1, 2, 3],
                   help="Anti-evasion level (0=off, 1=basic, 2=medium, 3=aggressive)")
    p.add_argument("--score-threshold", type=float, default=0.0,
                   help="Minimum risk score to report (default: 0.0 = report all)")
    p.add_argument("--no-preprocessing", action="store_true", help="Skip Phase 0")
    p.add_argument("--format", nargs="+", default=["json", "markdown"])
    p.add_argument("--output", "-o", help="Output report path (auto-generated if omitted)")

    # ── batch subcommand ──
    b = sub.add_parser("batch", help="Batch analyze a directory of samples")
    b.add_argument("target", help="Directory containing samples")
    b.add_argument("--workspace", "-w", default="lab_workspace")
    b.add_argument("--backend", default="capstone")
    b.add_argument("--cape", action="store_true")
    b.add_argument("--cape-url", default="http://localhost:8090")
    b.add_argument("--dynamic-unpack", action="store_true")
    b.add_argument("--evasion-level", type=int, default=0, choices=[0, 1, 2, 3])
    b.add_argument("--min-score", type=float, default=0.0)
    b.add_argument("--max-samples", type=int, default=0, help="Max samples to analyze (0=all)")
    b.add_argument("--format", nargs="+", default=["json"])
    b.add_argument("--parallel", "-j", type=int, default=1, help="Parallel workers")

    # ── scan subcommand ──
    s = sub.add_parser("scan", help="Quick scan (Phase 1 only)")
    s.add_argument("target", help="Path to sample or directory")
    s.add_argument("--backend", default="capstone")
    s.add_argument("--min-score", type=float, default=0.0)
    s.add_argument("--format", nargs="+", default=["json"])

    # ── classify subcommand ──
    c = sub.add_parser("classify", help="Classify packer/protector without full analysis")
    c.add_argument("target", help="Path to sample")
    c.add_argument("--verbose", "-v", action="store_true")

    return parser


# ── analyze command ──

def cmd_analyze(args: argparse.Namespace) -> int:
    """Run full analysis pipeline on a single sample."""
    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    from src.config import PipelineConfig
    from src.pipeline import run_phase1_scan, run_phase2_deep, generate_unified_report
    from src.analysis.preprocessing import run_preprocessing
    from src.analysis.preprocessing.pipeline import PreprocessingConfig

    print(f"\n{'=' * 60}")
    print(f"  Lab Runner — Full Analysis")
    print(f"  Target: {target}")
    print(f"  Backend: {args.backend}")
    print(f"  CAPE: {'enabled' if args.cape else 'disabled'}")
    print(f"  Evasion Level: {args.evasion_level}")
    print(f"{'=' * 60}")

    total_start = time.time()
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # Phase 0: Preprocessing
    current_target = target
    if not args.no_preprocessing:
        print(f"\n--- Phase 0: Preprocessing ---")
        pp_config = PreprocessingConfig(
            enabled=True,
            allow_static_unpack=True,
            allow_dynamic_unpack=args.dynamic_unpack,
            use_cape=args.cape,
            cape_api_url=args.cape_url,
        )
        pp_result = run_preprocessing(str(target), pp_config)

        if pp_result.was_unpacked:
            print(f"  ✓ Unpacked: {pp_result.cleaned_target}")
            current_target = Path(pp_result.cleaned_target)
        elif pp_result.packer_info and pp_result.packer_info.is_packed:
            print(f"  ⚠ Packer detected: {pp_result.packer_info.name}")
            for reason in pp_result.packer_info.reasons[:3]:
                print(f"    - {reason}")
        else:
            print(f"  ✓ No packing detected")

        if pp_result.deobfuscation_applied:
            print(f"  Deobfuscation: {', '.join(pp_result.deobfuscation_applied)}")

    # Phase 1: DriverScope
    print(f"\n--- Phase 1: DriverScope Static Analysis ---")
    config = PipelineConfig(
        target=current_target,
        workspace=workspace,
        ds_backend=args.backend,
        risk_threshold=0.0,
        max_deep_targets=0,  # No OVOIDA in lab runner
        report_formats=args.format,
    )
    config.resolve_paths()

    scan_result = run_phase1_scan(config)

    # Filter by score threshold
    if args.score_threshold > 0:
        filtered = [s for s in scan_result.top_samples
                    if s["risk_score"] >= args.score_threshold]
        print(f"  Filtered: {len(scan_result.top_samples)} → {len(filtered)} samples (threshold: {args.score_threshold})")
        scan_result.top_samples = filtered

    # Phase 3: Report
    print(f"\n--- Phase 3: Report Generation ---")
    report = generate_unified_report(config, scan_result, [])

    # Print summary
    total_elapsed = time.time() - total_start
    print(f"\n{'=' * 60}")
    print(f"  Analysis Complete in {total_elapsed:.1f}s")
    print(f"  Samples analyzed: {scan_result.samples_scanned}")
    print(f"  High risk: {scan_result.high_risk_count}")
    print(f"  Critical: {scan_result.critical_count}")

    if scan_result.top_samples:
        print(f"\n  Top findings:")
        for s in scan_result.top_samples[:10]:
            level = "CRIT" if s["risk_score"] >= 9.0 else "HIGH" if s["risk_score"] >= 7.0 else "MED "
            print(f"    [{level}] {s['name']}: {s['risk_score']:.1f}/10 ({s['finding_count']} findings)")

    # Save summary
    summary_path = workspace / "lab_summary.json"
    summary = {
        "target": str(target),
        "preprocessing": {
            "unpacked": pp_result.was_unpacked if not args.no_preprocessing else False,
            "packer": pp_result.packer_info.name if not args.no_preprocessing and pp_result.packer_info else "",
            "deobfuscation": pp_result.deobfuscation_applied if not args.no_preprocessing else [],
        },
        "scan": {
            "samples_scanned": scan_result.samples_scanned,
            "high_risk_count": scan_result.high_risk_count,
            "critical_count": scan_result.critical_count,
            "top_samples": scan_result.top_samples[:20],
        },
        "elapsed": total_elapsed,
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Summary: {summary_path}")
    print(f"{'=' * 60}")

    return 0


# ── batch command ──

def cmd_batch(args: argparse.Namespace) -> int:
    """Batch analyze a directory of samples."""
    target = Path(args.target)
    if not target.is_dir():
        print(f"[error] Target is not a directory: {target}", file=sys.stderr)
        return 1

    # Collect samples
    samples = []
    for ext in ("*.sys", "*.exe", "*.dll", "*.drv"):
        samples.extend(target.rglob(ext))

    if not samples:
        print(f"[error] No samples found in: {target}")
        return 1

    if args.max_samples > 0:
        samples = samples[:args.max_samples]

    print(f"\n{'=' * 60}")
    print(f"  Lab Runner — Batch Analysis")
    print(f"  Directory: {target}")
    print(f"  Samples found: {len(samples)}")
    if args.max_samples > 0:
        print(f"  Limiting to: {args.max_samples}")
    print(f"{'=' * 60}")

    # Analyze each sample
    results = []
    for i, sample in enumerate(samples, 1):
        print(f"\n[{i}/{len(samples)}] Analyzing: {sample.name}")

        # Create a minimal args for cmd_analyze
        analyze_args = argparse.Namespace(
            target=str(sample),
            workspace=str(Path(args.workspace) / sample.stem),
            backend=args.backend,
            cape=args.cape,
            cape_url=args.cape_url,
            dynamic_unpack=args.dynamic_unpack,
            evasion_level=args.evasion_level,
            score_threshold=args.min_score,
            no_preprocessing=False,
            format=args.format,
            output=None,
        )

        try:
            ret = cmd_analyze(analyze_args)
            results.append({
                "sample": str(sample),
                "status": "success" if ret == 0 else "failed",
            })
        except Exception as e:
            print(f"  ✗ Error: {e}")
            results.append({
                "sample": str(sample),
                "status": "error",
                "error": str(e),
            })

    # Summary
    success = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] == "failed")
    errors = sum(1 for r in results if r["status"] == "error")

    print(f"\n{'=' * 60}")
    print(f"  Batch Complete")
    print(f"  Total: {len(results)}")
    print(f"  Success: {success}")
    print(f"  Failed: {failed}")
    print(f"  Errors: {errors}")
    print(f"{'=' * 60}")

    # Save batch summary
    summary_path = Path(args.workspace) / "batch_summary.json"
    Path(args.workspace).mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"  Summary: {summary_path}")

    return 0 if errors == 0 else 1


# ── scan command ──

def cmd_scan(args: argparse.Namespace) -> int:
    """Quick scan (Phase 1 only)."""
    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    from src.config import PipelineConfig
    from src.pipeline import run_phase1_scan

    print(f"\n--- Quick Scan (Phase 1 only) ---")
    print(f"  Target: {target}")

    config = PipelineConfig(
        target=target,
        workspace=Path("lab_workspace"),
        ds_backend=args.backend,
        risk_threshold=args.min_score,
        max_deep_targets=0,
        report_formats=args.format,
    )
    config.resolve_paths()

    scan_result = run_phase1_scan(config)

    # Print results
    if scan_result.top_samples:
        print(f"\n  Findings:")
        for s in scan_result.top_samples:
            if s["risk_score"] >= args.min_score:
                print(f"    {s['name']}: {s['risk_score']:.1f}/10 ({s['finding_count']} findings)")
    else:
        print(f"\n  No findings above threshold ({args.min_score})")

    return 0


# ── classify command ──

def cmd_classify(args: argparse.Namespace) -> int:
    """Classify packer/protector without full analysis."""
    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    from src.analysis.preprocessing.pipeline import _classify_packer

    print(f"\n--- Packer Classification ---")
    print(f"  Target: {target}")

    info = _classify_packer(target)

    print(f"\n  Results:")
    print(f"    Packed: {info.is_packed}")
    if info.name:
        print(f"    Packer: {info.name}")
    print(f"    Confidence: {info.confidence:.2f}")
    print(f"    Max entropy: {info.entropy:.2f}")

    if info.section_entropies:
        print(f"\n  Section entropies:")
        for name, entropy in info.section_entropies.items():
            bar = "█" * int(entropy * 2)
            print(f"    {name:12s}: {entropy:.2f} {bar}")

    if args.verbose and info.reasons:
        print(f"\n  Detection reasons:")
        for reason in info.reasons:
            print(f"    - {reason}")

    if info.has_empty_iat:
        print(f"    - Empty/minimal import table")
    if info.entry_point_anomaly:
        print(f"    - Entry point outside normal sections")

    return 0


# ── main ──

def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "batch":
        return cmd_batch(args)
    elif args.command == "scan":
        return cmd_scan(args)
    elif args.command == "classify":
        return cmd_classify(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
