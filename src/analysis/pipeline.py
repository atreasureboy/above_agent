"""
DriverScope — Pipeline Orchestrator.

Runs the full 4-layer analysis pipeline for a single sample or batch:
  Ingestion → Disassembly → Analysis → Scoring → Report
"""

from __future__ import annotations

import os
import time
import concurrent.futures
from datetime import datetime
from pathlib import Path

from src.disassembly.capstone_backend import CapstoneBackend
from src.disassembly.ghidra_backend import GhidraBackend
from src.ingestion.pe_parser import ingest, ingest_directory
from src.models import Report, Sample, score_level
from src.analysis.core.registry import run_all_analyzers
from src.scoring.engine import DefaultScoringEngine

import src


def run_single(
    sample_path: Path,
    backend_name: str = "capstone",
    timeout: int = 0,
    use_cache: bool = True,
    score_engine_name: str = "default",
) -> Sample:
    """Run the full pipeline on a single .sys file.

    Args:
        sample_path: Path to the driver .sys file.
        backend_name: Disassembly backend to use.
        timeout: Max seconds for Layers 2-4 (0 = unlimited).
        use_cache: Check analysis cache before running (default True).

    Returns the enriched Sample object with findings and risk score.

    Raises:
        TimeoutError: If analysis exceeds ``timeout`` seconds.
    """
    start = time.time()

    # Layer 1: Ingestion
    print(f"\n[pipeline] Layer 1 — Ingesting {sample_path.name}")
    sample = ingest(sample_path)
    print(f"  Driver: {sample.name} ({sample.driver_type}, {sample.arch.value})")
    print(f"  Company: {sample.company}, Version: {sample.version}")
    print(f"  Imports: {len(sample.imports)}, Exports: {len(sample.exports)}")

    # Check cache before Layers 2-4
    if use_cache:
        from src.analysis.cache import AnalysisCache
        cache = AnalysisCache()
        cached = cache.get(sample.sha256, backend_name, src.__version__)
        if cached:
            print(f"\n[pipeline] Cache hit for {sample.sha256[:12]}...")
            sample.risk_score = cached["risk_score"]
            # Note: cache stores score, not full sample — disassembly/analysis
            # still needs to be re-run if caller needs detailed findings.
            # For single-file scan, we return the cached score but still run
            # the pipeline if the caller needs the full report.
            print(f"  Cached risk score: {sample.risk_score}/10")

    # Layers 2-4: Disassembly → Analysis → Scoring
    if timeout > 0:
        sample = _run_with_timeout(sample, backend_name, timeout, score_engine_name)
    else:
        sample = _run_pipeline_internal(sample, backend_name, print_layer=True, score_engine_name=score_engine_name)

    # Store in cache
    if use_cache:
        from src.analysis.cache import AnalysisCache
        cache = AnalysisCache()
        cache.put(sample.sha256, backend_name, src.__version__, {
            "risk_score": sample.risk_score,
            "finding_count": len(sample.analysis_findings),
        })

    elapsed = time.time() - start
    print(f"\n[pipeline] Completed in {elapsed:.1f}s")

    return sample


def run_batch(
    target: Path,
    backend_name: str = "capstone",
    limit: int = 0,
    min_score: float = 0,
    timeout_per_driver: int = 30,
    use_funnel: bool = True,
    workers: int = 0,
    use_cache: bool = True,
    include_usermode: bool = False,
    score_engine_name: str = "default",
) -> Report:
    """Run the full pipeline on a directory of .sys files (and optionally .exe/.dll).

    When use_funnel=True (default for large directories), runs a multi-layer
    funnel to filter candidates before expensive analysis:
      L0: File enumeration
      L1: Signature whitelist (Microsoft-signed → skip)
      L2: Import table scoring (no disassembly)
      L3: Light disassembly for IOCTL dispatcher
      L4: Full pipeline on survivors

    User-mode binaries (.exe/.dll) skip the funnel and are analyzed directly
    (they don't benefit from IOCTL/IRP-based funnel stages).

    Args:
        target: Directory containing .sys files (and optionally .exe/.dll).
        backend_name: Disassembly backend to use.
        limit: Maximum number of drivers for L4 (0 = unlimited).
        min_score: Only process drivers with risk >= this threshold.
        timeout_per_driver: Max seconds per driver (0 = no timeout).
        use_funnel: Use progressive filtering (recommended for >10 drivers).
        workers: Parallel worker count (0 = auto: CPU count - 1).
        use_cache: Check/store analysis cache (default True).
        include_usermode: Also ingest and analyze .exe/.dll files.

    Returns a Report object aggregating all results.
    """
    start = time.time()

    # L0: Ingestion
    print(f"\n[pipeline] Layer 0 — Ingesting directory {target}")
    samples = ingest_directory(target)

    total_found = len(samples)
    usermode_samples: list[Sample] = []

    if include_usermode:
        from src.ingestion.usermode_parser import ingest_directory_usermode
        usermode_samples = ingest_directory_usermode(target, include_nested=True)
        total_found += len(usermode_samples)
        if usermode_samples:
            print(f"  + {len(usermode_samples)} user-mode PE(s) included")

    if not samples and not usermode_samples:
        raise ValueError(f"No valid samples found in {target}")

    print(f"  Found {total_found} sample(s) ({len(samples)} kernel, {len(usermode_samples)} user-mode)")

    funnel_stats = {}

    if use_funnel and total_found > 5:
        # Run funnel to narrow down candidates (kernel samples only)
        from src.analysis.funnel import run_funnel

        funnel_result = run_funnel(
            samples,
            l2_threshold=15,
            l4_max=limit if limit else 20,  # Analyze up to 20 most suspicious drivers
            verbose=True,
        )
        funnel_stats = funnel_result["stats"]
        l4_candidates = funnel_result["survivors"]
        # User-mode samples skip funnel, go directly to L4
        l4_candidates.extend(usermode_samples)
    else:
        # No funnel — run on all samples (small directory)
        if limit and limit > 0:
            samples = samples[:limit]
        l4_candidates = samples + usermode_samples
        funnel_stats = {
            "l0_enumerated": total_found,
            "l4_candidates": len(l4_candidates),
        }

    # L4: Full pipeline on funnel survivors
    completed = 0
    failed = 0
    timed_out = 0
    high_risk = []

    # Initialize cache (shared across all drivers in batch)
    if use_cache:
        from src.analysis.cache import AnalysisCache
        _cache = AnalysisCache()
        _cache.clear_expired()  # Clean up before batch
    else:
        _cache = None

    # Determine worker count for parallel scanning
    if workers > 0:
        max_workers = workers
    elif len(l4_candidates) > 5:
        # Auto: use CPU count - 1, minimum 1
        max_workers = max(1, os.cpu_count() - 1)
    else:
        # Small batch — sequential is fine
        max_workers = 0  # 0 means sequential below

    if max_workers > 1:
        print(f"\n[pipeline] Parallel mode: {max_workers} workers")
        _enriched = [None] * len(l4_candidates)

        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for i, sample in enumerate(l4_candidates):
                future = executor.submit(
                    _run_pipeline_internal, sample.path, backend_name, False, timeout_per_driver, score_engine_name
                )
                futures[future] = (i, sample)

            for future in concurrent.futures.as_completed(futures):
                i, original_sample = futures[future]
                idx = i + 1
                try:
                    enriched = future.result(timeout=timeout_per_driver if timeout_per_driver > 0 else None)
                    _enriched[i] = enriched

                    # Store in cache
                    if _cache is not None:
                        _cache.put(enriched.sha256, backend_name, src.__version__, {
                            "risk_score": enriched.risk_score,
                            "finding_count": len(enriched.analysis_findings),
                        })

                    completed += 1
                    if enriched.risk_score >= min_score:
                        high_risk.append(enriched)

                    level = score_level(enriched.risk_score)
                    print(f"  [{idx}/{len(l4_candidates)}] {original_sample.name}: {enriched.risk_score:.1f}/10 ({level}), {len(enriched.analysis_findings)} findings")

                except concurrent.futures.TimeoutError:
                    print(f"  [{idx}/{len(l4_candidates)}] {original_sample.name}: TIMEOUT")
                    timed_out += 1
                    failed += 1
                except Exception as e:
                    print(f"  [{idx}/{len(l4_candidates)}] {original_sample.name}: ERROR: {e}")
                    failed += 1

        # Replace with enriched samples (keep originals for failed/timed-out)
        for i, enriched in enumerate(_enriched):
            if enriched is not None:
                l4_candidates[i] = enriched

    else:
        # Sequential mode
        for i, sample in enumerate(l4_candidates, 1):
            try:
                print(f"\n[{i}/{len(l4_candidates)}] Scanning {sample.name}...", end=" ", flush=True)

                # Check cache before analysis
                if _cache is not None:
                    cached = _cache.get(sample.sha256, backend_name, src.__version__)
                    if cached:
                        sample.risk_score = cached["risk_score"]
                        sample.analysis_findings = []  # Not cached
                        print(f"CACHED {sample.risk_score:.1f}/10")
                        completed += 1
                        if sample.risk_score >= min_score:
                            high_risk.append(sample)
                        continue

                if timeout_per_driver > 0:
                    enriched = _run_with_timeout(sample, backend_name, timeout_per_driver, score_engine_name)
                else:
                    enriched = _run_pipeline_internal(sample, backend_name, print_layer=False, score_engine_name=score_engine_name)

                # Update the list element so the Report contains enriched data
                l4_candidates[i - 1] = enriched

                # Store in cache
                if _cache is not None:
                    _cache.put(enriched.sha256, backend_name, src.__version__, {
                        "risk_score": enriched.risk_score,
                        "finding_count": len(enriched.analysis_findings),
                    })

                completed += 1

                if enriched.risk_score >= min_score:
                    high_risk.append(enriched)

                level = score_level(enriched.risk_score)
                if enriched.risk_score >= min_score:
                    print(f"{enriched.risk_score:.1f}/10 ({level}), {len(enriched.analysis_findings)} findings")
                else:
                    print(f"{enriched.risk_score:.1f}/10 ({level}) — skipped (below threshold)")

            except TimeoutError:
                print("TIMEOUT")
                timed_out += 1
                failed += 1
            except Exception as e:
                print(f"ERROR: {e}")
                failed += 1

    elapsed = time.time() - start

    # Generate report
    report = Report(
        samples=l4_candidates,
        timestamp=datetime.now().isoformat(),
        tool_version=src.__version__,
        backend=backend_name,
        total_analyzed=completed,
        total_findings=sum(len(s.analysis_findings) for s in l4_candidates),
        summary={
            "total_time": round(elapsed, 1),
            "avg_risk_score": round(
                sum(s.risk_score for s in l4_candidates) / len(l4_candidates), 2
            )
            if l4_candidates
            else 0.0,
            "critical_count": sum(
                1 for s in l4_candidates if s.risk_score >= 9.0
            ),
            "high_count": sum(
                1 for s in l4_candidates if 7.0 <= s.risk_score < 9.0
            ),
            "completed": completed,
            "failed": failed,
            "timed_out": timed_out,
            "high_risk_count": len(high_risk),
            "funnel": funnel_stats,
        },
    )

    return report


def _run_with_timeout(sample: Sample, backend_name: str, timeout: int, score_engine_name: str = "default") -> Sample:
    """Run Layers 2-4 on a sample with a hard timeout (Windows-compatible).

    Pass only the file path to the child process (Path is safely picklable)
    and re-ingest inside the subprocess.  This avoids serializing the full
    Sample dataclass, which can fail under spawn-mode multiprocessing.
    """
    with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run_pipeline_internal, sample.path, backend_name, False, timeout, score_engine_name)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            executor.shutdown(wait=False, cancel_futures=True)
            raise TimeoutError(f"timed out after {timeout}s")


def _run_pipeline_internal(sample: Sample | Path, backend_name: str, print_layer: bool = True, timeout_per_driver: int = 30, score_engine_name: str = "default") -> Sample:
    """Run Layers 2-4 on an already-ingested sample (or a Path to re-ingest).

    Accepts a Path when called from _run_with_timeout (spawn-mode
    subprocess), re-ingesting the file before analysis.

    For user-mode samples, disassembly is skipped (they don't benefit from
    kernel-focused IOCTL/IRP pattern detection). Analysis runs via
    UserModeAnalyzer which operates on PE metadata and imports.

    Returns the enriched Sample (required for subprocess isolation).
    """
    # Re-ingest if called from subprocess (received a Path)
    if isinstance(sample, Path):
        from src.ingestion.pe_parser import ingest_any_pe
        sample = ingest_any_pe(sample)

    # Layer 2: Disassembly (skip for user-mode)
    if sample.is_usermode:
        # User-mode: skip kernel-focused disassembly, run analysis directly
        if print_layer:
            print(f"\n[pipeline] Layer 2 — Skipping disassembly for user-mode {sample.name}")
        ir = None  # UserModeAnalyzer doesn't need IR
    else:
        if print_layer:
            print(f"\n[pipeline] Layer 2 — Disassembly ({backend_name})")
        if backend_name == "capstone":
            backend = CapstoneBackend()
        elif backend_name == "ghidra":
            backend = GhidraBackend()
        else:
            raise ValueError(f"Unknown backend: {backend_name}")

        if not backend.is_available():
            raise RuntimeError(f"Backend {backend_name} is not available")

        # Capstone supports quick mode + timeout; Ghidra always does full analysis
        if backend_name == "capstone":
            ir = backend.analyze(sample.path, quick=True, timeout=timeout_per_driver if timeout_per_driver > 0 else 30)
        else:
            ir = backend.analyze(sample.path)
        sample.disassembly_result = ir
        if print_layer:
            print(f"  Functions: {len(ir.functions)}")
            print(f"  IOCTL codes: {len(ir.ioctl_codes)}")
            print(f"  IRP handlers: {len(ir.irp_handlers)}")
            print(f"  Strings: {len(ir.strings)}")

    # Layer 3: Analysis
    if print_layer:
        print(f"\n[pipeline] Layer 3 — Analysis")
    findings = run_all_analyzers(sample, ir)
    sample.analysis_findings = findings

    # Layer 4: Scoring
    if score_engine_name == "exploitability":
        from src.scoring.exploitability_scorer import ExploitabilityScoringEngine
        engine = ExploitabilityScoringEngine()
    else:
        engine = DefaultScoringEngine()
    score = engine.score(sample, findings)
    sample.risk_score = score.overall
    if print_layer:
        print(f"  Risk score: {score.overall}/10 ({score.level})")
        explanation = engine.explain(sample, findings)
        for line in explanation[:5]:
            print(f"  > {line}")
        if len(explanation) > 5:
            print(f"  ... and {len(explanation) - 5} more")

    return sample
