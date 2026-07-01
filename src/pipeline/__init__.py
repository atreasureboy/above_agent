"""DEVOPS_driver — Pipeline Orchestrator.

Bridges DriverScope (batch scanning) and OVOIDA (deep reverse engineering)
into a single automated pipeline:

  Phase 1: DriverScope scans target directory → finds high-risk drivers
  Phase 2: OVOIDA performs deep reverse engineering on each high-risk driver
  Phase 3: Unified report merging DriverScope findings + OVOIDA results
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from src.config import PipelineConfig


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """DriverScope Phase 1 scan results."""
    samples_scanned: int = 0
    high_risk_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    avg_score: float = 0.0
    elapsed: float = 0.0
    top_samples: list[dict[str, Any]] = field(default_factory=list)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    deep_completed: int = 0
    deep_failed: int = 0
    deep_elapsed: float = 0.0
    correlation_findings: list[dict[str, Any]] = field(default_factory=list)
    # Original Sample objects for Phase 2 OvoidaEngine fallback
    _samples: list[Sample] = field(default_factory=list, repr=False)


@dataclass
class DeepResult:
    """OVOIDA Phase 2 deep reverse results for one target."""
    sample_name: str
    risk_score: float = 0.0
    driver_scope_findings: list[str] = field(default_factory=list)
    ovoida_session_dir: Path | None = None
    ovoida_completed: bool = False
    ovoida_error: str = ""
    elapsed: float = 0.0


@dataclass
class PipelineResult:
    """Complete pipeline result combining both phases."""
    target: str = ""
    timestamp: str = ""
    total_time: float = 0.0
    phase1_scan: ScanResult | None = None
    phase2_deep: list[DeepResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Phase 1: DriverScope Batch Scan (direct import)
# ---------------------------------------------------------------------------

def run_phase1_scan(config: PipelineConfig) -> ScanResult:
    """Run DriverScope batch analysis on the target directory.

    Now that all modules share the same src/ namespace, we import
    run_batch directly — no subprocess or sys.path manipulation needed.
    """
    print(f"\n{'=' * 60}")
    print(f"  Phase 1: DriverScope Batch Scan")
    print(f"  Target: {config.target}")
    print(f"  Risk threshold for deep analysis: {config.risk_threshold}")
    print(f"{'=' * 60}")

    start = time.time()

    from src.analysis.pipeline import run_batch

    report = run_batch(
        target=config.target,
        backend_name=config.ds_backend,
        limit=0,
        min_score=0,
        timeout_per_driver=config.ds_timeout,
        use_funnel=config.ds_use_funnel,
        workers=config.ds_workers,
        use_cache=config.ds_use_cache,
        score_engine_name=config.ds_score_engine,
        include_usermode=config.ds_include_usermode,
    )

    elapsed = time.time() - start

    # --- Phase 1.2: Multi-Driver Correlation (cross-sample analysis) ---
    correlation_findings: list[dict[str, Any]] = []
    if len(report.samples) >= 2:
        try:
            from src.analysis.core.multi_driver_correlator import MultiDriverCorrelator
            from src.analysis.core.protocol_analyzer import ProtocolAnalyzer

            correlator = MultiDriverCorrelator()
            proto_analyzer = ProtocolAnalyzer()

            corr_findings = correlator.analyze_cluster(report.samples)
            proto_findings = proto_analyzer.analyze(report.samples)
            all_corr = corr_findings + proto_findings

            # Attach correlation findings to relevant samples
            for f in all_corr:
                drivers = f.context.get("drivers", [])
                for s in report.samples:
                    if s.name in drivers:
                        s.analysis_findings.append(f)

            correlation_findings = [f.to_dict() for f in all_corr]
            if all_corr:
                print(f"\n[phase1.2] Cross-driver correlation: {len(all_corr)} findings")
                for cf in all_corr:
                    print(f"  [{cf.severity.value}] {cf.description[:100]}")
        except Exception as e:
            print(f"\n[phase1.2] Correlation failed: {e}")

    # Collect all samples sorted by risk
    all_samples = sorted(
        [s for s in report.samples if s.risk_score > 0],
        key=lambda s: s.risk_score,
        reverse=True,
    )

    top_samples = []
    for s in all_samples:
        # Extract function details with API calls from disassembly
        func_details = []
        if s.disassembly_result:
            for addr, func in list(s.disassembly_result.functions.items())[:100]:
                api_names = s.disassembly_result.function_apis.get(addr, [])
                api_details = s.disassembly_result.function_api_details.get(addr, [])
                calls = func.calls[:10] if hasattr(func, 'calls') else []
                called_by = func.called_by[:5] if hasattr(func, 'called_by') else []
                func_details.append({
                    "address": hex(addr),
                    "name": func.name,
                    "size": func.size,
                    "api_calls": api_names,
                    "api_details": [
                        {"name": ad.name, "call_addr": hex(ad.call_address), "params": ad.params_hint}
                        for ad in api_details[:5]
                    ],
                    "calls": [hex(c) for c in calls],
                    "called_by": [hex(c) for c in called_by],
                })

        # Extract full handler mappings
        ioctl_handlers = {}
        irp_handlers = {}
        if s.disassembly_result:
            for code, addr in s.disassembly_result.ioctl_handlers.items():
                ioctl_handlers[hex(code)] = f"sub_{addr:X}"
            for major, addr in s.disassembly_result.irp_handlers.items():
                irp_handlers[hex(major)] = f"sub_{addr:X}"

        top_samples.append({
            "name": s.name,
            "company": s.company,
            "driver_type": s.driver_type,
            "arch": s.arch.value,
            "sha256": s.sha256,
            "risk_score": s.risk_score,
            "risk_level": _score_level(s.risk_score),
            "finding_count": len(s.analysis_findings),
            "findings": [f.to_dict() for f in s.analysis_findings],
            "path": str(s.path),
            "imports": s.imports[:50],  # Top imports for context
            "exports": s.exports[:20],  # Exported function names
            "strings": s.disassembly_result.strings[:50] if s.disassembly_result else [],
            "entry_point": hex(s.entry_point) if s.entry_point else "0x0",
            "compile_timestamp": s.compile_timestamp,
            "debug_path": s.debug_path,  # PDB path
            "sections": s.sections[:15],
            "functions": func_details,
            "ioctl_handlers": ioctl_handlers,
            "irp_handlers": irp_handlers,
            "disassembly_backend": s.disassembly_result.backend if s.disassembly_result else "none",
        })

        # Extract device names from disassembly result
        if s.disassembly_result:
            from src.analysis.core.structure_analyzer import extract_device_names
            top_samples[-1]["device_names"] = extract_device_names(s.disassembly_result)
        else:
            top_samples[-1]["device_names"] = []

    critical = sum(1 for s in all_samples if s.risk_score >= 9.0)
    high = sum(1 for s in all_samples if 7.0 <= s.risk_score < 9.0)
    avg = round(sum(s.risk_score for s in all_samples) / len(all_samples), 1) if all_samples else 0.0

    # Filter high-risk candidates for Phase 2
    high_risk = [s for s in all_samples if s.risk_score >= config.risk_threshold]
    if config.max_deep_targets > 0:
        high_risk = high_risk[:config.max_deep_targets]

    # Track deep analysis stats (default: none run)
    deep_completed = 0
    deep_failed = 0
    deep_elapsed = 0.0

    print(f"\n[phase1] Scan complete in {elapsed:.1f}s")
    print(f"  Scanned: {report.total_analyzed}")
    print(f"  Critical: {critical}, High: {high}")
    print(f"  Avg score: {avg}")
    print(f"  High-risk candidates for Phase 2: {len(high_risk)}")

    # --- Phase 1.5: Ghidra Deep Analysis on high-risk candidates ---
    if config.ghidra_deep and high_risk:
        from src.analysis.deep import run_deep_analysis
        from src.disassembly.ghidra_backend import GhidraBackend

        ghidra = GhidraBackend()
        if ghidra.is_available():
            deep_targets = high_risk[:config.ghidra_deep_max] if config.ghidra_deep_max > 0 else high_risk
            print(f"\n{'=' * 60}")
            print(f"  Phase 1.5: Ghidra Deep Analysis")
            print(f"  Candidates: {len(deep_targets)}")
            print(f"{'=' * 60}")

            deep_start = time.time()
            deep_completed = 0
            deep_failed = 0

            for i, sample in enumerate(deep_targets, 1):
                sample_path = Path(sample_info["path"]) if (sample_info := next(
                    (s for s in all_samples if s.sha256 == sample.sha256), None
                )) else None
                if sample_path is None or not sample_path.exists():
                    print(f"  [{i}/{len(deep_targets)}] SKIP: {sample.name} (file not found)")
                    deep_failed += 1
                    continue

                try:
                    deep_result = run_deep_analysis(
                        sample_path,
                        timeout=config.ghidra_deep_timeout,
                        verbose=True,
                    )
                    deep_completed += 1

                    # Replace the sample's disassembly and findings with Ghidra results
                    sample.disassembly_result = deep_result["ir"]
                    sample.analysis_findings = deep_result["findings"]
                    sample.risk_score = deep_result["risk_score"]

                    # Update the corresponding top_samples entry
                    for ts in top_samples:
                        if ts["sha256"] == sample.sha256:
                            ts["risk_score"] = deep_result["risk_score"]
                            ts["risk_level"] = _score_level(deep_result["risk_score"])
                            ts["finding_count"] = len(deep_result["findings"])
                            ts["findings"] = [f.to_dict() for f in deep_result["findings"]]
                            ts["disassembly_backend"] = "ghidra"
                            break

                    level = _score_level(deep_result["risk_score"])
                    print(f"  [{i}/{len(deep_targets)}] {sample.name}: {deep_result['risk_score']:.1f}/10 ({level}), {len(deep_result['findings'])} findings")

                except Exception as e:
                    print(f"  [{i}/{len(deep_targets)}] {sample.name}: ERROR: {e}")
                    deep_failed += 1

            deep_elapsed = time.time() - deep_start
            print(f"\n[phase1.5] Ghidra deep analysis complete in {deep_elapsed:.1f}s")
            print(f"  Completed: {deep_completed}, Failed: {deep_failed}")

            # Re-sort samples by updated risk score
            all_samples.sort(key=lambda s: s.risk_score, reverse=True)
            top_samples.sort(key=lambda s: s["risk_score"], reverse=True)

            # Re-filter high-risk candidates for Phase 2
            high_risk = [s for s in all_samples if s.risk_score >= config.risk_threshold]
            if config.max_deep_targets > 0:
                high_risk = high_risk[:config.max_deep_targets]
            print(f"  Updated high-risk candidates for Phase 2: {len(high_risk)}")
        else:
            print(f"\n[phase1.5] WARNING: Ghidra not available, skipping deep analysis")

    return ScanResult(
        samples_scanned=report.total_analyzed,
        high_risk_count=len(high_risk),
        critical_count=critical,
        high_count=high,
        avg_score=avg,
        elapsed=elapsed,
        top_samples=top_samples,
        all_findings=[f.to_dict() for s in report.samples for f in s.analysis_findings],
        correlation_findings=correlation_findings,
        deep_completed=deep_completed,
        deep_failed=deep_failed,
        deep_elapsed=deep_elapsed,
        _samples=list(all_samples),
    )


# ---------------------------------------------------------------------------
# Phase 2: OVOIDA Deep Reverse Engineering (subprocess, TypeScript)
# ---------------------------------------------------------------------------

def run_phase2_deep(config: PipelineConfig, scan_result: ScanResult) -> list[DeepResult]:
    """Run OVOIDA deep reverse engineering on high-risk candidates.

    For each high-risk driver from Phase 1, invokes OVOIDA via subprocess
    to perform deep static/dynamic analysis.
    """
    print(f"\n{'=' * 60}")
    print(f"  Phase 2: OVOIDA Deep Reverse Engineering")
    print(f"  Candidates: {scan_result.high_risk_count}")
    print(f"  Output mode: {config.ov_output_mode}")
    print(f"{'=' * 60}")

    # OVOIDA root directory — allow config override for multi-repo setups
    if config.ovoida_root:
        ov_root = Path(config.ovoida_root)
    else:
        ov_root = Path(__file__).resolve().parent.parent.parent / "components" / "ovoida"
    node_ovoida_available = (ov_root / "package.json").exists()
    if not node_ovoida_available:
        print(f"[phase2] WARNING: OVOIDA Node.js agent not found at {ov_root}")
        print(f"[phase2] Falling back to Python OvoidaEngine for deep analysis.")

    # Check if OVOIDA is built (only if Node.js version is available)
    if node_ovoida_available:
        dist = ov_root / "dist"
        if not dist.exists():
            print(f"[phase2] OVOIDA not built. Building now...")
            _build_ovoida(ov_root)

    results: list[DeepResult] = []

    for i, sample_info in enumerate(scan_result.top_samples):
        if sample_info["risk_score"] < config.risk_threshold:
            break
        if config.max_deep_targets > 0 and i >= config.max_deep_targets:
            break

        sample_name = sample_info["name"]
        sample_path = sample_info.get("path", "")
        if not sample_path or not Path(sample_path).exists():
            print(f"\n[{i + 1}/{scan_result.high_risk_count}] SKIP: {sample_name} (file not found)")
            continue

        # Find the original Sample object for Python OvoidaEngine fallback
        sample_obj = None
        for s in scan_result._samples:
            if s.sha256 == sample_info.get("sha256", ""):
                sample_obj = s
                break

        print(f"\n[{i + 1}/{scan_result.high_risk_count}] Deep analysis: {sample_name}")
        print(f"  Risk: {sample_info['risk_score']}/10 ({sample_info['risk_level']})")
        print(f"  Findings: {sample_info['finding_count']}")

        deep = _run_ovoida_on_sample(
            ov_root=ov_root,
            sample_path=Path(sample_path),
            sample_name=sample_name,
            sample_info=sample_info,
            sample=sample_obj,
            config=config,
        )
        results.append(deep)

    completed = sum(1 for r in results if r.ovoida_completed)
    print(f"\n[phase2] Phase 2 complete: {completed}/{len(results)} succeeded")

    return results


def _build_ovoida(ov_root: Path) -> bool:
    """Build OVOIDA TypeScript project."""
    try:
        result = subprocess.run(
            ["npm", "run", "build"],
            cwd=ov_root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print(f"[phase2] OVOIDA build successful")
            return True
        else:
            print(f"[phase2] OVOIDA build failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"[phase2] OVOIDA build error: {e}")
        return False


def _run_ovoida_on_sample(
    ov_root: Path,
    sample_path: Path,
    sample_name: str,
    sample_info: dict[str, Any],
    config: PipelineConfig,
    sample: Sample | None = None,
) -> DeepResult:
    """Run OVOIDA on a single sample via subprocess.

    Falls back to Python OvoidaEngine when Node.js agent is unavailable.
    """
    start = time.time()
    session_dir = config.ov_session_dir(sample_name)
    session_dir.mkdir(parents=True, exist_ok=True)

    # Write structured context file for OVOIDA
    context_path = _write_ovoida_context(session_dir, sample_info, sample_path)

    # Auto-generate executable PoC files when exploit chains are detected
    _auto_generate_pocs(session_dir, sample_info, sample_path)

    # Build the OVOIDA task prompt — Agent as "Commander + Analyst"
    # DriverScope (Python) has already done the deterministic analysis:
    #   IR/CFG construction, pattern matching, taint tracking, exploit chain building.
    # The Agent's role is now: analysis validation, PoC generation, confidence assessment.
    findings_summary = _format_findings_for_ovoida(sample_info)

    # Detect if Ghidra-level data is available
    disasm_backend = sample_info.get("disassembly_backend", "capstone")
    ghidra_note = (
        "\n\n## 反汇编数据源: Ghidra\n"
        "本次分析的 IR/CFG/污点数据来自 Ghidra 全量反汇编，精度高。"
        if disasm_backend == "ghidra" else
        "\n\n## 反汇编数据源: Capstone（快速模式）\n"
        "本次分析使用 Capstone 轻量级反汇编，覆盖模式匹配和基础污点。"
    )

    # Device names for PoC generation
    device_names = sample_info.get("device_names", [])
    device_hint = ""
    if device_names:
        device_list = ", ".join(device_names)
        device_hint = f"\n\n## 目标设备名称\n已从二进制中提取: {device_list}\nPoC 中使用这些设备名。"

    # Chain count for context
    chain_count = len([f for f in sample_info.get("findings", []) if f.get("category") == "attack_chain"])

    task = (
        f"你是 BYOVD 深度逆向专家。DriverScope 已完成确定性分析（IR/CFG/污点/利用链构建）。\n"
        f"\n"
        f"## 目标驱动\n"
        f"- Sample path: {sample_path}\n"
        f"- Risk score: {sample_info['risk_score']}/10 ({sample_info['risk_level']})\n"
        f"- Driver type: {sample_info['driver_type']}, Architecture: {sample_info['arch']}\n"
        f"- SHA256: {sample_info.get('sha256', 'unknown')}\n"
        f"- Device names: {device_hint if device_names else '未提取到设备名，使用 driver_type 推断'}\n"
        f"{ghidra_note}\n"
        f"\n"
        f"## 你的角色\n"
        f"DriverScope（Python 引擎）已完成以下确定性工作：\n"
        f"- 所有 IOCTL code 和 handler 地址映射\n"
        f"- 所有危险 API 调用（精确到指令地址）\n"
        f"- 污点分析（taint source → sink 路径确认）\n"
        f"- 利用链构建（{chain_count} 条完整链）\n"
        f"- 设备名称提取\n"
        f"\n"
        f"你不需重新做这些工作。你的任务是：\n"
        f"\n"
        f"### 任务 1：综合研判\n"
        f"审阅 {context_path} 中的 findings，对每条利用链确认：\n"
        f"a. 用户态触发路径（哪个 IOCTL code？哪个 transfer method？）\n"
        f"b. 输入验证是否充分（cmp 检查大小？ExGetPreviousMode？ProbeForRead/Write？）\n"
        f"c. 危险 API 参数是否来自用户可控输入（污点确认？）\n"
        f"d. 给出置信度：High（完整污点确认）/ Medium（部分可控）/ Low（仅 API 暴露）\n"
        f"\n"
        f"### 任务 2：PoC 生成\n"
        f"为每个置信度 >= Medium 的利用链生成 Python ctypes PoC：\n"
        f"- CreateFileW 打开设备\n"
        f"- DeviceIoControl 调用序列\n"
        f"- 输入缓冲区构造（基于 taint source 的偏移和大小）\n"
        f"- 预期的内核行为\n"
        f"写入 poc.py 到 session 目录。\n"
        f"\n"
        f"### 任务 3：输出\n"
        f"- findings.json: 结构化发现（必须），包含每条链的置信度评估\n"
        f"- findings.md: 分析结论和利用链说明（人类可读）\n"
        f"- poc.py: PoC 代码（如果有确认的利用链）\n"
        f"- triage.txt: 快速摘要\n"
        f"\n"
        f"## 快速概览\n"
        f"{findings_summary}"
    )

    # Build OVOIDA command
    cmd = ["node", str(ov_root / "dist" / "bin" / "ovogogogo.js"), task]

    # Pass env vars including API credentials
    env = os.environ.copy()
    env["OVOGO_CWD"] = str(session_dir)
    if config.ov_model:
        env["OVOGO_MODEL"] = config.ov_model
    if config.ov_api_url:
        env["OPENAI_BASE_URL"] = config.ov_api_url
    if config.ov_api_key:
        env["OPENAI_API_KEY"] = config.ov_api_key
    env["OVOGO_MAX_ITER"] = str(config.ov_max_iter)

    print(f"  Session dir: {session_dir}")
    print(f"  Command: {' '.join(cmd[:4])}...")

    deep = DeepResult(
        sample_name=sample_name,
        risk_score=sample_info["risk_score"],
        driver_scope_findings=sample_info.get("findings", []),
        ovoida_session_dir=session_dir,
    )

    node_available = True
    try:
        timeout = config.ov_timeout if config.ov_timeout > 0 else None
        result = subprocess.run(
            cmd,
            cwd=str(session_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        deep.ovoida_completed = result.returncode == 0
        if result.returncode != 0:
            deep.ovoida_error = result.stderr[-500:] if result.stderr else "unknown error"

        # Write command log to session dir
        log = session_dir / "devops_command.log"
        log.write_text(f"Task: {task}\n\n--- stdout ---\n{result.stdout}\n\n--- stderr ---\n{result.stderr}\n")

    except subprocess.TimeoutExpired:
        deep.ovoida_error = f"timeout after {config.ov_timeout}s"
        print(f"  TIMEOUT — falling back to Python OvoidaEngine")
        node_available = False
    except FileNotFoundError:
        deep.ovoida_error = "node/npm not found, falling back to Python OvoidaEngine"
        print(f"  Node.js not available — falling back to Python OvoidaEngine")
        node_available = False
    except Exception as e:
        deep.ovoida_error = str(e)
        print(f"  ERROR: {e}")
        node_available = False

    # Fallback: Python OvoidaEngine when Node.js agent is unavailable
    if not deep.ovoida_completed and sample is not None and sample.disassembly_result is not None:
        print(f"  Running Python OvoidaEngine fallback...")
        deep = _run_python_ovoida(sample, sample_info, session_dir, deep)

    deep.elapsed = time.time() - start
    if deep.ovoida_completed:
        print(f"  Completed in {deep.elapsed:.1f}s")
    else:
        print(f"  Failed: {deep.ovoida_error[:100]}")

    return deep


def _run_python_ovoida(
    sample: Sample,
    sample_info: dict[str, Any],
    session_dir: Path,
    deep: DeepResult,
) -> DeepResult:
    """Run Python OvoidaEngine as fallback when Node.js agent is unavailable.

    Uses the existing Sample and its DisassemblyResult to perform
    deep analysis: critical function identification, taint tracking,
    and exploit chain construction.
    """
    try:
        from src.analysis.deep.ovoida_engine import OvoidaEngine

        engine = OvoidaEngine(backend=sample_info.get("disassembly_backend", "capstone"))
        phase1_findings = sample.analysis_findings or []

        result = engine.analyze(
            sample=sample,
            ir=sample.disassembly_result,
            phase1_findings=phase1_findings,
            output_dir=session_dir,
        )

        deep.ovoida_completed = True
        deep.ovoida_error = ""

        # Write findings.json from OvoidaResult
        findings_data = {
            "sample_name": result.sample_name,
            "risk_score": result.risk_score,
            "functions_analyzed": result.functions_analyzed,
            "exploit_chains": result.exploit_chains,
            "functions_detail": result.functions_detail,
            "engine": "python_ovoida",
            "confidence": "confirmed" if any(
                c.get("user_controllable") for c in result.exploit_chains
            ) else "speculated",
        }
        findings_path = session_dir / "findings_python.json"
        findings_path.write_text(
            json.dumps(findings_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Write findings.md
        md_lines = [
            f"# DriverScope Python OVOIDA Analysis: {result.sample_name}",
            "",
            f"**Risk Score:** {result.risk_score:.1f}/10",
            f"**Functions Analyzed:** {result.functions_analyzed}",
            f"**Exploit Chains:** {len(result.exploit_chains)}",
            "",
        ]
        for i, chain in enumerate(result.exploit_chains, 1):
            md_lines.extend([
                f"## Chain {i}: {chain.get('name', 'unknown')}",
                f"- Severity: {chain['severity']}",
                f"- Function: {chain['function']}",
                f"- APIs: {', '.join(chain['dangerous_apis'])}",
                f"- Validation: {chain['validation']}",
                f"- User Controllable: {chain['user_controllable']}",
                f"- Transfer Method: {chain.get('transfer_method', 'N/A')}",
                "",
            ])
            if chain.get("poc_steps"):
                md_lines.append("### PoC Steps")
                md_lines.append("")
                for step in chain["poc_steps"]:
                    md_lines.append(f"- {step}")
                md_lines.append("")

        (session_dir / "findings_python.md").write_text(
            "\n".join(md_lines), encoding="utf-8"
        )

        # Auto-generate PoC from exploit chains
        if result.exploit_chains:
            try:
                from src.report.poc_generator import generate_poc_from_chain

                device_names = sample_info.get("device_names", [])
                device_name = (
                    device_names[0].replace("\\\\.\\", "")
                    if device_names
                    else sample_info.get("driver_type", "TargetDriver")
                )

                for chain in result.exploit_chains[:2]:
                    generate_poc_from_chain(
                        chain, device_name=device_name,
                        format="python",
                        output_path=session_dir / "poc_python.py",
                    )
                    break  # Just generate one PoC for now
            except Exception as e:
                print(f"  Python PoC generation failed: {e}")

        print(f"  Python OvoidaEngine: {result.functions_analyzed} functions, "
              f"{len(result.exploit_chains)} chains in {result.elapsed:.1f}s")

    except Exception as e:
        deep.ovoida_error = f"Python OvoidaEngine fallback failed: {e}"
        print(f"  Python OvoidaEngine error: {e}")

    return deep


def _auto_generate_pocs(
    session_dir: Path,
    sample_info: dict[str, Any],
    sample_path: Path,
) -> list[Path]:
    """Auto-generate executable PoC files when exploit chains are detected.

    Uses API-specific payload templates from poc_generator.py via
    generate_poc_from_chain for targeted buffer construction.
    Generates both Python (.py) and C (.c) formats.
    """
    generated = []

    # Extract exploit chains from attack_chain findings
    chains = []
    for f in sample_info.get("findings", []):
        if f.get("category") == "attack_chain":
            ctx = f.get("context", {})
            apis = ctx.get("primitive_apis", [])
            ioctl_hex_list = ctx.get("ioctl_codes", [])
            ioctl_code = 0x22A004
            if ioctl_hex_list:
                try:
                    ioctl_code = int(ioctl_hex_list[0], 16)
                except (ValueError, TypeError):
                    pass

            # Extract transfer method from findings
            transfer_method = 0  # METHOD_BUFFERED default
            transfer_methods = sample_info.get("transfer_methods", {})
            for code_str, method in transfer_methods.items():
                try:
                    if int(code_str, 16) == ioctl_code:
                        transfer_method = method
                        break
                except (ValueError, TypeError):
                    pass

            # Safely convert function_address to int (may be str from JSON)
            func_addr = f.get("function_address", 0)
            if isinstance(func_addr, str):
                try:
                    func_addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
                except (ValueError, AttributeError):
                    func_addr = 0

            chain = {
                "name": f"BYOVD chain: {', '.join(apis[:3])}" if apis else f"Attack chain in sub_{func_addr:X}",
                "severity": f.get("severity", "HIGH"),
                "function": hex(func_addr),
                "dangerous_apis": apis,
                "validation": ctx.get("missing_checks", "unknown"),
                "taint_sources": ctx.get("taint_sources", []),
                "taint_sinks": apis,
                "buffer_size": 0x1000,
                "ioctl_code": ioctl_code,
                "method": transfer_method,
            }
            chains.append(chain)

    if not chains:
        return generated

    # Determine device name
    device_names = sample_info.get("device_names", [])
    device_name = device_names[0].replace("\\\\.\\", "") if device_names else sample_info.get("driver_type", "TargetDriver")

    try:
        from src.report.poc_generator import generate_poc_from_chain

        # Generate targeted PoC for each chain (top chain gets poc.py/poc.c)
        for i, chain in enumerate(chains[:3]):
            suffix = f"_{i+1}" if i > 0 else ""
            poc_py_path = session_dir / f"poc{suffix}.py"
            generate_poc_from_chain(chain, device_name=device_name, format="python", output_path=poc_py_path)
            generated.append(poc_py_path)

            poc_c_path = session_dir / f"poc{suffix}.c"
            generate_poc_from_chain(chain, device_name=device_name, format="c", output_path=poc_c_path)
            generated.append(poc_c_path)

    except Exception as e:
        print(f"  PoC generation failed: {e}")

    return generated


def _write_ovoida_context(
    session_dir: Path,
    sample_info: dict[str, Any],
    sample_path: Path,
) -> Path:
    """Write a structured JSON context file for OVOIDA to consume.

    Contains complete Phase 1 findings — no truncation. OVOIDA reads
    this file first to understand what DriverScope already found.
    """
    context = {
        "sample": {
            "name": sample_info.get("name", ""),
            "path": str(sample_path),
            "sha256": sample_info.get("sha256", ""),
            "arch": sample_info.get("arch", ""),
            "driver_type": sample_info.get("driver_type", ""),
            "company": sample_info.get("company", ""),
            "entry_point": sample_info.get("entry_point", "0x0"),
            "compile_timestamp": sample_info.get("compile_timestamp", 0),
            "debug_path": sample_info.get("debug_path", ""),  # PDB path
            "sections": sample_info.get("sections", []),
        },
        "risk_score": sample_info.get("risk_score", 0.0),
        "risk_level": sample_info.get("risk_level", "NONE"),
        "finding_count": sample_info.get("finding_count", 0),
        "findings": sample_info.get("findings", []),  # Complete, not truncated
        "functions": sample_info.get("functions", []),  # Full function list with API calls
        "ioctl_handlers": sample_info.get("ioctl_handlers", {}),
        "irp_handlers": sample_info.get("irp_handlers", {}),
        "dangerous_apis": [],
        "priority_functions": [],  # Functions to focus on, sorted by risk
        "imports": sample_info.get("imports", []),  # IAT imports for context
        "exports": sample_info.get("exports", []),  # Exported names
        "strings_top50": sample_info.get("strings", []),  # Interesting strings
        "disassembly_backend": sample_info.get("disassembly_backend", "capstone"),  # capstone or ghidra
        "device_names": sample_info.get("device_names", []),  # Kernel device names
        "transfer_methods": {},  # IOCTL code → METHOD_* mapping
    }

    # Extract handler mapping and dangerous API details from findings
    for f in sample_info.get("findings", []):
        cat = f.get("category", "")
        if cat == "ioctl_code_exposed":
            ctx = f.get("context", {})
            if "ioctl_handlers" in ctx:
                context["ioctl_handlers"] = ctx["ioctl_handlers"]
            if "transfer_methods" in ctx:
                context["transfer_methods"] = ctx["transfer_methods"]
        elif cat in (
            "arbitrary_memory_map", "msr_access", "physical_memory_access",
            "kernel_rw_primitive", "code_execution_primitive",
            "process_manipulation", "missing_privilege_check",
            "unvalidated_user_input", "missing_size_check",
            "partial_validation", "attack_chain",
        ):
            api = f.get("api_name", "")
            if api and api not in context["dangerous_apis"]:
                context["dangerous_apis"].append(api)

            # Extract function address as priority
            func_addr = f.get("function_address", 0)
            instr_addr = f.get("instruction_address", 0)
            # Addresses may be int or hex string from JSON serialization
            if isinstance(func_addr, str):
                try:
                    func_addr = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr)
                except (ValueError, AttributeError):
                    func_addr = 0
            if isinstance(instr_addr, str):
                try:
                    instr_addr = int(instr_addr, 16) if instr_addr.startswith("0x") else int(instr_addr)
                except (ValueError, AttributeError):
                    instr_addr = 0
            if func_addr and func_addr not in [p.get("address") for p in context["priority_functions"]]:
                context["priority_functions"].append({
                    "address": hex(func_addr),
                    "name": f"sub_{func_addr:X}",
                    "api": api,
                    "instruction_address": hex(instr_addr) if instr_addr else None,
                    "severity": f.get("severity", "info"),
                    "description": f.get("description", "")[:200],
                })

    out_path = session_dir / "ovoida_context.json"
    out_path.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def _build_handler_context(sample_info: dict[str, Any]) -> str:
    """Build a concise handler address summary for the prompt."""
    parts = []
    for f in sample_info.get("findings", []):
        cat = f.get("category", "")
        if cat == "attack_chain":
            ctx = f.get("context", {})
            apis = ctx.get("primitive_apis", [])
            ioctls = ctx.get("ioctl_codes", [])
            func = f.get("function_address", "0")
            if apis:
                parts.append(
                    f"- CRITICAL: Function {func} forms complete attack chain "
                    f"via {', '.join(apis)}"
                )
                if ioctls:
                    parts.append(f"  Exposed IOCTLs: {', '.join(ioctls[:5])}")
        elif cat == "ioctl_code_exposed" and f.get("context", {}).get("ioctl_handlers"):
            handlers = f["context"]["ioctl_handlers"]
            for code, addr in sorted(handlers.items(), key=lambda x: x[0])[:5]:
                parts.append(f"- IOCTL {code} → handler at {addr}")

    if parts:
        return "## Priority Handlers & Chains\n" + "\n".join(parts)
    return "## Priority Handlers\nNo specific handler context available."


def _build_priority_function_list(sample_info: dict[str, Any]) -> str:
    """Build a prioritized list of functions for OVOIDA to focus on."""
    priority = []
    for f in sample_info.get("findings", []):
        sev = f.get("severity", "")
        if sev not in ("critical", "high"):
            continue
        func_addr = f.get("function_address", 0)
        api = f.get("api_name", "")
        desc = f.get("description", "")[:150]
        if func_addr and api:
            priority.append(f"  - sub_{func_addr:X}: {api} — {desc}")

    if priority:
        return "## 重点关注函数\n" + "\n".join(priority[:10])
    return "## 重点关注函数\n无特定高优先级函数。"


def _format_findings_for_ovoida(sample_info: dict[str, Any]) -> str:
    """Format DriverScope findings into a concise summary for OVOIDA."""
    findings = sample_info.get("findings", [])
    if not findings:
        return "无具体发现"

    # Group by severity
    by_severity: dict[str, list] = {}
    for f in findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, []).append(f)

    parts = []
    for sev in ("critical", "high", "medium"):
        items = by_severity.get(sev, [])
        if items:
            apis = {f.get("api_name", "") for f in items if f.get("api_name")}
            descs = [f.get("description", "")[:80] for f in items[:3]]
            if apis:
                parts.append(f"{sev.upper()}: API调用 {{{', '.join(sorted(apis))}}}")
            for d in descs:
                parts.append(f"  - {d}")

    return "; ".join(parts) if parts else "有发现但未分类"


def _parse_ovoida_results(session_dir: Path) -> list[dict[str, Any]]:
    """Parse OVOIDA session output for structured findings.

    Reads the session directory looking for:
    - JSON files written by OVOIDA tools
    - Markdown analysis notes (findings.md, *.md)
    - The command log for extracted evidence
    - Assembly/disassembly files with vulnerability annotations

    Returns a list of finding dicts suitable for merging with Phase 1 results.
    """
    import re as _re

    findings = []

    # 1. Try to find any JSON output files OVOIDA may have written
    for json_file in session_dir.glob("*.json"):
        if json_file.name == "ovoida_context.json":
            continue  # Skip our input context file
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict) and "findings" in data:
                findings.extend(data["findings"])
            elif isinstance(data, dict) and "finding" in data:
                findings.append(data["finding"])
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logging.warning("[pipeline] Failed to parse OVOIDA JSON file %s: %s", json_file.name, e)

    # 2. Parse markdown analysis notes for function addresses, APIs, IOCTLs
    for md_file in session_dir.glob("*.md"):
        try:
            md_text = md_file.read_text(encoding="utf-8", errors="replace")
            md_findings = _extract_findings_from_markdown(md_text, md_file.name)
            findings.extend(md_findings)
        except Exception as e:
            logging.warning("[pipeline] Failed to parse markdown file %s: %s", md_file.name, e)
    cmd_log = session_dir / "devops_command.log"
    if cmd_log.exists():
        try:
            log_text = cmd_log.read_text(encoding="utf-8", errors="replace")
            stdout_section = (
                log_text.split("--- stdout ---\n")[-1].split("\n\n--- stderr ---")[0]
                if "--- stdout ---" in log_text
                else ""
            )
            log_findings = _extract_findings_from_log(stdout_section)
            findings.extend(log_findings)
        except Exception as e:
            logging.warning("[pipeline] Failed to parse OVOIDA command log: %s", e)
    for asm_file in session_dir.glob("*.asm"):
        try:
            asm_text = asm_file.read_text(encoding="utf-8", errors="replace")[:4096]
            if asm_text:
                findings.append({
                    "source": "ovoida_evidence",
                    "file": asm_file.name,
                    "snippet": asm_text[:200],
                    "note": "Assembly evidence from OVOIDA analysis",
                })
        except Exception as e:
            logging.warning("[pipeline] Failed to parse assembly file %s: %s", asm_file.name, e)
    for disasm_file in session_dir.glob("disassembly*.txt"):
        try:
            disasm_text = disasm_file.read_text(encoding="utf-8", errors="replace")[:8192]
            if disasm_text:
                findings.append({
                    "source": "ovoida_disassembly",
                    "file": disasm_file.name,
                    "snippet": disasm_text[:500],
                    "note": "Disassembly evidence from OVOIDA analysis",
                })
        except Exception as e:
            logging.warning("[pipeline] Failed to parse disassembly file %s: %s", disasm_file.name, e)
    triage_file = session_dir / "triage.txt"
    if triage_file.exists():
        try:
            triage_text = triage_file.read_text(encoding="utf-8", errors="replace")[:4096]
            if triage_text:
                findings.append({
                    "source": "ovoida_triage",
                    "file": "triage.txt",
                    "snippet": triage_text[:200],
                    "note": "Triage evidence from OVOIDA analysis",
                })
        except Exception as e:
            logging.warning("[pipeline] Failed to parse triage file: %s", e)

    return findings


def _extract_findings_from_markdown(md_text: str, filename: str) -> list[dict[str, Any]]:
    """Extract function addresses, API names, and IOCTL codes from markdown analysis notes."""
    findings = []

    # Extract function addresses (sub_HEX pattern)
    func_pattern = re.compile(r'sub_([0-9A-Fa-f]+)', re.IGNORECASE)
    funcs_found = set(func_pattern.findall(md_text))

    # Extract kernel API names
    api_pattern = re.compile(r'\b(Mm\w+|Ke\w+|Zw\w+|Nt\w+|Ex\w+|Ps\w+|Se\w+|Io\w+|Rtl\w+|Hal\w+)\b')
    apis_found = set(api_pattern.findall(md_text))

    # Extract IOCTL codes (0x22xxxx pattern)
    ioctl_pattern = re.compile(r'0x(22[0-9A-Fa-f]{4})', re.IGNORECASE)
    ioctls_found = set(ioctl_pattern.findall(md_text))

    # Check for confirmation keywords that validate Phase 1 findings
    confirm_keywords = ["confirmed", "verified", "validated", "确认", "确认存在", "已确认"]
    is_confirmed = any(kw.lower() in md_text.lower() for kw in confirm_keywords)

    if apis_found:
        findings.append({
            "source": "ovoida_confirmed" if is_confirmed else "ovoida_analysis",
            "api_names": sorted(apis_found),
            "functions": [f"sub_{f}" for f in sorted(funcs_found)[:10]],
            "ioctl_codes": [f"0x{i}" for i in sorted(ioctls_found)[:10]],
            "confirmed": is_confirmed,
            "note": f"OVOIDA analysis ({filename}) identified APIs: {', '.join(sorted(apis_found))}",
            "evidence_snippet": md_text[:500],
        })

    if funcs_found and not apis_found:
        findings.append({
            "source": "ovoida_analysis",
            "functions": [f"sub_{f}" for f in sorted(funcs_found)[:15]],
            "note": f"OVOIDA identified functions in {filename}",
        })

    return findings


def _extract_findings_from_log(stdout_section: str) -> list[dict[str, Any]]:
    """Extract API and function mentions from OVOIDA command log stdout."""
    findings = []

    if not stdout_section:
        return findings

    api_pattern = _re.compile(r'\b(Mm\w+|Ke\w+|Zw\w+|Nt\w+|Ex\w+|Ps\w+|Se\w+|Io\w+|Rtl\w+|Hal\w+)\b')
    func_pattern = _re.compile(r'sub_[0-9A-Fa-f]+', re.IGNORECASE)
    ioctl_pattern = _re.compile(r'0x(22[0-9A-Fa-f]{4})', re.IGNORECASE)

    apis_found = set()
    for m in api_pattern.finditer(stdout_section):
        name = m.group(1)
        # Filter out common non-API matches
        if len(name) > 3 and name not in ("Input", "Invalid", "Integer"):
            apis_found.add(name)

    funcs_found = set(func_pattern.findall(stdout_section))
    ioctls_found = set(ioctl_pattern.findall(stdout_section))

    if apis_found:
        findings.append({
            "source": "ovoida_confirmed",
            "api_names": sorted(apis_found),
            "functions": sorted(funcs_found)[:10],
            "ioctl_codes": [f"0x{i}" for i in sorted(ioctls_found)[:10]],
            "confirmed": True,
            "note": f"OVOIDA identified {', '.join(sorted(apis_found))} during deep analysis",
        })

    return findings


# ---------------------------------------------------------------------------
# Phase 3: Unified Report
# ---------------------------------------------------------------------------

def generate_unified_report(
    config: PipelineConfig,
    scan_result: ScanResult,
    deep_results: list[DeepResult],
) -> dict[str, Any]:
    """Generate a unified report merging Phase 1 + Phase 2 results."""
    print(f"\n{'=' * 60}")
    print(f"  Phase 3: Unified Report Generation")
    print(f"{'=' * 60}")

    report_dir = config.workspace / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Parse OVOIDA session outputs for each completed deep analysis
    ovoida_findings: dict[str, list[dict]] = {}
    for r in deep_results:
        if r.ovoida_completed and r.ovoida_session_dir:
            findings = _parse_ovoida_results(r.ovoida_session_dir)
            if findings:
                ovoida_findings[r.sample_name] = findings

    # Merge OVOIDA findings back into Phase 1 samples
    merged_samples = _merge_ovoida_into_samples(scan_result.top_samples, ovoida_findings)

    # Extract exploit chains for dedicated section
    exploit_chains = _extract_exploit_chains(merged_samples, ovoida_findings)

    # --- Attack Path Visualization (DOT/Graphviz) ---
    _generate_attack_graphs(scan_result, report_dir)

    # --- Dynamic Analysis Report ---
    _generate_dynamic_reports(scan_result, report_dir)

    # Build JSON report
    report = {
        "tool": "DEVOPS_driver",
        "version": "0.1.0",
        "timestamp": datetime.now().isoformat(),
        "target": str(config.target),
        "summary": {
            "total_scanned": scan_result.samples_scanned,
            "high_risk_candidates": scan_result.high_risk_count,
            "deep_analyzed": sum(1 for r in deep_results if r.ovoida_completed),
            "deep_failed": sum(1 for r in deep_results if not r.ovoida_completed),
            "critical": scan_result.critical_count,
            "high": scan_result.high_count,
            "avg_score": scan_result.avg_score,
            "ovoida_findings": {k: len(v) for k, v in ovoida_findings.items()},
            "exploit_chain_count": len(exploit_chains),
        },
        "phase1_scan": {
            "elapsed": scan_result.elapsed,
            "top_samples": scan_result.top_samples,
        },
        "phase2_deep": [
            {
                "sample_name": r.sample_name,
                "risk_score": r.risk_score,
                "ovoida_completed": r.ovoida_completed,
                "ovoida_error": r.ovoida_error,
                "ovoida_session_dir": str(r.ovoida_session_dir) if r.ovoida_session_dir else None,
                "ovoida_findings": ovoida_findings.get(r.sample_name, []),
                "elapsed": r.elapsed,
            }
            for r in deep_results
        ],
        "merged_samples": merged_samples,
        "exploit_chains": exploit_chains,
    }

    # Write JSON
    json_path = report_dir / "unified_report.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  JSON report: {json_path}")

    # Write Markdown summary
    md_path = report_dir / "unified_report.md"
    _write_markdown_summary(report, md_path)
    print(f"  Markdown summary: {md_path}")

    # Write HTML report (uses merged samples)
    html_path = report_dir / "unified_report.html"
    _write_html_from_merged(report, html_path)
    print(f"  HTML report: {html_path}")

    # Write SARIF report (uses merged samples)
    sarif_path = report_dir / "unified_report.sarif"
    _write_sarif_from_merged(report, sarif_path)
    print(f"  SARIF report: {sarif_path}")

    return report


def _write_markdown_summary(report: dict, output_path: Path) -> None:
    """Write a Markdown summary of the unified report."""
    s = report["summary"]
    lines = [
        "# DEVOPS_driver Analysis Report",
        "",
        f"**Target:** {report['target']}  ",
        f"**Timestamp:** {report['timestamp']}  ",
        f"**Version:** {report['version']}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total scanned | {s['total_scanned']} |",
        f"| High-risk candidates | {s['high_risk_candidates']} |",
        f"| Deep analyzed (OVOIDA) | {s['deep_analyzed']} |",
        f"| Deep failed | {s['deep_failed']} |",
        f"| Critical | {s['critical']} |",
        f"| High | {s['high']} |",
        f"| Avg score | {s['avg_score']:.1f}/10 |",
        "",
        "## Phase 1: DriverScope Scan Results",
        "",
        "| Rank | Driver | Score | Level | Findings | Type | Arch |",
        "|---|---|---|---|---|---|---|",
    ]

    for i, sample in enumerate(report["phase1_scan"]["top_samples"], 1):
        lines.append(
            f"| {i} | {sample['name']} | {sample['risk_score']:.1f} | "
            f"{sample['risk_level']} | {sample['finding_count']} | "
            f"{sample.get('driver_type', 'N/A')} | {sample.get('arch', 'N/A')} |"
        )

    lines.append("")
    lines.append("## Phase 2: OVOIDA Deep Analysis")
    lines.append("")

    for r in report["phase2_deep"]:
        status = "COMPLETED" if r["ovoida_completed"] else f"FAILED: {r['ovoida_error']}"
        lines.append(f"### {r['sample_name']}")
        lines.append(f"- **Risk:** {r['risk_score']:.1f}/10")
        lines.append(f"- **Status:** {status}")
        lines.append(f"- **Session:** {r['ovoida_session_dir']}")
        lines.append(f"- **Time:** {r['elapsed']:.1f}s")

        # Include OVOIDA findings summary
        ov_findings = r.get("ovoida_findings", [])
        if ov_findings:
            confirmed = [f for f in ov_findings if f.get("source") in ("ovoida_confirmed", "ovoida_analysis")]
            if confirmed:
                apis = set()
                for f in confirmed:
                    # New format: api_names list
                    if "api_names" in f:
                        apis.update(f["api_names"])
                    # Legacy format: single api_name
                    elif f.get("api_name"):
                        apis.add(f["api_name"])
                if apis:
                    lines.append(f"- **OVOIDA Identified APIs:** {', '.join(sorted(apis))}")

            # Show confirmed IOCTL codes
            ioctls = set()
            for f in ov_findings:
                for code in f.get("ioctl_codes", []):
                    ioctls.add(code)
            if ioctls:
                lines.append(f"- **IOCTLs mentioned:** {', '.join(sorted(ioctls)[:10])}")

        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Attack Graph and Dynamic Report Generation
# ---------------------------------------------------------------------------


def _generate_attack_graphs(scan_result: ScanResult, report_dir: Path) -> None:
    """Generate attack path DOT files from scan results."""
    try:
        from src.models import Finding
        from src.report.attack_graph import (
            build_attack_graph_from_findings,
            build_cross_driver_graph,
            export_attack_graph,
        )

        samples = scan_result._samples
        if not samples:
            return

        # Single-driver attack graphs
        for sample in samples:
            findings = sample.analysis_findings or []
            if not findings:
                continue
            graph = build_attack_graph_from_findings(findings, sample)
            dot_path = report_dir / f"attack_{sample.name.replace('.sys', '')}.dot"
            export_attack_graph(graph, dot_path)
            print(f"  Attack graph: {dot_path.name}")

        # Cross-driver attack chain graph (if 2+ samples)
        if len(samples) >= 2:
            # Reconstruct correlation Finding objects from serialized data
            corr_findings: list[Finding] = []
            for fd in scan_result.correlation_findings:
                try:
                    corr_findings.append(Finding(
                        category=fd.get("category", "info"),
                        severity=fd.get("severity", "info"),
                        confidence=fd.get("confidence", "medium"),
                        description=fd.get("description", ""),
                        context=fd.get("context", {}),
                    ))
                except Exception:
                    continue

            if corr_findings:
                cross_graph = build_cross_driver_graph(samples, corr_findings)
                cross_dot_path = report_dir / "attack_cross_driver.dot"
                export_attack_graph(cross_graph, cross_dot_path)
                print(f"  Cross-driver graph: {cross_dot_path.name}")

    except Exception as e:
        print(f"  Attack graph generation failed: {e}")


def _generate_dynamic_reports(scan_result: ScanResult, report_dir: Path) -> None:
    """Generate dynamic analysis reports from sample dynamic_results."""
    try:
        from src.report.dynamic_report import generate_dynamic_json, generate_dynamic_report

        # Collect all dynamic results
        all_dynamic: list[dict[str, Any]] = []
        for sample in scan_result._samples:
            for dr in (sample.dynamic_results or []):
                enriched = dict(dr)
                enriched["sample_name"] = sample.name
                enriched["driver_path"] = str(sample.path)
                all_dynamic.append(enriched)

        if not all_dynamic:
            return

        # HTML report
        html_path = report_dir / "dynamic_report.html"
        generate_dynamic_report(all_dynamic, output_path=html_path)
        print(f"  Dynamic report: {html_path.name}")

        # JSON report
        json_path = report_dir / "dynamic_report.json"
        json_content = generate_dynamic_json(all_dynamic)
        json_path.write_text(json_content, encoding="utf-8")
        print(f"  Dynamic JSON: {json_path.name}")

    except Exception as e:
        print(f"  Dynamic report generation failed: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_level(score: float) -> str:
    """Legacy alias — use src.models.score_level instead."""
    from src.models import score_level as _sl
    return _sl(score)


# ---------------------------------------------------------------------------
# OVOIDA findings merge & exploit chain extraction
# ---------------------------------------------------------------------------

def _merge_ovoida_into_samples(
    samples: list[dict[str, Any]],
    ovoida_findings: dict[str, list[dict]],
) -> list[dict[str, Any]]:
    """Merge OVOIDA findings into Phase 1 sample dicts.

    For each sample with OVOIDA results:
    - Mark matching attack_chains with ovoida_confirmed
    - Append OVOIDA evidence to existing findings
    - Add any new findings OVOIDA discovered independently
    """
    merged = []
    for sample in samples:
        name = sample.get("name", "")
        sample_findings = list(sample.get("findings", []))
        ov_findings = ovoida_findings.get(name, [])

        if not ov_findings:
            merged.append(sample)
            continue

        # Build lookup for OVOIDA confirmed APIs and functions
        ov_apis: set[str] = set()
        ov_funcs: set[str] = set()
        ov_ioctls: set[str] = set()
        ov_confirmed = False

        for f in ov_findings:
            src = f.get("source", "")
            if src in ("ovoida_confirmed", "ovoida_analysis"):
                ov_apis.update(f.get("api_names", []))
                ov_funcs.update(f.get("functions", []))
                ov_ioctls.update(f.get("ioctl_codes", []))
                if f.get("confirmed"):
                    ov_confirmed = True

        # Mark matching DriverScope findings as OVOIDA-confirmed
        for finding in sample_findings:
            ctx = finding.get("context", {})
            apis = ctx.get("primitive_apis", [])
            func_addr = finding.get("function_address", "")
            func_name = f"sub_{func_addr:X}" if isinstance(func_addr, int) else str(func_addr)

            if apis and any(api in ov_apis for api in apis):
                finding["ovoida_confirmed"] = True
                finding.setdefault("context", {})["ovoida_session"] = True
            elif func_name in ov_funcs:
                finding["ovoida_confirmed"] = True

            # Append OVOIDA evidence snippets
            for ov_f in ov_findings:
                if ov_f.get("source") in ("ovoida_confirmed", "ovoida_analysis"):
                    evidence = finding.get("evidence", [])
                    snippet = ov_f.get("evidence_snippet", "")
                    if snippet and len(evidence) < 5:
                        evidence.append({
                            "source": "ovoida",
                            "snippet": snippet[:300],
                            "note": ov_f.get("note", ""),
                        })

        # Add OVOIDA-only findings not already in DriverScope
        ov_new = [f for f in ov_findings if f.get("source") in (
            "ovoida_disassembly", "ovoida_triage", "ovoida_evidence"
        )]
        if ov_new:
            sample_findings.extend(ov_new[:10])  # Cap at 10 evidence items

        new_sample = dict(sample)
        new_sample["findings"] = sample_findings
        new_sample["finding_count"] = len(sample_findings)
        merged.append(new_sample)

    return merged


def _extract_exploit_chains(
    merged_samples: list[dict[str, Any]],
    ovoida_findings: dict[str, list[dict]],
) -> list[dict[str, Any]]:
    """Extract structured exploit chain summaries from merged findings.

    Each chain contains: driver name, function address, IOCTL codes,
    dangerous APIs, missing validation checks, OVOIDA confirmation status,
    and a suggested PoC skeleton.
    """
    chains = []
    for sample in merged_samples:
        name = sample.get("name", "")
        for f in sample.get("findings", []):
            cat = f.get("category", "")
            if cat != "attack_chain":
                continue
            ctx = f.get("context", {})
            chain_type = ctx.get("chain_type", "")
            if chain_type != "byovd_complete":
                continue

            ovoida_ok = f.get("ovoida_confirmed", False) or ctx.get("ovoida_session", False)
            apis = ctx.get("primitive_apis", [])
            ioctls = ctx.get("ioctl_codes", [])
            missing = ctx.get("missing_checks", [])
            func_addr = f.get("function_address", 0)
            func_name = f"sub_{func_addr:X}" if isinstance(func_addr, int) else str(func_addr)
            severity = f.get("severity", "unknown")

            # Build PoC pseudo-code
            poc_lines = [
                f"// 1. Open device handle",
                f'HANDLE h = CreateFile("\\\\.\\\\{sample.get("driver_type", "Unknown")}", ...);',
                f"",
                f"// 2. Trigger via DeviceIoControl",
                f"DWORD bytes = 0;",
            ]
            for ioctl in ioctls[:3]:
                poc_lines.append(f"DeviceIoControl(h, {ioctl}, inputBuf, inSize, outputBuf, outSize, &bytes);")
            poc_lines.extend([
                f"",
                f"// 3. Result: {', '.join(apis)} called without {'/'.join(missing) if missing else 'validation'}",
                f"//    → Arbitrary kernel memory access primitive achieved",
            ])

            chains.append({
                "driver": name,
                "function": func_name,
                "function_address": func_addr,
                "severity": severity,
                "primitive_category": ctx.get("primitive_category", ""),
                "ioctl_codes": ioctls,
                "dangerous_apis": apis,
                "missing_checks": missing,
                "ovoida_confirmed": ovoida_ok,
                "confidence": f.get("confidence", "unknown"),
                "num_supporting_findings": ctx.get("num_supporting_findings", 0),
                "poc_pseudo_code": "\n".join(poc_lines),
                "description": f.get("description", ""),
            })

    # Sort: OVOIDA-confirmed first, then by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    chains.sort(key=lambda c: (
        not c["ovoida_confirmed"],
        severity_order.get(c.get("severity", "info"), 4),
    ))

    return chains


def _write_html_from_merged(report: dict, output_path: Path) -> None:
    """Write HTML report using merged samples with exploit chain cards."""
    try:
        from src.report.html import write_html
        from src.models import Report as ReportModel, Sample, Finding, Evidence, Severity, FindingCategory, Confidence

        # Convert merged sample dicts back to Sample objects for HTML generator
        samples = []
        for sd in report.get("merged_samples", report.get("phase1_scan", {}).get("top_samples", [])):
            sample = Sample(
                name=sd.get("name", "unknown"),
                path=Path(sd.get("path", "")),
                sha256=sd.get("sha256", ""),
                arch=type("Arch", (), {"value": sd.get("arch", "x64")})(),
                company=sd.get("company", ""),
                driver_type=sd.get("driver_type", ""),
                risk_score=sd.get("risk_score", 0.0),
            )
            for fd in sd.get("findings", []):
                finding = Finding(
                    category=FindingCategory(fd.get("category", "info")),
                    severity=Severity(fd.get("severity", "info")),
                    confidence=Confidence(fd.get("confidence", "medium")),
                    description=fd.get("description", ""),
                    function_address=fd.get("function_address", 0),
                    api_name=fd.get("api_name", ""),
                    ioctl_code=fd.get("ioctl_code", 0),
                    context=fd.get("context", {}),
                    evidence=[
                        Evidence(
                            type=e.get("type", "code"),
                            location=e.get("location", ""),
                            snippet=e.get("snippet", ""),
                            rule_id=e.get("rule_id", ""),
                        )
                        for e in fd.get("evidence", [])
                    ],
                )
                # Carry over ovoida_confirmed
                if fd.get("ovoida_confirmed"):
                    finding.context["ovoida_confirmed"] = True
                sample.analysis_findings.append(finding)
            samples.append(sample)

        model_report = ReportModel(
            samples=samples,
            timestamp=report.get("timestamp", ""),
            tool_version=report.get("version", ""),
            backend="capstone",
            total_analyzed=len(samples),
            total_findings=sum(len(s.analysis_findings) for s in samples),
        )

        write_html(model_report, output_path)
    except Exception as e:
        # Fallback: write a simple HTML with exploit chain cards
        _write_simple_exploit_html(report, output_path)


def _write_simple_exploit_html(report: dict, output_path: Path) -> None:
    """Write a simple HTML report focused on exploit chains."""
    import html as html_mod
    chains = report.get("exploit_chains", [])
    samples = report.get("merged_samples", report.get("phase1_scan", {}).get("top_samples", []))

    chain_cards = ""
    for ch in chains:
        sev_color = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107"}.get(ch.get("severity", ""), "#666")
        ovoida_badge = '<span style="color:#28a745;font-weight:bold;">✓ OVOIDA confirmed</span>' if ch.get("ovoida_confirmed") else '<span style="color:#6c757d;">DriverScope only</span>'
        apis = ", ".join(ch.get("dangerous_apis", []))
        ioctls = ", ".join(ch.get("ioctl_codes", []))
        missing = ", ".join(ch.get("missing_checks", [])) or "none"
        poc = html_mod.escape(ch.get("poc_pseudo_code", ""))

        chain_cards += f"""
<div style="background:#fff;border-left:4px solid {sev_color};border-radius:8px;padding:16px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
  <h3 style="color:{sev_color};margin:0 0 8px;">{ch.get("function", "unknown")} — {ch.get("driver", "")}</h3>
  <div style="font-size:13px;color:#555;">
    <strong>Severity:</strong> {ch.get("severity", "").upper()} | <strong>IOCTLs:</strong> {ioctls or "N/A"} |
    <strong>APIs:</strong> {apis} | <strong>Missing:</strong> {missing}<br/>
    <strong>Status:</strong> {ovoida_badge}
  </div>
  <details style="margin-top:8px;">
    <summary style="cursor:pointer;font-size:12px;color:#0d6efd;">PoC Pseudo-Code</summary>
    <pre style="background:#f8f9fa;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;">{poc}</pre>
  </details>
</div>"""

    sample_rows = ""
    for s in samples[:20]:
        sev = _score_level(s.get("risk_score", 0))
        color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#17a2b8"}.get(sev, "#666")
        sample_rows += f"""
<tr>
  <td>{html_mod.escape(s.get("name", ""))}</td>
  <td><span style="color:{color};font-weight:bold;">{s.get("risk_score", 0):.1f} {sev}</span></td>
  <td>{s.get("finding_count", 0)}</td>
  <td>{html_mod.escape(s.get("driver_type", ""))}</td>
  <td>{s.get("arch", "")}</td>
</tr>"""

    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>DEVOPS_driver Report</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;color:#333;padding:20px;}}
.container{{max-width:1200px;margin:0 auto;}}h1{{font-size:24px;margin-bottom:4px;}}
h2{{font-size:18px;margin:24px 0 12px;}}.subtitle{{color:#666;font-size:14px;margin-bottom:20px;}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);}}
th{{background:#f8f9fa;padding:10px 12px;text-align:left;font-size:12px;color:#666;border-bottom:2px solid #dee2e6;}}
td{{padding:8px 12px;border-bottom:1px solid #eee;font-size:13px;}}</style></head><body>
<div class="container">
  <h1>DEVOPS_driver Report</h1>
  <p class="subtitle">{html_mod.escape(report.get("tool", ""))} v{html_mod.escape(report.get("version", ""))} | {html_mod.escape(report.get("timestamp", ""))}</p>
  <h2>Summary</h2>
  <p>Scanned: {report.get("summary", {}).get("total_scanned", 0)} |
  Critical: {report.get("summary", {}).get("critical", 0)} |
  High: {report.get("summary", {}).get("high", 0)} |
  Exploit Chains: {len(chains)}</p>
  <h2>Exploit Chains ({len(chains)})</h2>
  {chain_cards or '<p style="color:#888;">No complete exploit chains detected.</p>'}
  <h2>All Samples</h2>
  <table><tr><th>Driver</th><th>Score</th><th>Findings</th><th>Type</th><th>Arch</th></tr>{sample_rows}</table>
</div></body></html>"""
    output_path.write_text(body, encoding="utf-8")


def _write_sarif_from_merged(report: dict, output_path: Path) -> None:
    """Write SARIF report using merged samples."""
    try:
        from src.report.sarif import write_sarif
        from src.models import Report as ReportModel, Sample, Finding, Evidence, Severity, FindingCategory, Confidence

        samples = []
        for sd in report.get("merged_samples", report.get("phase1_scan", {}).get("top_samples", [])):
            sample = Sample(
                name=sd.get("name", "unknown"),
                path=Path(sd.get("path", "")),
                sha256=sd.get("sha256", ""),
                arch=type("Arch", (), {"value": sd.get("arch", "x64")})(),
                company=sd.get("company", ""),
                driver_type=sd.get("driver_type", ""),
                risk_score=sd.get("risk_score", 0.0),
            )
            for fd in sd.get("findings", []):
                finding = Finding(
                    category=FindingCategory(fd.get("category", "info")),
                    severity=Severity(fd.get("severity", "info")),
                    confidence=Confidence(fd.get("confidence", "medium")),
                    description=fd.get("description", ""),
                    function_address=fd.get("function_address", 0),
                    api_name=fd.get("api_name", ""),
                    ioctl_code=fd.get("ioctl_code", 0),
                    context=fd.get("context", {}),
                    evidence=[
                        Evidence(
                            type=e.get("type", "code"),
                            location=e.get("location", ""),
                            snippet=e.get("snippet", ""),
                            rule_id=e.get("rule_id", ""),
                        )
                        for e in fd.get("evidence", [])
                    ],
                )
                if fd.get("ovoida_confirmed"):
                    finding.context["ovoida_confirmed"] = True
                sample.analysis_findings.append(finding)
            samples.append(sample)

        model_report = ReportModel(
            samples=samples,
            timestamp=report.get("timestamp", ""),
            tool_version=report.get("version", ""),
            backend="capstone",
            total_analyzed=len(samples),
            total_findings=sum(len(s.analysis_findings) for s in samples),
        )
        write_sarif(model_report, output_path)
    except Exception:
        # Fallback: write minimal SARIF
        _write_minimal_sarif(report, output_path)


def _write_minimal_sarif(report: dict, output_path: Path) -> None:
    """Write a minimal SARIF file with exploit chains as results."""
    chains = report.get("exploit_chains", [])
    results = []
    for ch in chains:
        tags = []
        if ch.get("ovoida_confirmed"):
            tags.append("ovoida-confirmed")
        results.append({
            "ruleId": "BYOVD_ATTACK_CHAIN",
            "level": "error",
            "message": {
                "text": (
                    f"BYOVD Attack Chain in {ch.get('function', 'unknown')} "
                    f"({ch.get('driver', '')}): {', '.join(ch.get('dangerous_apis', []))} "
                    f"without {'/'.join(ch.get('missing_checks', []))}"
                ),
            },
            "properties": {
                "severity": ch.get("severity", ""),
                "ioctl_codes": ch.get("ioctl_codes", []),
                "dangerous_apis": ch.get("dangerous_apis", []),
                "missing_checks": ch.get("missing_checks", []),
                "poc_pseudo_code": ch.get("poc_pseudo_code", ""),
                "tags": tags,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DEVOPS_driver",
                    "version": report.get("version", ""),
                    "informationUri": "https://github.com/DEVOPS_driver",
                    "rules": [{
                        "id": "BYOVD_ATTACK_CHAIN",
                        "name": "BYOVD Attack Chain",
                        "shortDescription": {"text": "Complete BYOVD attack chain detected: IOCTL handler calls dangerous kernel APIs without input validation"},
                        "defaultConfiguration": {"level": "error"},
                    }],
                },
            },
            "results": results,
        }],
    }
    output_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
