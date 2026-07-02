"""DEVOPS_driver — CLI entry point for the unified pipeline.

Usage:
    python -m src pipeline samples/                                # Full pipeline
    python -m src pipeline samples/ --threshold 7.0                # Only 7+ risk → OVOIDA
    python -m src pipeline samples/ --max-deep 3                   # Limit OVOIDA to 3
    python -m src pipeline samples/ --no-ovoida                    # Phase 1 only
    python -m src pipeline samples/ --ov-url https://api.openai.com/v1 --ov-key sk-xxx
    python -m src init-config                                      # Create ~/.devops_driver/config.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="devops-driver",
        description="DEVOPS_driver — Unified Windows Driver Analysis Platform (DriverScope + OVOIDA)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- pipeline subcommand ---
    p = subparsers.add_parser("pipeline", help="Run full 3-phase analysis pipeline")
    p.add_argument("target", help="Path to directory containing .sys files")
    p.add_argument("--workspace", "-w", default="workspace", help="Output workspace directory")
    p.add_argument("--threshold", "-t", type=float, default=5.0, help="Risk score threshold for OVOIDA (default: 5.0)")
    p.add_argument("--max-deep", type=int, default=5, help="Max drivers for OVOIDA (default: 5, 0=unlimited)")
    p.add_argument("--no-ovoida", action="store_true", help="Skip Phase 2 (OVOIDA)")
    p.add_argument("--no-preprocessing", action="store_true", help="Skip Phase 0 (unpacking/deobfuscation)")
    p.add_argument("--format", nargs="+", default=["json", "markdown"], help="Report formats")
    p.add_argument("--backend", default="capstone", help="Disassembly backend")
    p.add_argument("--timeout", type=int, default=30, help="DriverScope timeout per driver (s)")
    p.add_argument("--workers", "-j", type=int, default=0, help="Parallel workers (0=auto)")
    p.add_argument("--no-funnel", action="store_true", help="Skip filter funnel")
    p.add_argument("--no-cache", action="store_true", help="Disable analysis cache")
    p.add_argument("--deep-analysis", action="store_true",
                   help="Run Ghidra full analysis on high-risk candidates before OVOIDA")
    p.add_argument("--deep-threshold", type=float, default=5.0,
                   help="Min risk score for Ghidra deep analysis (default: 5.0)")
    p.add_argument("--deep-max", type=int, default=5,
                   help="Max drivers for Ghidra deep analysis (default: 5)")
    p.add_argument("--deep-timeout", type=int, default=300,
                   help="Ghidra timeout per driver in seconds (default: 300)")
    p.add_argument("--usermode", action="store_true",
                   help="Also analyze .exe/.dll files in target directory")
    p.add_argument("--score-engine", default="default", choices=["default", "exploitability"],
                   help="Scoring engine: default (BYOVD-focused) or exploitability (security-mechanism-aware)")
    # OVOIDA API settings
    p.add_argument("--ov-url", help="OVOIDA LLM API URL (e.g. https://api.openai.com/v1)")
    p.add_argument("--ov-key", help="OVOIDA LLM API key")
    p.add_argument("--ov-model", default="", help="OVOIDA LLM model name")
    p.add_argument("--ov-max-iter", type=int, default=30, help="OVOIDA max iterations")
    p.add_argument("--ov-timeout", type=int, default=0, help="OVOIDA timeout per run (s, 0=unlimited)")
    p.add_argument("--ovoida-root", help="Override OVOIDA project root path (default: components/ovoida)")

    # --- scan subcommand (DriverScope only, for quick scanning) ---
    s = subparsers.add_parser("scan", help="Quick scan with DriverScope only (Phase 1)")
    s.add_argument("target", help="Path to .sys file or directory")
    s.add_argument("--backend", default="capstone")
    s.add_argument("--timeout", type=int, default=30)
    s.add_argument("--workers", "-j", type=int, default=0)
    s.add_argument("--no-funnel", action="store_true")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--output", "-o", help="Output JSON report path")
    s.add_argument("--threshold", type=float, default=5.0, help="Risk threshold for OVOIDA candidates")
    s.add_argument("--score-engine", default="default", choices=["default", "exploitability"],
                   help="Scoring engine: default or exploitability")
    s.add_argument("--usermode", action="store_true",
                   help="Also analyze .exe/.dll files in target directory")

    # --- deep subcommand (Ghidra full analysis on a single .sys) ---
    d = subparsers.add_parser("deep", help="Ghidra full disassembly + taint tracking on a single driver")
    d.add_argument("target", help="Path to .sys file")
    d.add_argument("--timeout", type=int, default=300, help="Ghidra timeout in seconds (default: 300)")
    d.add_argument("--output", "-o", help="Output JSON report path")

    # --- list-analyzers subcommand ---
    la = subparsers.add_parser("list-analyzers", help="List registered analyzers")

    # --- report subcommand ---
    rp = subparsers.add_parser("report", help="Generate formatted report from JSON")
    rp.add_argument("input", help="Input report JSON path")
    rp.add_argument(
        "--format", choices=["json", "html", "sarif", "pdf", "markdown"], default="json"
    )
    rp.add_argument("--output", "-o", help="Output file path")

    # --- init-config subcommand ---
    c = subparsers.add_parser("init-config", help="Create default config at ~/.devops_driver/config.json")
    c.add_argument("--output", "-o", help="Custom config path")

    # --- validate subcommand (dynamic analysis) ---
    v = subparsers.add_parser("validate", help="Dynamic validation of a driver in sandbox/debugger")
    v.add_argument("target", help="Path to .sys file to validate")
    v.add_argument("--sandbox", action="store_true", help="Run in QEMU sandbox")
    v.add_argument("--debugger", action="store_true", help="Attach WinDbg/KD for runtime analysis")
    v.add_argument("--poc", help="Path to PoC script (.py) to execute against driver")
    v.add_argument("--qemu", help="Path to qemu-system-x86_64.exe")
    v.add_argument("--vm-image", help="Path to VM disk image")
    v.add_argument("--snapshot", default="clean", help="VM snapshot name for revert")
    v.add_argument("--windbg", help="Path to WinDbg (windbgx.exe)")
    v.add_argument("--timeout", type=int, default=30, help="Seconds per test case")
    v.add_argument("--output", "-o", help="Output JSON report path")

    # --- correlate subcommand (multi-driver correlation) ---
    co = subparsers.add_parser("correlate", help="Multi-driver correlation analysis")
    co.add_argument("--drivers", required=True, help="Path to directory containing multiple drivers")
    co.add_argument("--output", "-o", help="Output DOT graph path")
    co.add_argument("--json", help="Output JSON correlation report path")

    # --- check-env subcommand (dynamic analysis environment) ---
    ce = subparsers.add_parser("check-env", help="Check dynamic analysis environment (QEMU, WinDbg, KDNET)")

    # --- reverse subcommand (AI-powered reverse engineering, no driver scoring) ---
    rv = subparsers.add_parser("reverse", help="AI-powered reverse engineering of any PE file (no BYOVD scoring)")
    rv.add_argument("target", help="Path to PE file (.exe, .dll, .sys, or directory)")
    rv.add_argument("--workspace", "-w", default="workspace", help="Output workspace directory")
    rv.add_argument("--ov-url", help="OVOIDA LLM API URL (e.g. https://api.deepseek.com/v1)")
    rv.add_argument("--ov-key", help="OVOIDA LLM API key")
    rv.add_argument("--ov-model", default="deepseek-chat", help="OVOIDA LLM model name")
    rv.add_argument("--ov-max-iter", type=int, default=30, help="OVOIDA max iterations")
    rv.add_argument("--ov-timeout", type=int, default=0, help="OVOIDA timeout (s, 0=unlimited)")
    rv.add_argument("--output", "-o", help="Output JSON report path")
    rv.add_argument("--ovoida-root", help="Override OVOIDA project root path")

    args = parser.parse_args(argv)

    if args.command == "pipeline":
        return _run_pipeline(args)
    elif args.command == "scan":
        return _run_scan(args)
    elif args.command == "deep":
        return _run_deep(args)
    elif args.command == "reverse":
        return _run_reverse(args)
    elif args.command == "report":
        return _run_report(args)
    elif args.command == "list-analyzers":
        return _list_analyzers(args)
    elif args.command == "init-config":
        return _init_config(args)
    elif args.command == "validate":
        return _run_validate(args)
    elif args.command == "correlate":
        return _run_correlate(args)
    elif args.command == "check-env":
        return _run_check_env(args)

    return 1


def _run_pipeline(args: PipelineConfig) -> int:
    """Run the unified 3-phase pipeline."""
    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    from src.config import PipelineConfig
    from src.pipeline import run_phase1_scan, run_phase2_deep, generate_unified_report

    # Load user config as base, CLI args override
    from src.config.user import load_config
    user_cfg = load_config()

    config = PipelineConfig(
        target=target,
        workspace=Path(args.workspace),
        risk_threshold=args.threshold,
        max_deep_targets=0 if args.no_ovoida else args.max_deep,
        ds_backend=args.backend,
        ds_timeout=args.timeout,
        ds_workers=args.workers,
        ds_use_funnel=not args.no_funnel,
        ds_use_cache=not args.no_cache,
        ds_include_usermode=args.usermode,
        ds_score_engine=args.score_engine,
        ghidra_deep=args.deep_analysis,
        ghidra_deep_threshold=args.deep_threshold,
        ghidra_deep_max=args.deep_max,
        ghidra_deep_timeout=args.deep_timeout,
        ovoida_root=Path(args.ovoida_root) if args.ovoida_root else None,
        ov_output_mode=user_cfg.get("ov_output_mode", "pseudocode"),
        ov_model=args.ov_model or user_cfg.get("ov_model", ""),
        ov_api_url=args.ov_url or user_cfg.get("ov_api_url", ""),
        ov_api_key=args.ov_key or user_cfg.get("ov_api_key", ""),
        ov_max_iter=args.ov_max_iter,
        ov_timeout=args.ov_timeout,
        report_formats=args.format,
        unified_report=True,
    )
    config.resolve_paths()

    total_start = time.time()

    # Phase 0: Preprocessing (unpacking / deobfuscation)
    if getattr(args, "no_preprocessing", False):
        print("\n[pipeline] Preprocessing disabled (--no-preprocessing). Skipping Phase 0.")
    else:
        try:
            from src.analysis.preprocessing import run_preprocessing
            from src.analysis.preprocessing.pipeline import PreprocessingConfig

            pp_config = PreprocessingConfig(
                enabled=True,
                allow_static_unpack=config.allow_static_unpack,
                allow_dynamic_unpack=config.allow_dynamic_unpack,
                upx_binary=config.upx_binary,
                dynamic_unpack_timeout=config.dynamic_unpack_timeout,
                qemu_path=config.qemu_path,
                vm_image=config.vm_image,
                sandbox_snapshot=config.sandbox_snapshot,
                frida_server_port=config.frida_server_port,
                cape_api_url=config.cape_api_url,
                use_cape=config.use_cape,
            )

            pp_result = run_preprocessing(str(config.target), pp_config)

            if pp_result.was_unpacked:
                print(f"\n[pipeline] Phase 0: Unpacked to {pp_result.cleaned_target}")
                # Update target to unpacked path
                config.target = Path(pp_result.cleaned_target)
            elif pp_result.packer_info and pp_result.packer_info.is_packed:
                packer = pp_result.packer_info.name
                print(f"\n[pipeline] Phase 0: Detected packer '{packer}' but could not unpack.")
                print(f"  Reasons: {'; '.join(pp_result.packer_info.reasons[:3])}")
                if pp_result.warnings:
                    for w in pp_result.warnings[:3]:
                        print(f"  Warning: {w}")
            else:
                print(f"\n[pipeline] Phase 0: No packing detected — proceeding with original binary")

        except Exception as e:
            print(f"\n[pipeline] Phase 0 error: {e}")
            print("  Continuing with original binary...")

    # Phase 1: DriverScope Batch Scan
    scan_result = run_phase1_scan(config)

    if scan_result.high_risk_count == 0:
        print("\n[pipeline] No high-risk candidates found. Skipping Phase 2.")
        deep_results = []
    elif args.no_ovoida:
        print("\n[pipeline] OVOIDA disabled (--no-ovoida). Skipping Phase 2.")
        deep_results = []
    else:
        # Check OVOIDA API config
        if not config.has_ovoida_api():
            print("\n[pipeline] WARNING: OVOIDA API not configured.")
            print("  Set --ov-url and --ov-key, or run: python -m src init-config")
            print("  Continuing without OVOIDA...")
            deep_results = []
        else:
            deep_results = run_phase2_deep(config, scan_result)

    # Phase 3: Unified Report
    report = generate_unified_report(config, scan_result, deep_results)

    total_elapsed = time.time() - total_start
    print(f"\n{'=' * 60}")
    print(f"  Pipeline complete in {total_elapsed:.1f}s")
    print(f"  Reports: {config.workspace / 'reports'}")
    print(f"{'=' * 60}")

    return 0


def _run_scan(args: argparse.Namespace) -> int:
    """Quick scan with DriverScope only."""
    from src.config import PipelineConfig
    from src.pipeline import run_phase1_scan

    config = PipelineConfig(
        target=Path(args.target),
        ds_backend=args.backend,
        ds_timeout=args.timeout,
        ds_workers=args.workers,
        ds_use_funnel=not args.no_funnel,
        ds_use_cache=not args.no_cache,
        ds_include_usermode=args.usermode,
        ds_score_engine=args.score_engine,
        risk_threshold=args.threshold,
        max_deep_targets=0,  # Phase 1 only
    )
    config.resolve_paths()

    scan_result = run_phase1_scan(config)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "tool": "DEVOPS_driver (Phase 1 only)",
            "target": str(config.target),
            "summary": {
                "scanned": scan_result.samples_scanned,
                "high_risk": scan_result.high_risk_count,
                "critical": scan_result.critical_count,
                "high": scan_result.high_count,
                "avg_score": scan_result.avg_score,
            },
            "top_samples": scan_result.top_samples,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[scan] Report written to {out}")

    return 0


def _run_deep(args: argparse.Namespace) -> int:
    """Run Ghidra full disassembly + taint tracking on a single driver."""
    from src.analysis.deep import run_deep_analysis

    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    print(f"\n{'=' * 60}")
    print(f"  Ghidra Deep Analysis")
    print(f"  Target: {target.name}")
    print(f"  Timeout: {args.timeout}s")
    print(f"{'=' * 60}")

    try:
        result = run_deep_analysis(target, timeout=args.timeout, verbose=True)

        print(f"\n[deep] Analysis complete in {result['elapsed']:.1f}s")
        print(f"  Risk score: {result['risk_score']:.1f}/10")
        print(f"  Findings: {len(result['findings'])}")

        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)

            # Build findings list
            findings_list = []
            for f in result["findings"]:
                fd = f.to_dict()
                fd["function_address"] = hex(f.function_address) if f.function_address else None
                fd["instruction_address"] = hex(f.instruction_address) if f.instruction_address else None
                findings_list.append(fd)

            out.write_text(json.dumps({
                "tool": "DEVOPS_driver (Ghidra deep)",
                "sample": target.name,
                "risk_score": result["risk_score"],
                "findings": findings_list,
                "ghidra_version": result["ghidra_version"],
                "elapsed_seconds": round(result["elapsed"], 1),
            }, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\n[deep] Report written to {out}")

    except RuntimeError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1

    return 0


def _run_reverse(args: argparse.Namespace) -> int:
    """AI-powered reverse engineering — skip BYOVD scoring, send directly to OVOIDA."""
    import os
    import subprocess

    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    session_dir = workspace / "sessions" / target.stem
    session_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"  AI Reverse Engineering (no BYOVD scoring)")
    print(f"  Target: {target}")
    print(f"  Model: {args.ov_model}")
    print(f"{'=' * 60}")

    # Extract PE metadata
    from src.ingestion.pe_parser import ingest, is_driver_pe
    from src.ingestion.usermode_parser import ingest_usermode
    import pefile

    try:
        pe = pefile.PE(str(target), fast_load=False)
    except pefile.PEFormatError as e:
        print(f"[error] Not a valid PE: {e}", file=sys.stderr)
        return 1

    is_drv = is_driver_pe(pe)
    if is_drv:
        sample = ingest(target)
    else:
        sample = ingest_usermode(target)

    # Build context for OVOIDA
    context = {
        "sample": {
            "name": sample.name,
            "path": str(target),
            "sha256": sample.sha256,
            "arch": sample.arch.value,
            "is_driver": is_drv,
            "binary_type": getattr(sample, "binary_type", "sys" if is_drv else "exe"),
            "size": sample.size,
            "compile_timestamp": sample.compile_timestamp,
            "entry_point": hex(sample.entry_point) if sample.entry_point else "0x0",
            "sections": sample.sections[:20],
            "debug_path": sample.debug_path,
        },
        "imports": sample.imports[:200],
        "exports": sample.exports[:50],
        "strings": [],
        "analysis_note": (
            "This is a GENERAL reverse engineering task — NOT a BYOVD driver vulnerability scan. "
            "Analyze the binary's purpose, functionality, interesting behaviors, and potential risks. "
            "Focus on: what does this program do? How does it work? What APIs does it call and why? "
            "Are there any suspicious or interesting behaviors?"
        ),
    }

    # Extract interesting strings
    try:
        data = target.read_bytes()
        import re
        ascii_strings = re.findall(rb'[\x20-\x7e]{6,}', data)
        context["strings"] = [s.decode("ascii", errors="replace") for s in ascii_strings[:100]]
    except Exception:
        pass

    # Write context
    context_path = session_dir / "reverse_context.json"
    context_path.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")

    # Build OVOIDA task prompt
    task = (
        f"你是高级逆向工程师。请对以下二进制文件进行深度分析。\n\n"
        f"## 目标文件\n"
        f"- 路径: {target}\n"
        f"- 类型: {'Windows 驱动 (.sys)' if is_drv else 'User-mode PE (.exe/.dll)'}\n"
        f"- 架构: {sample.arch.value}\n"
        f"- SHA256: {sample.sha256}\n"
        f"- 大小: {sample.size} bytes\n"
        f"- 入口点: {hex(sample.entry_point) if sample.entry_point else 'N/A'}\n"
        f"- 编译时间戳: {sample.compile_timestamp}\n\n"
        f"## 导入函数 ({len(sample.imports)} 个)\n"
        f"{json.dumps(sample.imports[:100], indent=2)}\n\n"
        f"## 导出函数 ({len(sample.exports)} 个)\n"
        f"{json.dumps(sample.exports[:30], indent=2)}\n\n"
        f"## 区段\n"
        f"{json.dumps(sample.sections[:15], indent=2)}\n\n"
        f"## 字符串 (前100条)\n"
        f"{json.dumps(context['strings'][:100], indent=2)}\n\n"
        f"## 你的任务\n"
        f"请从以下角度全面分析此程序：\n"
        f"1. **功能概述**: 这个程序是做什么的？\n"
        f"2. **技术分析**: 关键 API 调用的目的和含义\n"
        f"3. **工作流程**: 推测程序的执行流程\n"
        f"4. **风险/特征**: 是否有任何可疑或值得注意的行为\n"
        f"5. **结论**: 综合判断此程序的性质和意图\n\n"
        f"请用中文回复，提供详细的技术分析。"
    )

    # Direct API call (OVOIDA agent is for BYOVD pipeline, reverse mode uses direct API)
    return _call_api_directly(task, args, session_dir, target)


def _call_api_directly(task: str, args, session_dir: Path, target: Path) -> int:
    """Direct API call fallback when OVOIDA agent is unavailable."""
    import urllib.request
    import urllib.error

    api_url = args.ov_url or os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com/v1")
    api_key = args.ov_key or os.environ.get("OPENAI_API_KEY", "")
    model = args.ov_model or "deepseek-chat"

    if not api_key:
        print("[error] No API key provided. Use --ov-key or set OPENAI_API_KEY env var.", file=sys.stderr)
        return 1

    if not api_url.endswith("/chat/completions"):
        api_url = api_url.rstrip("/") + "/chat/completions"

    print(f"[reverse] Calling {api_url} with model {model}...")

    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": task}],
        "max_tokens": 4096,
        "temperature": 0.3,
    }).encode("utf-8")

    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        timeout = args.ov_timeout if args.ov_timeout > 0 else 180
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
            content = body["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")[:500]
        print(f"[error] API returned HTTP {e.code}: {err_body}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[error] API call failed: {e}", file=sys.stderr)
        return 1

    # Print result
    print(f"\n{'=' * 60}")
    print(f"  AI Analysis Result")
    print(f"{'=' * 60}\n")
    print(content)

    # Save
    output_path = Path(args.output) if args.output else session_dir / "reverse_result.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "tool": "DEVOPS_driver (AI Reverse - Direct API)",
        "target": str(target),
        "model": model,
        "api_url": api_url,
        "analysis": content,
        "usage": body.get("usage", {}),
    }
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[reverse] Report written to {output_path}")

    return 0


def _run_report(args: argparse.Namespace) -> int:
    """Generate formatted report from a JSON report file."""
    import json as _json

    src_path = Path(args.input)
    if not src_path.exists():
        print(f"[error] File not found: {src_path}", file=sys.stderr)
        return 1

    data = _json.loads(src_path.read_text(encoding="utf-8"))
    out_path = Path(args.output) if args.output else src_path.with_suffix(f".{args.format}")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "html":
        from src.models import Report
        from src.report.html import generate_html
        report = Report(**{k: v for k, v in data.items() if k in ("samples", "timestamp", "tool_version", "backend", "total_analyzed", "total_findings", "summary")})
        out_path.write_text(generate_html(report), encoding="utf-8")
    elif args.format == "sarif":
        from src.models import Report
        from src.report.sarif import generate_sarif
        report = Report(**{k: v for k, v in data.items() if k in ("samples", "timestamp", "tool_version", "backend", "total_analyzed", "total_findings", "summary")})
        out_path.write_text(_json.dumps(generate_sarif(report), indent=2), encoding="utf-8")
    elif args.format == "markdown":
        from src.models import Report
        from src.report.markdown import generate_markdown
        report = Report(**{k: v for k, v in data.items() if k in ("samples", "timestamp", "tool_version", "backend", "total_analyzed", "total_findings", "summary")})
        out_path.write_text(generate_markdown(report), encoding="utf-8")
    else:
        out_path.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[report] {args.format.upper()} report written to {out_path}")
    return 0


def _list_analyzers(args: argparse.Namespace) -> int:
    """List all registered analyzers."""
    from src.analysis.core.registry import list_analyzers
    analyzers = list_analyzers()
    print(f"\n{'=' * 60}")
    print(f"  Registered Analyzers ({len(analyzers)})")
    print(f"{'=' * 60}")
    for a in analyzers:
        status = "enabled" if a.get("enabled") else "disabled"
        print(f"  {a['name']:30s} [{status}]")
        if a.get("description"):
            print(f"    {a['description']}")
        print()
    return 0


def _init_config(args: argparse.Namespace) -> int:
    """Create default config file."""
    from src.config.user import create_default_config

    path = Path(args.output) if args.output else None
    created = create_default_config(path)
    print(f"[config] Default config created at: {created}")
    print(f"  Edit this file to set your OVOIDA API URL and key.")
    return 0


def _run_validate(args: argparse.Namespace) -> int:
    """Dynamic validation of a driver in sandbox/debugger."""
    import json as _json

    target = Path(args.target)
    if not target.exists():
        print(f"[error] Target not found: {target}", file=sys.stderr)
        return 1

    from src.config.dynamic import DynamicConfig, safety_check

    config = DynamicConfig(
        sandbox_enabled=args.sandbox,
        debugger_attached=args.debugger,
        qemu_path=args.qemu or "",
        vm_image=args.vm_image or "",
        snapshot_name=args.snapshot,
        windbg_path=args.windbg or "",
        timeout_per_test=args.timeout,
    )

    try:
        safety_check(config)
    except RuntimeError as e:
        print(f"[validate] {e}", file=sys.stderr)
        return 1

    print(f"\n{'=' * 60}")
    print(f"  Dynamic Validation")
    print(f"  Target: {target.name}")
    print(f"  Sandbox: {args.sandbox}")
    print(f"  Debugger: {args.debugger}")
    print(f"  PoC: {args.poc}")
    print(f"{'=' * 60}")

    # Step 1: Static analysis baseline
    print("\n[validate] Step 1: Static analysis for baseline...")
    from src.config import PipelineConfig
    from src.disassembly import get_backend
    from src.ingestion.pe_parser import ingest_any_pe
    from src.analysis.core.registry import run_all_analyzers

    try:
        sample = ingest_file(target)
        print(f"  Ingested: {sample.name} ({sample.arch.value}, {sample.size} bytes)")
    except Exception as e:
        print(f"[error] Failed to ingest {target.name}: {e}", file=sys.stderr)
        return 1

    backend = get_backend("capstone")
    try:
        ir = backend.disassemble(sample)
        print(f"  Disassembled: {len(ir.functions)} functions, {len(ir.instructions)} instructions")
    except Exception as e:
        print(f"[error] Disassembly failed: {e}", file=sys.stderr)
        return 1

    static_findings = run_all_analyzers(sample, ir)
    print(f"  Static findings: {len(static_findings)}")

    # Step 2: Dynamic validation
    print("\n[validate] Step 2: Dynamic validation...")
    from src.analysis.dynamic.validator import DynamicValidator, ValidationConfig

    val_config = ValidationConfig(
        sandbox_enabled=args.sandbox,
        debugger_enabled=args.debugger,
        poc_script=args.poc or "",
        timeout_per_test=args.timeout,
        qemu_path=args.qemu or "",
        vm_image=args.vm_image or "",
        snapshot_name=args.snapshot,
        windbg_path=args.windbg or "",
    )

    validator = DynamicValidator(val_config)
    dynamic_result = validator.validate_sample(sample, ir)

    print(f"\n  Sandbox used: {dynamic_result.sandbox_used}")
    print(f"  Debugger used: {dynamic_result.debugger_used}")
    print(f"  PoC executed: {dynamic_result.poc_executed}")
    print(f"  Crash detected: {dynamic_result.crash_detected}")
    print(f"  New findings: {len(dynamic_result.new_findings)}")
    print(f"  Validated findings: {len(dynamic_result.findings_validated)}")
    print(f"  Elapsed: {dynamic_result.elapsed:.1f}s")

    if dynamic_result.error:
        print(f"  Error: {dynamic_result.error}")

    # Step 3: Write reports
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_json.dumps({
            "tool": "DEVOPS_driver (dynamic validate)",
            "sample": target.name,
            "static_findings": len(static_findings),
            "dynamic": validator.to_dict(dynamic_result),
            "status": "completed",
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[validate] JSON report written to {out}")

    try:
        from src.report.dynamic_report import generate_dynamic_report
        html_path = (args.output or str(target)).rsplit(".", 1)[0] + "_dynamic.html"
        generate_dynamic_report([validator.to_dict(dynamic_result)], output_path=Path(html_path))
        print(f"[validate] HTML report written to {html_path}")
    except Exception as e:
        print(f"[validate] HTML report generation skipped: {e}")

    return 0


def _run_correlate(args: argparse.Namespace) -> int:
    """Multi-driver correlation analysis."""
    import json as _json

    drivers_dir = Path(args.drivers)
    if not drivers_dir.exists() or not drivers_dir.is_dir():
        print(f"[error] Invalid directory: {drivers_dir}", file=sys.stderr)
        return 1

    driver_files = list(drivers_dir.glob("*.sys"))
    if not driver_files:
        print(f"[error] No .sys files found in {drivers_dir}", file=sys.stderr)
        return 1

    print(f"\n{'=' * 60}")
    print(f"  Multi-Driver Correlation Analysis")
    print(f"  Directory: {drivers_dir}")
    print(f"  Drivers: {len(driver_files)}")
    print(f"{'=' * 60}")

    print(f"\n[correlate] Running multi-driver correlation analysis...")

    from src.models import Sample, Architecture, SignatureStatus
    from src.ingestion.pe_parser import ingest_any_pe
    from src.disassembly import get_backend
    from src.analysis.core.multi_driver_correlator import MultiDriverCorrelator
    from src.analysis.core.protocol_analyzer import ProtocolAnalyzer
    from src.report.attack_graph import build_cross_driver_graph, export_attack_graph, graph_to_dot

    backend = get_backend("capstone")
    samples: list[Sample] = []
    for f in driver_files:
        try:
            sample = ingest_file(f)
            try:
                ir = backend.disassemble(sample)
            except Exception:
                pass  # Sample still usable without disassembly
            samples.append(sample)
        except Exception as e:
            print(f"  [warn] Failed to parse {f.name}: {e}")

    if not samples:
        print("[error] No samples could be parsed.", file=sys.stderr)
        return 1

    # Run correlation analysis
    correlator = MultiDriverCorrelator()
    proto_analyzer = ProtocolAnalyzer()

    corr_findings = correlator.analyze_cluster(samples)
    proto_findings = proto_analyzer.analyze(samples)
    all_findings = corr_findings + proto_findings

    # Build clusters
    clusters = correlator.build_clusters(samples)

    print(f"\n  Cross-driver findings: {len(all_findings)}")
    for cf in all_findings:
        print(f"  [{cf.severity.value}] {cf.description[:100]}")
    print(f"  Driver clusters: {len(clusters)}")
    for c in clusters:
        print(f"    {c.name}: {', '.join(c.members)}")

    if args.output:
        # Generate DOT attack graph from correlation findings
        out_dot = Path(args.output)
        out_dot.parent.mkdir(parents=True, exist_ok=True)
        cross_graph = build_cross_driver_graph(samples, all_findings)
        export_attack_graph(cross_graph, out_dot)
        print(f"\n[correlate] DOT graph written to {out_dot}")

    if args.json:
        out_json = Path(args.json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(_json.dumps({
            "tool": "DEVOPS_driver (correlate)",
            "directory": str(drivers_dir),
            "drivers": len(samples),
            "findings": [f.to_dict() for f in all_findings],
            "clusters": [
                {
                    "name": c.name,
                    "members": c.members,
                    "channels": c.communication_channels,
                }
                for c in clusters
            ],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[correlate] JSON report written to {out_json}")

    return 0


def _run_check_env(args: argparse.Namespace) -> int:
    """Check dynamic analysis environment readiness."""
    from src.analysis.dynamic.sandbox_setup import check_environment
    result = check_environment()
    print(result.summary())
    return 0 if result.overall_ready else 1


if __name__ == "__main__":
    sys.exit(main())
