"""
DriverScope -- Dynamic Analysis Report.

Generates HTML and JSON reports for dynamic validation results,
including crash information, system changes, and PoC outcomes.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def generate_dynamic_report(
    results: list[dict[str, Any]],
    tool_version: str = "DriverScope",
    output_path: Path | None = None,
) -> str:
    """Generate an HTML report for dynamic analysis results.

    Args:
        results: List of serialized DynamicResult dictionaries.
        tool_version: Tool version string.
        output_path: Optional output path for the HTML file.

    Returns:
        HTML report content.
    """
    total_tests = len(results)
    crashes = sum(1 for r in results if r.get("crash_detected"))
    poc_executed = sum(1 for r in results if r.get("poc_executed"))
    new_findings = sum(len(r.get("new_findings", [])) for r in results)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>DriverScope -- Dynamic Analysis Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }}
.summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
.card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
.card .value {{ font-size: 32px; font-weight: bold; }}
.card .value.crash {{ color: #d32f2f; }}
.card .value.success {{ color: #2e7d32; }}
.card .value.info {{ color: #1976d2; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: white; }}
th {{ background: #0078d4; color: white; padding: 12px; text-align: left; }}
td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
tr:hover {{ background: #f0f7ff; }}
.badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; color: white; }}
.badge.crash {{ background: #d32f2f; }}
.badge.ok {{ background: #2e7d32; }}
.badge.info {{ background: #1976d2; }}
.finding {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
.finding.critical {{ background: #ffebee; border-left-color: #d32f2f; }}
pre {{ background: #263238; color: #eeffff; padding: 15px; border-radius: 4px; overflow-x: auto; }}
</style>
</head>
<body>
<div class="container">
<h1>Dynamic Analysis Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Tool: {tool_version}</p>

<div class="summary">
  <div class="card">
    <h3>Total Tests</h3>
    <div class="value info">{total_tests}</div>
  </div>
  <div class="card">
    <h3>Crashes Detected</h3>
    <div class="value crash">{crashes}</div>
  </div>
  <div class="card">
    <h3>PoC Executed</h3>
    <div class="value success">{poc_executed}</div>
  </div>
  <div class="card">
    <h3>New Findings</h3>
    <div class="value info">{new_findings}</div>
  </div>
</div>

<h2>Test Results</h2>
<table>
<tr><th>Sample</th><th>Sandbox</th><th>Debugger</th><th>PoC</th><th>Crash</th><th>Elapsed</th></tr>
"""

    for r in results:
        crash_badge = '<span class="badge crash">CRASH</span>' if r.get("crash_detected") else '<span class="badge ok">OK</span>'
        poc_badge = '<span class="badge ok">YES</span>' if r.get("poc_executed") else '<span class="badge">NO</span>'
        sandbox_badge = '<span class="badge info">YES</span>' if r.get("sandbox_used") else '<span class="badge">NO</span>'
        debugger_badge = '<span class="badge info">YES</span>' if r.get("debugger_used") else '<span class="badge">NO</span>'

        html += f"""<tr>
<td>{r.get('sample_name', 'unknown')}</td>
<td>{sandbox_badge}</td>
<td>{debugger_badge}</td>
<td>{poc_badge}</td>
<td>{crash_badge}</td>
<td>{r.get('elapsed', 0):.1f}s</td>
</tr>
"""

    html += "</table>\n"

    # New findings section
    all_new = []
    for r in results:
        for f in r.get("new_findings", []):
            all_new.append(f)

    if all_new:
        html += "<h2>New Findings from Dynamic Analysis</h2>\n"
        for f in all_new:
            severity_class = "critical" if f.get("severity") == "critical" else ""
            html += f"""<div class="finding {severity_class}">
<strong>[{f.get('severity', 'unknown').upper()}]</strong> {f.get('category', 'unknown')}
<p>{f.get('description', '')}</p>
</div>
"""

    # System changes section
    changes = [r for r in results if r.get("system_changes")]
    if changes:
        html += "<h2>System Changes</h2>\n<pre>\n"
        for r in changes:
            html += json.dumps(r.get("system_changes", {}), indent=2, ensure_ascii=False) + "\n"
        html += "</pre>\n"

    # Errors
    errors = [r for r in results if r.get("error")]
    if errors:
        html += "<h2>Errors</h2>\n"
        for r in errors:
            html += f'<div class="finding critical"><strong>{r.get("sample_name", "unknown")}</strong>: {r.get("error", "")}</div>\n'

    html += """</div>
</body>
</html>"""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    return html


def generate_dynamic_json(
    results: list[dict[str, Any]],
    tool_version: str = "DriverScope",
) -> str:
    """Generate a JSON report for dynamic analysis results."""
    report = {
        "tool": tool_version,
        "type": "dynamic_analysis",
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tests": len(results),
            "crashes": sum(1 for r in results if r.get("crash_detected")),
            "poc_executed": sum(1 for r in results if r.get("poc_executed")),
            "new_findings": sum(len(r.get("new_findings", [])) for r in results),
        },
        "results": results,
    }
    return json.dumps(report, indent=2, ensure_ascii=False)
