"""DriverScope — Markdown report generator.

Produces a clean, GitHub-flavored Markdown report suitable for
issues, wikis, and documentation.
"""

from __future__ import annotations

from pathlib import Path

from src.models import Report, score_level


def generate_markdown(report: Report) -> str:
    """Generate a Markdown report from analysis results."""
    lines: list[str] = []

    lines.append("# DriverScope Analysis Report\n")
    lines.append(f"**Version:** {report.tool_version}  |  **Backend:** {report.backend}  |  **Timestamp:** {report.timestamp}\n")

    # Summary
    s = report.summary
    lines.append("## Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Samples analyzed | {report.total_analyzed} |")
    lines.append(f"| Total findings | {report.total_findings} |")
    lines.append(f"| Critical | {s.get('critical_count', 0)} |")
    lines.append(f"| High | {s.get('high_count', 0)} |")
    lines.append(f"| Avg risk score | {s.get('avg_risk_score', 0):.1f}/10 |")
    lines.append(f"| Time | {s.get('total_time', 0)}s |")
    if 'funnel' in s:
        f = s['funnel']
        lines.append(f"| L0 enumerated | {f.get('l0_enumerated', 0)} |")
        lines.append(f"| L4 candidates | {f.get('l4_candidates', 0)} |")
    lines.append("")

    # Top samples
    top = report.top_n(10)
    if top:
        lines.append("## Top Risk Samples\n")
        lines.append("| Rank | Name | Score | Level | Findings |")
        lines.append("|---|---|---|---|---|")
        for i, sample in enumerate(top, 1):
            lines.append(
                f"| {i} | {sample.name} | {sample.risk_score:.1f} | "
                f"{score_level(sample.risk_score)} | {len(sample.analysis_findings)} |"
            )
        lines.append("")

    # Detailed findings per sample
    for sample in top:
        if not sample.analysis_findings:
            continue
        lines.append(f"## {sample.name}\n")
        lines.append(f"**Score:** {sample.risk_score:.1f}/10 ({score_level(sample.risk_score)})  ")
        lines.append(f"**Type:** {sample.driver_type}  ")
        lines.append(f"**SHA256:** `{sample.sha256}`  ")
        if sample.company:
            lines.append(f"**Company:** {sample.company}  ")
        lines.append("")

        # Group findings by severity
        by_severity: dict[str, list] = {}
        for f in sample.analysis_findings:
            by_severity.setdefault(f.severity.value, []).append(f)

        for severity in ("critical", "high", "medium", "low", "info"):
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            lines.append(f"### {severity.upper()} ({len(findings)})\n")
            for f in findings:
                cat = f.category.value.replace("_", " ").title()
                line = f"- **[{cat}]** {f.description}"
                if f.api_name:
                    line += f" (API: `{f.api_name}`)"
                if f.ioctl_code:
                    line += f" (IOCTL: `0x{f.ioctl_code:X}`)"
                lines.append(line)
            lines.append("")

    return "\n".join(lines)


def write_markdown(report: Report, output_path: Path) -> None:
    """Write a Markdown report to file."""
    content = generate_markdown(report)
    output_path.write_text(content, encoding="utf-8")
