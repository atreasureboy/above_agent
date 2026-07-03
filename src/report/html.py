"""
DriverScope — HTML Report Generator.

Produces a self-contained HTML report with no external dependencies.
Includes summary cards, per-sample finding summaries (grouped by severity),
expandable detail sections, and print-friendly CSS for PDF export.
"""

from __future__ import annotations

import html as html_mod
import re
from collections import defaultdict
from pathlib import Path

from src.models import Finding, Report, Sample, score_level

_SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}

_SEVERITY_BG = {
    "critical": "#f8d7da",
    "high": "#ffe5cc",
    "medium": "#fff3cd",
    "low": "#d1ecf1",
    "info": "#e2e3e5",
}

_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       background: #f5f7fa; color: #333; padding: 20px; }
h1 { font-size: 24px; margin-bottom: 4px; }
h2 { font-size: 18px; margin-bottom: 8px; }
h3 { font-size: 15px; margin-bottom: 4px; }
.subtitle { color: #666; font-size: 14px; margin-bottom: 20px; }
.container { max-width: 1200px; margin: 0 auto; }

/* Search */
.search-bar { margin-bottom: 20px; display: flex; gap: 8px; }
.search-bar input { flex: 1; padding: 10px 14px; border: 1px solid #ddd;
                    border-radius: 6px; font-size: 14px; outline: none; }
.search-bar input:focus { border-color: #0d6efd; box-shadow: 0 0 0 2px rgba(13,110,253,0.15); }
.search-bar .result-count { font-size: 12px; color: #888; align-self: center; padding-left: 8px; }

/* Summary Cards — severity-graded */
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 16px; margin-bottom: 24px; }
.card { background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.card .label { font-size: 12px; color: #888; text-transform: uppercase; margin-bottom: 4px; }
.card .value { font-size: 28px; font-weight: 700; }
.card .value.critical { color: #dc3545; }
.card .value.high { color: #fd7e14; }
.card .value.medium { color: #ffc107; }

/* Severity-colored cards for quick visual scan */
.card.critical-card { border-left: 4px solid #dc3545; }
.card.high-card { border-left: 4px solid #fd7e14; }
.card.medium-card { border-left: 4px solid #ffc107; }

/* Sample Sections */
.sample { background: #fff; border-radius: 8px; margin-bottom: 16px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
.sample-header { padding: 12px 16px; cursor: pointer; display: flex;
                 justify-content: space-between; align-items: center;
                 border-bottom: 1px solid #eee; }
.sample-header:hover { background: #f8f9fa; }
.sample-name { font-weight: 600; font-size: 15px; }
.sample-meta { font-size: 12px; color: #888; }
.score-badge { display: inline-block; padding: 4px 12px; border-radius: 12px;
               font-weight: 600; font-size: 14px; color: #fff; }
.sample-body { padding: 16px; }

/* Finding Summary Groups */
.finding-group { margin-bottom: 10px; border-radius: 6px; overflow: hidden;
                 border-left: 4px solid; }
.finding-group-header { padding: 10px 12px; cursor: pointer; display: flex;
                        justify-content: space-between; align-items: center; }
.finding-group-header:hover { filter: brightness(0.97); }
.finding-group .sev { font-weight: 700; font-size: 11px; text-transform: uppercase; }
.finding-count { font-size: 12px; font-weight: 600; }
.finding-group-detail { padding: 0 12px 10px 12px; display: none; }
.finding-detail { padding: 8px 10px; margin-bottom: 6px; border-radius: 4px;
                  background: rgba(255,255,255,0.6); font-size: 13px; }
.finding-detail .desc { margin-bottom: 4px; }
.finding-detail .evidence { font-family: "Fira Code", "Consolas", monospace;
                            font-size: 11px; background: #f8f9fa; padding: 6px 8px;
                            border-radius: 4px; white-space: pre-wrap; word-break: break-all; }

/* Individual Finding (shown when not grouped or in detail) */
.finding { padding: 10px 12px; margin-bottom: 8px; border-radius: 6px;
           border-left: 4px solid; }
.finding .sev { font-weight: 700; font-size: 11px; text-transform: uppercase; }
.finding .desc { font-size: 13px; margin-top: 4px; }
.finding .evidence { margin-top: 6px; font-family: "Fira Code", "Consolas", monospace;
                     font-size: 11px; background: #f8f9fa; padding: 6px 8px;
                     border-radius: 4px; white-space: pre-wrap; word-break: break-all; }

/* Highlight matched search text */
mark.search-highlight { background: #fff3cd; padding: 0 2px; border-radius: 2px; }

/* Footer */
.footer { text-align: center; color: #999; font-size: 11px; margin-top: 32px; padding: 16px; }

/* Print / PDF */
@media print {
    body { background: #fff; padding: 0; font-size: 12px; }
    .container { max-width: 100%; }
    .sample-header { cursor: default; }
    .sample-header:hover { background: transparent; }
    .sample-body { display: block !important; }
    .finding-group-detail { display: block !important; }
    .summary { grid-template-columns: repeat(3, 1fr); }
    .card { box-shadow: none; border: 1px solid #ddd; }
    a { color: inherit; text-decoration: none; }
    .no-print { display: none; }
}
"""


def _sanitize(text: str) -> str:
    """Strip non-printable characters and ensure clean UTF-8 for HTML output."""
    # Remove control characters except newline/tab
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Replace common problematic Unicode chars with ASCII equivalents
    replacements = {
        "—": "--",   # em-dash
        "–": "-",    # en-dash
        "‘": "'",    # left single quote
        "’": "'",    # right single quote
        "“": '"',    # left double quote
        "”": '"',    # right double quote
        "…": "...",  # ellipsis
        "�": "?",    # replacement character
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text


def generate_html(report: Report) -> str:
    """Generate a self-contained HTML report."""
    samples = sorted(
        [s for s in report.samples if s.risk_score > 0],
        key=lambda s: s.risk_score,
        reverse=True,
    )

    critical_count = sum(1 for s in samples if s.risk_score >= 9.0)
    high_count = sum(1 for s in samples if 7.0 <= s.risk_score < 9.0)
    medium_count = sum(1 for s in samples if 4.0 <= s.risk_score < 7.0)
    avg_score = round(sum(s.risk_score for s in samples) / len(samples), 1) if samples else 0.0

    # Count findings per severity across all samples
    finding_by_severity: dict[str, int] = defaultdict(int)
    for s in samples:
        for f in s.analysis_findings:
            finding_by_severity[f.severity.value] += 1
    total_findings = report.total_findings

    cards_html = _summary_cards(
        total=len(report.samples),
        analyzed=report.total_analyzed,
        critical=critical_count,
        high=high_count,
        medium=medium_count,
        avg_score=avg_score,
        total_findings=total_findings,
        finding_by_severity=dict(finding_by_severity),
    )

    samples_html = ""
    for i, sample in enumerate(samples):
        samples_html += _sample_section(sample, i)

    if not samples_html:
        samples_html = '<div class="card"><p style="color:#888;">No findings detected.</p></div>'

    # Preprocessing section (Phase 0 results)
    pp_html = _preprocessing_section(report.preprocessing_info)

    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>DriverScope Report</title>
<style>{_CSS}</style></head><body>
<div class="container">
  <h1>DriverScope Report</h1>
  <p class="subtitle">{html_mod.escape(_sanitize(report.tool_version))} | {html_mod.escape(_sanitize(report.timestamp))} | Backend: {html_mod.escape(_sanitize(report.backend))}</p>
  <div class="summary">{cards_html}</div>
  {pp_html}
  <div class="search-bar">
    <input type="text" id="search-input" placeholder="Search by driver name, API, finding description…" oninput="doSearch()">
    <span class="result-count" id="search-count"></span>
  </div>
  <div class="no-print" style="text-align:right;margin-bottom:12px;">
    <button onclick="window.print()" style="padding:8px 20px;border-radius:6px;border:1px solid #ccc;background:#fff;cursor:pointer;font-size:13px;">Export PDF (Print)</button>
  </div>
  {samples_html}
  <div class="footer">Generated by DriverScope v{html_mod.escape(_sanitize(report.tool_version))}</div>
</div>
<script>
function doSearch() {{
  var q = document.getElementById('search-input').value.toLowerCase().trim();
  var samples = document.querySelectorAll('.sample');
  var visibleCount = 0;
  var totalFindings = 0;
  samples.forEach(function(s) {{
    if (!q) {{ s.style.display = ''; totalFindings += s.querySelectorAll('.finding-group').length; visibleCount++; return; }}
    var text = s.textContent.toLowerCase();
    var match = text.indexOf(q) >= 0;
    s.style.display = match ? '' : 'none';
    if (match) {{ visibleCount++; }}
  }});
  var countEl = document.getElementById('search-count');
  if (q) {{ countEl.textContent = visibleCount + ' sample(s) match'; }}
  else {{ countEl.textContent = ''; }}
}}
</script>
</body></html>"""
    return body


def _preprocessing_section(pp_info: dict) -> str:
    """Generate HTML section for Phase 0 preprocessing results."""
    if not pp_info:
        return ""

    packer = pp_info.get("packer_name", "")
    was_unpacked = pp_info.get("was_unpacked", False)
    strategy = pp_info.get("strategy", "")
    deobfuscation = pp_info.get("deobfuscation_applied", [])
    anti_evasion = pp_info.get("anti_evasion_patches", [])
    unpacked_path = pp_info.get("unpacked_path", "")
    elapsed = pp_info.get("elapsed", 0.0)

    if not packer and not was_unpacked and not deobfuscation:
        return ""

    rows = []

    if packer:
        rows.append(f'<tr><td><strong>🔒 Packer/Protector</strong></td>'
                    f'<td><span class="tag tag-high">{html_mod.escape(packer)}</span></td></tr>')

    if was_unpacked:
        rows.append(f'<tr><td><strong>📦 Unpacked</strong></td>'
                    f'<td style="color:#00e676;">✓ Yes</td></tr>')
        if unpacked_path:
            rows.append(f'<tr><td><strong>📁 Unpacked Path</strong></td>'
                        f'<td><code>{html_mod.escape(unpacked_path)}</code></td></tr>')
    elif packer:
        rows.append(f'<tr><td><strong>📦 Unpacked</strong></td>'
                    f'<td style="color:#ff5252;">✗ Failed</td></tr>')

    if strategy:
        rows.append(f'<tr><td><strong>🎯 Strategy</strong></td>'
                    f'<td>{html_mod.escape(strategy)}</td></tr>')

    if deobfuscation:
        deobf_text = ", ".join(html_mod.escape(str(d)) for d in deobfuscation)
        rows.append(f'<tr><td><strong>🧩 Deobfuscation</strong></td>'
                    f'<td>{deobf_text}</td></tr>')

    if anti_evasion:
        evasion_text = ", ".join(html_mod.escape(str(e)) for e in anti_evasion)
        rows.append(f'<tr><td><strong>🛡️ Anti-Evasion</strong></td>'
                    f'<td>{evasion_text}</td></tr>')

    if elapsed > 0:
        rows.append(f'<tr><td><strong>⏱️ Elapsed</strong></td>'
                    f'<td>{elapsed:.1f}s</td></tr>')

    if not rows:
        return ""

    table_rows = "\n".join(rows)
    return f"""
  <div class="card" style="border-left:4px solid #9c27b0;">
    <h3 style="color:#ce93d8;">🔧 Phase 0: Preprocessing</h3>
    <table style="width:100%;border-collapse:collapse;">
      {table_rows}
    </table>
  </div>
"""


def _summary_cards(total, analyzed, critical, high, medium, avg_score, total_findings, finding_by_severity=None):
    if finding_by_severity is None:
        finding_by_severity = {}
    sev_cards = ""
    for sev, css_class in (("critical", "critical-card"), ("high", "high-card"), ("medium", "medium-card"), ("low", ""), ("info", "")):
        cnt = finding_by_severity.get(sev, 0)
        if cnt > 0:
            cls = f'card {css_class}' if css_class else 'card'
            sev_cards += f'<div class="{cls}"><div class="label">{sev.capitalize()} Findings</div><div class="value {sev}">{cnt}</div></div>'

    return f"""
<div class="card"><div class="label">Total Samples</div><div class="value">{total}</div></div>
<div class="card"><div class="label">Analyzed</div><div class="value">{analyzed}</div></div>
<div class="card critical-card"><div class="label">Critical Drivers</div><div class="value critical">{critical}</div></div>
<div class="card high-card"><div class="label">High Drivers</div><div class="value high">{high}</div></div>
<div class="card medium-card"><div class="label">Medium Drivers</div><div class="value medium">{medium}</div></div>
<div class="card"><div class="label">Avg Score</div><div class="value">{avg_score}/10</div></div>
{sev_cards}
"""


def _sample_section(sample: Sample, index: int):
    level = score_level(sample.risk_score)
    color = _SEVERITY_COLORS.get(level.lower(), "#666")

    # Build attack chain cards if present
    chains = [f for f in sample.analysis_findings if f.category.value == "attack_chain"
              and f.context.get("chain_type") == "byovd_complete"]
    chain_summary = ""
    if chains:
        cards = []
        for c in chains:
            ctx = c.context
            apis = ctx.get("primitive_apis", [])
            ioctls = ctx.get("ioctl_codes", [])
            missing = ctx.get("missing_checks", [])
            func_addr = c.function_address
            func_name = f"sub_{func_addr:X}" if func_addr else "unknown"
            sev_color = _SEVERITY_COLORS.get(c.severity.value, "#666")
            ovoida = "✓ OVOIDA confirmed" if ctx.get("ovoida_confirmed") or c.context.get("ovoida_session") else "DriverScope only"
            ovoida_color = "#28a745" if "OVOIDA" in ovoida else "#6c757d"

            cards.append(f"""
    <div style="background:#fff;border:1px solid {sev_color};border-left:4px solid {sev_color};border-radius:6px;padding:12px;margin-bottom:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <strong style="color:{sev_color};font-size:14px;">{func_name} — Complete BYOVD Chain</strong>
        <span style="color:{ovoida_color};font-size:11px;font-weight:bold;">{ovoida}</span>
      </div>
      <div style="font-size:12px;color:#555;line-height:1.6;">
        <strong>IOCTLs:</strong> {', '.join(ioctls) if ioctls else 'N/A'}<br/>
        <strong>Dangerous APIs:</strong> {', '.join(apis)}<br/>
        <strong>Missing:</strong> {', '.join(missing) if missing else 'none'}<br/>
        <strong>Severity:</strong> <span style="color:{sev_color};font-weight:bold;">{c.severity.value.upper()}</span>
      </div>
    </div>""")

        chain_summary = f"""
  <div style="margin-bottom:12px;">
    <div style="font-size:13px;font-weight:bold;color:#856404;margin-bottom:6px;">⚠ {len(chains)} BYOVD Attack Chain{"s" if len(chains) != 1 else ""} Detected</div>
    {''.join(cards)}
  </div>"""

    header = f"""
<div class="sample" id="sample-{index}">
  <div class="sample-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
    <div>
      <span class="sample-name">{html_mod.escape(_sanitize(sample.name))}</span>
      <span class="sample-meta"> | {html_mod.escape(_sanitize(sample.company or "Unknown"))} | {html_mod.escape(_sanitize(sample.driver_type or "N/A"))} | {html_mod.escape(_sanitize(sample.arch.value))} | SHA256: {html_mod.escape(_sanitize(sample.sha256[:12]))}…</span>
    </div>
    <span class="score-badge" style="background:{color}">{sample.risk_score:.1f} — {level}</span>
  </div>
  <div class="sample-body">{chain_summary}"""

    findings_html = ""
    if sample.analysis_findings:
        # Group findings by severity
        by_severity: dict[str, list[Finding]] = defaultdict(list)
        for f in sample.analysis_findings:
            by_severity[f.severity.value].append(f)

        # Show severity groups in order: critical, high, medium, low, info
        for sev in ("critical", "high", "medium", "low", "info"):
            findings_in_group = by_severity.get(sev, [])
            if not findings_in_group:
                continue
            sev_color = _SEVERITY_COLORS.get(sev, "#666")
            sev_bg = _SEVERITY_BG.get(sev, "#f0f0f0")
            group_id = f"grp-{index}-{sev}"

            # Group header with count
            findings_html += f"""
<div class="finding-group" style="background:{sev_bg};border-left-color:{sev_color}">
  <div class="finding-group-header" onclick="document.getElementById('{group_id}').style.display = document.getElementById('{group_id}').style.display === 'none' ? 'block' : 'none'">
    <span class="sev" style="color:{sev_color}">{sev.upper()}</span>
    <span class="finding-count">{len(findings_in_group)} finding{"s" if len(findings_in_group) > 1 else ""}</span>
  </div>
  <div class="finding-group-detail" id="{group_id}">"""

            # Detail for each finding
            for f in findings_in_group:
                desc = html_mod.escape(_sanitize(f.description))

                # Build context info
                context_html = ""
                if f.api_name:
                    context_html += f'<span style="color:#d63384;font-weight:600;">API: {html_mod.escape(_sanitize(f.api_name))}</span> '
                if f.function_address:
                    context_html += f'<span style="color:#6c757d;font-family:monospace;">func 0x{f.function_address:X}</span> '
                if f.ioctl_code:
                    context_html += f'<span style="color:#0d6efd;font-family:monospace;">IOCTL 0x{f.ioctl_code:X}</span> '
                if f.context:
                    missing = f.context.get("missing_checks", [])
                    if missing:
                        context_html += f'<span style="color:#dc3545;">Missing: {", ".join(missing)}</span> '

                evidence_html = ""
                for ev in f.evidence:
                    evidence_html += (
                        f'<div class="evidence">'
                        f'<strong>{html_mod.escape(_sanitize(ev.rule_id))}</strong> | '
                        f'{html_mod.escape(_sanitize(ev.location))}: '
                        f'{html_mod.escape(_sanitize(ev.snippet))}</div>'
                    )
                findings_html += f"""
<div class="finding-detail">
  <div class="desc">{desc}</div>
  {context_html}
  {evidence_html}
</div>"""

            findings_html += "</div></div>"
    else:
        findings_html = '<p style="color:#888;font-size:13px;">No findings.</p>'

    footer = """</div></div>"""
    return header + findings_html + footer



def write_html(report: Report, output_path: Path) -> None:
    """Generate and write an HTML report."""
    html_content = generate_html(report)
    output_path.write_text(html_content, encoding="utf-8")
    print(f"[report] HTML report written to {output_path}")
