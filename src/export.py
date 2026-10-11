"""
Safe Export Utilities
Provides formula-injection-safe CSV export, JSON serialization, and standalone HTML forensic reporting.
"""

import csv
import json
import io
import html
from typing import List, Dict, Any
import pandas as pd


DANGEROUS_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> Any:
    """
    Prevents CSV Formula Injection (DDE attacks).
    Prepends a single apostrophe (') if a string cell starts with dangerous execution characters.
    """
    if isinstance(value, str):
        if value.startswith(DANGEROUS_FORMULA_PREFIXES):
            return f"'{value}"
    return value


def safe_dataframe_to_csv(df: pd.DataFrame) -> str:
    """Exports DataFrame to CSV string with formula injection protection."""
    safe_df = df.copy()
    for col in safe_df.columns:
        if safe_df[col].dtype == object:
            safe_df[col] = safe_df[col].apply(sanitize_csv_cell)
    return safe_df.to_csv(index=False)


def export_report_to_json(report: Dict[str, Any], indent: int = 2) -> str:
    """Serializes investigation report to formatted JSON."""
    return json.dumps(report, indent=indent, default=str)


def generate_html_forensic_report(report: Dict[str, Any]) -> str:
    """
    Generates a standalone, secure, styled HTML digital forensics report.
    Adheres to Navy/Dark Blue design aesthetic with clean typography.
    """
    ex = report.get("executive_summary", {})
    findings = report.get("findings", [])
    timeline = report.get("timeline_key_events", [])
    provenance = report.get("provenance", [])

    findings_html = ""
    for idx, f in enumerate(findings, 1):
        sev_color = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#2563eb",
        }.get(f.get("severity"), "#4b5563")

        sources_html = "".join(
            f"<li><code>{html.escape(s.get('file', ''))}</code> : Line {s.get('line', '')}</li>"
            for s in f.get("evidence_sources", [])[:6]
        )

        findings_html += f"""
        <div class="finding-card" style="border-left: 5px solid {sev_color};">
            <div class="finding-header">
                <h3>#{idx}: {html.escape(f.get('title', ''))}</h3>
                <span class="badge" style="background-color: {sev_color};">{html.escape(f.get('severity', ''))}</span>
            </div>
            <p><strong>Confidence:</strong> <code>{html.escape(f.get('confidence_level', ''))}</code> | <strong>Category:</strong> {html.escape(f.get('category', ''))}</p>
            <p><strong>Time Window:</strong> Relative Seconds {f.get('start_time')} &rarr; {f.get('end_time')}</p>
            <p><strong>Reasoning:</strong> {html.escape(f.get('reason', ''))}</p>
            <p><strong>Involved Hosts:</strong> {html.escape(', '.join(f.get('involved_hosts', [])) or 'None')}</p>
            <p><strong>Involved Users:</strong> {html.escape(', '.join(f.get('involved_users', [])) or 'None')}</p>
            <div class="evidence-box">
                <strong>Supporting Evidence Sources:</strong>
                <ul>{sources_html}</ul>
            </div>
            <p class="rec"><strong>Defensive Recommendation:</strong> {html.escape(f.get('recommendation', ''))}</p>
        </div>
        """

    timeline_rows = ""
    for ev in timeline[:40]:
        timeline_rows += f"""
        <tr>
            <td>{ev.get('timestamp')}</td>
            <td><span class="tag">{html.escape(ev.get('event_type', ''))}</span></td>
            <td>{html.escape(ev.get('action', ''))}</td>
            <td>{html.escape(str(ev.get('user') or '-'))}</td>
            <td>{html.escape(str(ev.get('src_host') or '-'))}</td>
            <td>{html.escape(str(ev.get('dst_host') or '-'))}</td>
            <td><code>{html.escape(str(ev.get('source_file', '')))}:{ev.get('line_number')}</code></td>
        </tr>
        """

    prov_rows = ""
    for p in provenance:
        prov_rows += f"""
        <tr>
            <td><code>{html.escape(p.get('filename', ''))}</code></td>
            <td><code>{html.escape(p.get('sha256_hash', ''))[:24]}...</code></td>
            <td>{p.get('record_count', 0):,}</td>
            <td>{p.get('file_size_bytes', 0):,} bytes</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceMind AI - Forensic Investigation Report</title>
    <style>
        :root {{
            --navy: #0f172a;
            --blue: #1e3a8a;
            --accent: #2563eb;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --muted: #64748b;
            --border: #e2e8f0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: var(--card-bg);
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
            border: 1px solid var(--border);
        }}
        h1, h2, h3 {{
            color: var(--navy);
            margin-top: 1.5em;
            margin-bottom: 0.5em;
        }}
        h1 {{
            margin-top: 0;
            border-bottom: 2px solid var(--border);
            padding-bottom: 12px;
        }}
        .header-meta {{
            color: var(--muted);
            font-size: 0.9em;
            margin-bottom: 24px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: #f1f5f9;
            padding: 16px;
            border-radius: 6px;
            text-align: center;
            border: 1px solid var(--border);
        }}
        .stat-box .num {{
            font-size: 28px;
            font-weight: 700;
            color: var(--blue);
        }}
        .stat-box .label {{
            font-size: 13px;
            color: var(--muted);
            text-transform: uppercase;
        }}
        .finding-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            padding: 18px;
            margin: 16px 0;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.02);
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        .evidence-box {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 12px;
            border-radius: 4px;
            margin: 12px 0;
            font-size: 0.9em;
        }}
        .rec {{
            background: #ecfdf5;
            color: #065f46;
            padding: 10px;
            border-radius: 4px;
            border-left: 4px solid #10b981;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 0.9em;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #f1f5f9;
            color: var(--navy);
            font-weight: 600;
        }}
        .tag {{
            background: #e0e7ff;
            color: #3730a3;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
        }}
        code {{
            background: #f1f5f9;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: Consolas, monospace;
            font-size: 0.88em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>TraceMind AI &mdash; Forensic Investigation Report</h1>
        <div class="header-meta">
            Generated: {html.escape(report.get('metadata', {}).get('generated_at_utc', ''))} |
            Engine: TraceMind AI v1.0.0 | Case Reference: Local Forensics Session
        </div>

        <h2>1. Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="num">{ex.get('total_events_analyzed', 0):,}</div>
                <div class="label">Events Analyzed</div>
            </div>
            <div class="stat-box">
                <div class="num">{ex.get('ground_truth_matches', 0)}</div>
                <div class="label">Ground Truth Confirmed</div>
            </div>
            <div class="stat-box">
                <div class="num">{ex.get('analytical_detections', 0)}</div>
                <div class="label">Analytical Findings</div>
            </div>
            <div class="stat-box">
                <div class="num">{ex.get('duration_seconds', 0):,}s</div>
                <div class="label">Observed Duration</div>
            </div>
        </div>

        <h2>2. Correlated Findings & Evidence</h2>
        {findings_html if findings_html else "<p>No correlated security incidents identified.</p>"}

        <h2>3. Key Evidentiary Event Timeline</h2>
        <table>
            <thead>
                <tr>
                    <th>Time (s)</th>
                    <th>Type</th>
                    <th>Action</th>
                    <th>User</th>
                    <th>Src Host</th>
                    <th>Dst Host</th>
                    <th>Source Reference</th>
                </tr>
            </thead>
            <tbody>
                {timeline_rows if timeline_rows else "<tr><td colspan='7'>No events in timeline</td></tr>"}
            </tbody>
        </table>

        <h2>4. Chain of Custody & File Provenance</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>SHA-256 Digest</th>
                    <th>Record Count</th>
                    <th>File Size</th>
                </tr>
            </thead>
            <tbody>
                {prov_rows if prov_rows else "<tr><td colspan='4'>No files registered</td></tr>"}
            </tbody>
        </table>

        <hr style="margin-top: 40px; border: 0; border-top: 1px solid var(--border);">
        <p style="font-size: 0.8em; color: var(--muted); text-align: center;">
            TraceMind AI Digital Forensics &bull; Confidential Investigation Artifact &bull; Defense Use Only
        </p>
    </div>
</body>
</html>
"""
    return html_content


def _pdf_sanitize(val: Any) -> str:
    """Sanitizes text strings for PDF rendering with standard Latin-1 / ASCII fonts."""
    if val is None:
        return ""
    s = str(val)
    replacements = {
        "\u2014": "-",  # em dash
        "\u2013": "-",  # en dash
        "\u2192": "->", # right arrow
        "\u2190": "<-", # left arrow
        "\u2022": "*",  # bullet
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
        "🛡": "", "⚡": "", "⚠️": "[!]", "🔒": "",
        "📋": "", "🕸": "", "📈": "", "📝": "",
        "⚙": "", "📥": "", "💡": "*", "🎯": "*",
        "✓": "[OK]", "✗": "[X]",
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "replace").decode("latin-1")


def generate_pdf_forensic_report(report: Dict[str, Any]) -> bytes:
    """
    Generates an executive-ready, evidence-grounded PDF Forensic Investigation Report.
    Includes Chain of Custody hashes, Correlated Findings, Timeline, and Defensive Actions.
    """
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError as e:
        raise ImportError("fpdf2 is required for PDF report generation. Run `pip install fpdf2`.") from e

    class ForensicPDF(FPDF):
        def header(self):
            self.set_font("helvetica", "B", 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 5, _pdf_sanitize("TRACEMIND AI  |  DIGITAL FORENSIC INVESTIGATION REPORT"), border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(3)

        def footer(self):
            self.set_y(-12)
            self.set_font("helvetica", "I", 7.5)
            self.set_text_color(148, 163, 184)
            self.cell(0, 8, _pdf_sanitize(f"Page {self.page_no()}/{{nb}}  |  Confidential Forensic Artifact  |  Defensive SOC"), align="C")

    pdf = ForensicPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 12, 15)
    pdf.add_page()

    ex = report.get("executive_summary", {})
    metadata = report.get("metadata", {})
    findings = report.get("findings", [])
    timeline = report.get("timeline_key_events", [])
    provenance = report.get("provenance", [])

    # Title Banner
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(15, 23, 42)  # Dark Navy
    pdf.cell(0, 9, _pdf_sanitize("TraceMind AI - Forensic Investigation Report"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("helvetica", size=9)
    pdf.set_text_color(71, 85, 105)
    meta_line = f"Generated: {metadata.get('generated_at_utc', 'N/A')} UTC | Engine: {metadata.get('tool_name', 'TraceMind AI')} v{metadata.get('version', '1.0.0')}"
    pdf.cell(0, 5, _pdf_sanitize(meta_line), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    notes = metadata.get("analyst_notes")
    if notes:
        pdf.ln(2)
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("helvetica", "I", 8.5)
        pdf.set_text_color(51, 65, 85)
        pdf.multi_cell(pdf.epw, 5, _pdf_sanitize(f"Case / Analyst Notes: {notes}"), border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(4)

    # Section 1: Executive Summary
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 58, 138)  # Deep Navy Blue
    pdf.cell(0, 7, _pdf_sanitize("1. Executive Summary"), border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    time_span_str = f"{ex.get('relative_time_start', 0)} -> {ex.get('relative_time_end', 0)} ({ex.get('duration_seconds', 0):,} sec)"
    summary_rows = [
        ["Metric", "Value", "Metric", "Value"],
        ["Total Events Analyzed", f"{ex.get('total_events_analyzed', 0):,}", "Ground Truth Confirmed", str(ex.get("ground_truth_matches", 0))],
        ["Analytical Findings", str(ex.get("analytical_detections", 0)), "Observed Duration", time_span_str],
        ["Unique Users Identified", str(ex.get("unique_users_count", 0)), "Unique Hosts Identified", str(ex.get("unique_hosts_count", 0))],
    ]
    pdf.set_font("helvetica", size=8.5)
    pdf.set_text_color(30, 41, 59)
    pdf.table(summary_rows, col_widths=(45, 45, 45, 45))

    pdf.ln(4)

    # Section 2: Correlated Findings
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 58, 138)
    pdf.cell(0, 7, _pdf_sanitize(f"2. Correlated Findings & Evidence ({len(findings)})"), border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    if not findings:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, _pdf_sanitize("No security incidents or anomalies correlated in this log segment."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "LOW")
            sev_colors = {
                "CRITICAL": (220, 38, 38),
                "HIGH": (234, 88, 12),
                "MEDIUM": (202, 138, 4),
                "LOW": (37, 99, 235),
            }
            color = sev_colors.get(sev, (71, 85, 105))

            # Header with severity badge
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(15, 23, 42)
            title_text = f"#{idx}: {f.get('title', 'Security Finding')}"
            badge_w = 35
            title_w = pdf.epw - badge_w
            pdf.cell(title_w, 6, _pdf_sanitize(title_text), align="L")
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(*color)
            pdf.cell(badge_w, 6, _pdf_sanitize(f"[{sev}]"), align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Details
            pdf.set_font("helvetica", size=8.5)
            pdf.set_text_color(51, 65, 85)
            detail_line = f"Confidence: {f.get('confidence_level')} | Category: {f.get('category')} | Time Window: {f.get('start_time')}s -> {f.get('end_time')}s"
            pdf.cell(0, 5, _pdf_sanitize(detail_line), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_font("helvetica", "B", 8)
            pdf.cell(0, 4, _pdf_sanitize("Forensic Reasoning:"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=8)
            pdf.multi_cell(pdf.epw, 4, _pdf_sanitize(f.get("reason", "N/A")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            hosts_str = ", ".join(f.get("involved_hosts", [])) or "None"
            users_str = ", ".join(f.get("involved_users", [])) or "None"
            pdf.cell(0, 4, _pdf_sanitize(f"Involved Hosts: {hosts_str} | Involved Users: {users_str}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Evidence sources
            sources = f.get("evidence_sources", [])
            if sources:
                src_txt = ", ".join([f"{s.get('file')}:L{s.get('line')}" for s in sources[:5]])
                pdf.set_font("helvetica", "I", 7.5)
                pdf.cell(0, 4, _pdf_sanitize(f"Evidence Sources: {src_txt}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Recommendation
            rec = f.get("recommendation")
            if rec:
                pdf.set_font("helvetica", "B", 8)
                pdf.set_text_color(22, 101, 52)
                pdf.multi_cell(pdf.epw, 4, _pdf_sanitize(f"Defensive Recommendation: {rec}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.ln(2)

    pdf.ln(2)

    # Section 3: Evidentiary Timeline
    if timeline:
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(30, 58, 138)
        pdf.cell(0, 7, _pdf_sanitize(f"3. Key Evidentiary Event Timeline (Top {min(len(timeline), 30)})"), border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        timeline_rows = [["Time(s)", "Type", "Action", "User", "Src Host", "Dst Host", "Source Ref"]]
        for ev in timeline[:30]:
            timeline_rows.append([
                str(ev.get("timestamp", "-")),
                _pdf_sanitize(ev.get("event_type", "-")[:10]),
                _pdf_sanitize(ev.get("action", "-")[:12]),
                _pdf_sanitize(str(ev.get("user") or "-")[:12]),
                _pdf_sanitize(str(ev.get("src_host") or "-")[:8]),
                _pdf_sanitize(str(ev.get("dst_host") or "-")[:8]),
                _pdf_sanitize(f"{str(ev.get('source_file') or '')[:12]}:{ev.get('line_number', '-')}")
            ])

        pdf.set_font("helvetica", size=7.5)
        pdf.set_text_color(30, 41, 59)
        pdf.table(timeline_rows, col_widths=(18, 24, 28, 28, 24, 24, 34))
        pdf.ln(3)

    # Section 4: Chain of Custody & File Provenance
    if provenance:
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(30, 58, 138)
        pdf.cell(0, 7, _pdf_sanitize("4. Chain of Custody & Cryptographic Provenance"), border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        prov_rows = [["File", "SHA-256 Digest (64 hex)", "Records", "Size"]]
        for p in provenance:
            prov_rows.append([
                _pdf_sanitize(p.get("filename", "-")),
                _pdf_sanitize(p.get("sha256_hash", "-")),
                f"{p.get('record_count', 0):,}",
                f"{p.get('file_size_bytes', 0):,} B",
            ])
        pdf.set_font("helvetica", size=7.5)
        pdf.set_text_color(30, 41, 59)
        pdf.table(prov_rows, col_widths=(35, 95, 25, 25))
        pdf.ln(3)

    # Section 5: Hypotheses & Explanations
    plausible = report.get("plausible_explanations", [])
    alternative = report.get("alternative_explanations", [])
    limitations = report.get("evidence_limitations", [])

    if plausible or alternative or limitations:
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(30, 58, 138)
        pdf.cell(0, 7, _pdf_sanitize("5. Hypotheses, Alternative Explanations & Limitations"), border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        if plausible:
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 5, _pdf_sanitize("Plausible Hypotheses:"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=8)
            for p in plausible:
                pdf.multi_cell(pdf.epw, 4, _pdf_sanitize(f"- {p}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)

        if alternative:
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 5, _pdf_sanitize("Alternative / Benign Explanations:"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=8)
            for a in alternative:
                pdf.multi_cell(pdf.epw, 4, _pdf_sanitize(f"- {a}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1)

        if limitations:
            pdf.set_font("helvetica", "B", 8.5)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 5, _pdf_sanitize("Investigation Boundaries & Limitations:"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", size=8)
            for lim in limitations:
                pdf.multi_cell(pdf.epw, 4, _pdf_sanitize(f"- {lim}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())

