"""
llm08_scanner.output_layer.pdf_exporter
=========================================
Builds the PDF report using reportlab.

Changes (depth-test fixes):
  - Finding tables are capped at MAX_ROWS_PER_MODULE (default 20). When cap
    is hit, the surplus is written to a CSV and a "…and N more — see <csv>"
    line is appended to the PDF.
  - export_full_findings_csv() is exported as a public helper so callers can
    trigger it independently if needed.
  - ACL-fuzzer table columns are explicitly proportioned and the verbose
    "reason" column is replaced with a short classification tag.
  - Column widths are proportioned per-module type so no word wraps across
    more than 2 lines at standard page width.
"""

from __future__ import annotations

import csv
import logging
import dataclasses
import math
import os
from pathlib import Path
from typing import Any

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from llm08_scanner.core.scoring_engine import OverallRiskScore
from llm08_scanner.output_layer.remediation_mapper import map_finding_to_remediation

log = logging.getLogger(__name__)

# Default cap: top N rows are shown in the PDF; remainder → CSV
MAX_ROWS_PER_MODULE = 20


# ── Severity helpers ───────────────────────────────────────────────────────────

def _score_to_severity(score: float) -> str:
    """Map numeric score to explicit severity band."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "CLEAN"


# ── Numpy / NaN sanitizer ─────────────────────────────────────────────────────

def _sanitize_finding(obj: Any) -> Any:
    """Recursively strip numpy types and convert dataclasses to standard dicts."""
    if dataclasses.is_dataclass(obj):
        obj = dataclasses.asdict(obj)
    if isinstance(obj, dict):
        return {k: _sanitize_finding(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_finding(v) for v in obj]
    if HAS_NUMPY:
        if isinstance(obj, float) and np.isnan(obj):
            return None
        if hasattr(obj, 'item'):
            val = obj.item()
            if isinstance(val, float) and math.isnan(val):
                return None
            return val
    if isinstance(obj, float) and math.isnan(obj):
        return None
    return obj


# ── ACL classification tag ────────────────────────────────────────────────────

def _acl_reason_tag(reason: str | None) -> str:
    """
    Convert a verbose ACL reason string to a short classification tag.
    Avoids rendering the full sentence in each table row.
    """
    if not reason:
        return "UNKNOWN"
    r = str(reason).upper()
    if "SHARED" in r and "COLLECTION" in r:
        return "SHARED_COLLECTION"
    if "CROSS" in r and "TENANT" in r:
        return "CROSS_TENANT"
    if "UNAUTHORIZED" in r or "AUTH" in r:
        return "UNAUTHORIZED_ACCESS"
    if "NULL" in r or "TOKEN" in r:
        return "NULL_TOKEN"
    # Fallback: first 30 chars
    return str(reason)[:30].upper()


# ── Column width schemes ──────────────────────────────────────────────────────

_USABLE_WIDTH = 460  # points, within letter page with 72pt margins each side


def _col_widths_for_module(module_name: str, headers: list[str]) -> list[float]:
    """
    Return explicit column widths (in points) proportioned to the expected
    content for each module type. Prevents single words from wrapping across
    4-5 lines in narrow auto-sized columns.
    """
    n = len(headers)
    if n == 0:
        return []

    # ACL Fuzzer: 4 name columns + 1 tag column (no "reason" column)
    if "acl_fuzzer" in module_name or all(
        h in headers for h in ("querier_tenant", "target_tenant")
    ):
        # querier_tenant, target_tenant, querier_collection, target_collection, tag
        # Collections can be long (depth_vuln_shared_collection = 29 chars)
        scheme = {
            "querier_tenant": 80,
            "target_tenant": 80,
            "querier_collection": 140,
            "target_collection": 140,
            "tag": 60,
        }
        widths = [scheme.get(h, _USABLE_WIDTH / n) for h in headers]
        # Normalise to usable width
        total = sum(widths)
        return [w * _USABLE_WIDTH / total for w in widths]

    # Drift: vector_id, namespace, mahalanobis_distance, cluster_label, is_outlier
    if "drift" in module_name or "mahalanobis_distance" in headers:
        scheme = {
            "vector_id": 60,
            "namespace": 140,
            "mahalanobis_distance": 90,
            "cluster_label": 70,
            "is_outlier": 70,
        }
        widths = [scheme.get(h, _USABLE_WIDTH / n) for h in headers]
        total = sum(widths)
        return [w * _USABLE_WIDTH / total for w in widths]

    # Inversion: vector_id, namespace, overlap_score / reconstructed_text
    if "inversion" in module_name or "overlap_score" in headers or "reconstructed" in str(headers):
        scheme = {
            "vector_id": 60,
            "namespace": 120,
            "overlap_score": 80,
            "reconstructed_text": 200,
        }
        widths = [scheme.get(h, _USABLE_WIDTH / n) for h in headers]
        total = sum(widths)
        return [w * _USABLE_WIDTH / total for w in widths]

    # Default: equal columns
    return [_USABLE_WIDTH / n] * n


# ── CSV export ─────────────────────────────────────────────────────────────────

def export_full_findings_csv(
    overall_score: OverallRiskScore,
    unique_tech_results: dict[str, Any],
    output_dir: str,
) -> str:
    """
    Write every sanitized finding (all modules, all rows — no cap) to a single
    combined CSV file with a leading `module` column.

    Returns the resolved path of the written CSV.
    """
    os.makedirs(output_dir, exist_ok=True)
    csv_path = str(Path(output_dir) / f"findings_{overall_score.scan_timestamp}.csv")

    rows: list[dict] = []

    all_modules: list[tuple[str, Any]] = [
        (m.module_name, m) for m in overall_score.module_results
    ]
    for tech_name, res in unique_tech_results.items():
        if res:
            all_modules.append((tech_name, res))

    for mod_name, mod in all_modules:
        if not mod.findings:
            continue
        for f in mod.findings:
            san = _sanitize_finding(f)
            if isinstance(san, dict):
                san["module"] = mod_name
                rows.append(san)
            else:
                rows.append({"module": mod_name, "value": str(san)})

    if not rows:
        log.info("No findings to export to CSV.")
        return csv_path

    # Collect all possible keys, module first
    all_keys: list[str] = ["module"]
    seen: set[str] = {"module"}
    for row in rows:
        for k in row:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    log.info("Full findings CSV written to %s (%d rows)", csv_path, len(rows))
    return csv_path


# ── Header/footer canvas callback ─────────────────────────────────────────────

def _header_footer_callback(canvas, doc):
    """Callback for drawing headers and footers on every page."""
    canvas.saveState()
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(72, doc.pagesize[1] - 40, "LLM08 Vector Security Scan Report")
    canvas.setStrokeColor(colors.lightgrey)
    canvas.line(72, doc.pagesize[1] - 45, doc.pagesize[0] - 72, doc.pagesize[1] - 45)
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(doc.pagesize[0] - 72, 30, f"Page {doc.page}")
    canvas.line(72, 40, doc.pagesize[0] - 72, 40)
    canvas.restoreState()


# ── Findings table builder ─────────────────────────────────────────────────────

def _build_finding_table(
    mod_name: str,
    sanitized_findings: list[dict],
    styles_cell,
    max_rows: int,
    csv_path: str | None,
) -> list:
    """
    Build a capped ReportLab table for a single module's findings.
    Returns a list of Story elements (Table + optional overflow note).
    """
    story_elements = []

    if not sanitized_findings:
        return story_elements

    # ACL fuzzer: replace verbose "reason" column with a short classification tag
    if any("querier_tenant" in f for f in sanitized_findings[:1]):
        processed = []
        for f in sanitized_findings:
            row = {k: v for k, v in f.items() if k != "reason"}
            row["tag"] = _acl_reason_tag(f.get("reason"))
            processed.append(row)
        sanitized_findings = processed

    total = len(sanitized_findings)
    capped = sanitized_findings[:max_rows]
    remaining = total - len(capped)

    headers = list(capped[0].keys())
    col_widths = _col_widths_for_module(mod_name, headers)

    wrapped_data = []
    wrapped_data.append([Paragraph(f"<b>{str(h)}</b>", styles_cell) for h in headers])

    for sf in capped:
        row_cells = []
        for h in headers:
            val = sf.get(h)
            cell_str = "None" if val is None else str(val)
            row_cells.append(Paragraph(cell_str, styles_cell))
        wrapped_data.append(row_cells)

    ftable = Table(wrapped_data, colWidths=col_widths, repeatRows=1)
    ftable.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E0E0E0')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    story_elements.append(ftable)

    if remaining > 0:
        overflow_msg = f"… and {remaining} more finding(s) not shown."
        if csv_path:
            overflow_msg += f" Full dataset exported to CSV: {csv_path}"
        from reportlab.lib.styles import getSampleStyleSheet
        note_style = getSampleStyleSheet()['Italic']
        story_elements.append(Spacer(1, 4))
        story_elements.append(Paragraph(overflow_msg, note_style))

    return story_elements


# ── Main export function ──────────────────────────────────────────────────────

def export_pdf(
    filepath: str,
    overall_score: OverallRiskScore,
    unique_tech_results: dict[str, Any],
    heatmap_path: str | None = None,
    max_rows_per_module: int = MAX_ROWS_PER_MODULE,
) -> bool:
    """
    Generates a PDF report.
    Returns True if successful, False if reportlab is missing.

    Args:
        filepath: Output PDF path.
        overall_score: Aggregated scan result.
        unique_tech_results: Results from unique tech modules.
        heatmap_path: Optional path to the 2D projection PNG.
        max_rows_per_module: Cap on table rows per module section in the PDF.
            Rows beyond this cap are written to a companion CSV file in the
            same directory as `filepath`.
    """
    if not HAS_REPORTLAB:
        log.error("reportlab not installed. Cannot generate PDF.")
        return False

    # Determine total finding count and whether CSV is needed
    total_findings = sum(len(m.findings) for m in overall_score.module_results)
    total_findings += sum(
        len(r.findings) for r in unique_tech_results.values() if r and r.findings
    )

    csv_path: str | None = None
    if total_findings > max_rows_per_module:
        output_dir = str(Path(filepath).parent)
        csv_path = export_full_findings_csv(overall_score, unique_tech_results, output_dir)
        log.info(
            "Total findings (%d) exceed per-module cap (%d). Full CSV: %s",
            total_findings, max_rows_per_module, csv_path,
        )

    doc = SimpleDocTemplate(
        filepath, pagesize=letter,
        rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72
    )
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='RiskLevel', parent=styles['Heading1'],
        textColor=colors.red, fontSize=18
    ))
    styles.add(ParagraphStyle(
        name='Remediation', parent=styles['Normal'],
        backColor=colors.lightgrey, spaceAfter=10, leftIndent=10,
        rightIndent=10, spaceBefore=10, borderPadding=10,
        borderColor=colors.grey, borderWidth=0.5
    ))
    styles_cell = ParagraphStyle(
        name='Cell', parent=styles['Normal'],
        fontSize=8, leading=10, wordWrap='CJK'
    )

    Story = []

    # ── Title Page ────────────────────────────────────────────────────────────
    Story.append(Paragraph("LLM08 Vector Database Security Scan", styles['Title']))
    Story.append(Spacer(1, 12))
    Story.append(Paragraph(f"Scan Timestamp: {overall_score.scan_timestamp}", styles['Normal']))
    Story.append(Spacer(1, 24))

    rl_color = (
        colors.red if overall_score.risk_level in ("CRITICAL", "HIGH")
        else colors.orange if overall_score.risk_level == "MEDIUM"
        else colors.green
    )
    styles['RiskLevel'].textColor = rl_color
    Story.append(Paragraph(f"Overall Risk Level: {overall_score.risk_level}", styles['RiskLevel']))
    Story.append(Paragraph(f"Overall Score: {overall_score.overall_score:.1f} / 100", styles['Heading2']))
    Story.append(Spacer(1, 24))

    # ── Executive Summary ─────────────────────────────────────────────────────
    Story.append(Paragraph("Executive Summary", styles['Heading2']))
    Story.append(Paragraph(
        "This report details the security posture of the audited vector database against the OWASP "
        "LLM08 Top 10 vulnerabilities. It rigorously tests for cross-tenant data leakage, embedding "
        "inversion risks, data poisoning, and semantic distribution anomalies.",
        styles['Normal']
    ))
    Story.append(Spacer(1, 12))

    top_modules = sorted(
        [m for m in overall_score.module_results if m.score > 0],
        key=lambda x: x.score, reverse=True
    )[:3]
    if top_modules:
        Story.append(Paragraph("Top Priority Fixes:", styles['Heading4']))
        for m in top_modules:
            Story.append(Paragraph(
                f"• <b>{m.module_name}</b> (Score: {m.score:.1f} — {_score_to_severity(m.score)})",
                styles['Normal']
            ))
        Story.append(Spacer(1, 12))

    Story.append(Paragraph("Findings Summary:", styles['Heading4']))
    for m in overall_score.module_results:
        Story.append(Paragraph(f"• {m.module_name}: {len(m.findings)} finding(s)", styles['Normal']))

    if csv_path:
        Story.append(Spacer(1, 8))
        Story.append(Paragraph(
            f"<i>Total findings ({total_findings}) exceed the per-module PDF cap ({max_rows_per_module} rows). "
            f"Full dataset exported to: {csv_path}</i>",
            styles['Normal']
        ))

    Story.append(Spacer(1, 24))

    # ── Core Modules Summary Table ─────────────────────────────────────────────
    Story.append(Paragraph("Core Module Results", styles['Heading2']))
    table_data = [["Module", "Severity", "Score", "Findings"]]
    for m in overall_score.module_results:
        sev = _score_to_severity(m.score)
        table_data.append([m.module_name, sev, f"{m.score:.1f}", str(len(m.findings))])

    t = Table(table_data, colWidths=[200, 100, 80, 80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0055A4')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    Story.append(t)
    Story.append(Spacer(1, 24))
    Story.append(PageBreak())

    # ── Core Findings & Remediation ───────────────────────────────────────────
    Story.append(Paragraph("Core Findings &amp; Remediation", styles['Heading2']))

    finding_count = 0
    for mod in overall_score.module_results:
        if not mod.findings:
            continue
        finding_count += len(mod.findings)
        Story.append(Paragraph(f"Module: {mod.module_name}", styles['Heading3']))

        rem_text = map_finding_to_remediation(mod.findings[0])
        Story.append(Paragraph(f"<b>Remediation:</b> {rem_text}", styles['Remediation']))
        Story.append(Spacer(1, 8))

        sanitized_findings = [_sanitize_finding(f) for f in mod.findings]
        Story.extend(_build_finding_table(
            mod.module_name, sanitized_findings, styles_cell,
            max_rows=max_rows_per_module, csv_path=csv_path
        ))
        Story.append(Spacer(1, 20))

    if finding_count == 0:
        Story.append(Paragraph("No critical findings in core modules.", styles['Normal']))

    Story.append(PageBreak())

    # ── Supplementary Evidence (Unique Tech) ───────────────────────────────────
    Story.append(Paragraph("Supplementary Evidence (Unique Tech Layer)", styles['Heading2']))
    Story.append(Paragraph(
        "These modules provide advanced simulations and structural checks. "
        "They do not impact the aggregate risk score.",
        styles['Normal']
    ))
    Story.append(Spacer(1, 12))

    for tech_name, res in unique_tech_results.items():
        if not res or not res.findings:
            continue
        Story.append(Paragraph(f"Module: {tech_name}", styles['Heading3']))
        Story.append(Paragraph(f"Score Context: {res.score:.1f}", styles['Normal']))

        rem_text = map_finding_to_remediation(res.findings[0])
        Story.append(Paragraph(f"<b>Recommendation:</b> {rem_text}", styles['Remediation']))
        Story.append(Spacer(1, 8))

        sanitized_findings = [_sanitize_finding(f) for f in res.findings]
        Story.extend(_build_finding_table(
            tech_name, sanitized_findings, styles_cell,
            max_rows=max_rows_per_module, csv_path=csv_path
        ))
        Story.append(Spacer(1, 20))

    # ── Heatmap ───────────────────────────────────────────────────────────────
    if heatmap_path:
        Story.append(PageBreak())
        Story.append(Paragraph("Vector Space Distribution (Heatmap)", styles['Heading2']))
        Story.append(Image(heatmap_path, width=450, height=350))
        Story.append(Paragraph(
            "Anomalies (hollow red stars) indicate vectors flagged by the Drift Detector or Poison Classifier.",
            styles['Normal']
        ))

    doc.build(Story, onFirstPage=_header_footer_callback, onLaterPages=_header_footer_callback)
    return True
