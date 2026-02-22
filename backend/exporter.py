"""
Report exporter — converts an AnalysisResult into a downloadable file.

Supported formats
─────────────────
json  — Clean structured report:
          meta (api info) + score summary + findings list.
          Each finding has affected_locations as a flat list of strings
          (no repetitive per-occurrence detail text).

csv   — Two-section flat file:
          Section 1: rule summary — one row per violated rule.
          Section 2: occurrences — one row per location (spreadsheet-friendly).
          Both sections have independent headers so Excel can filter each.

pdf   — Structured PDF: score table, severity breakdown, grouped findings.

Entry point
───────────
    export_result(result, format) -> Response
"""

from __future__ import annotations

import csv
import io
import json
import re
from html import escape

import logging

from fastapi.responses import JSONResponse, Response, StreamingResponse

logger = logging.getLogger(__name__)

from backend.models import AnalysisResult


# ── Severity colour map for PDF ───────────────────────────────────────────────

_SEV_HEX = {
    "critical": "#ffd6d6",
    "high":     "#fff0c0",
    "medium":   "#d6e8ff",
    "low":      "#d6f5e0",
    "info":     "#ebebeb",
}

_GRADE_HEX = {
    "A": "#1a7f37",
    "B": "#3fb950",
    "C": "#d29922",
    "D": "#e3730a",
    "F": "#cf222e",
}

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_filename(name: str) -> str:
    return re.sub(r"[^\w\-]", "-", name).lower().strip("-") or "report"


# ── JSON export ────────────────────────────────────────────────────────────────

def to_json_response(result: AnalysisResult) -> Response:
    """
    Clean structured JSON report — NOT the raw API model.

    Shape
    ─────
    {
      "meta":     { tool, api, api_version, spec_version },
      "score":    { value, grade, rules_violated, total_occurrences },
      "severity_breakdown": { critical, high, medium, low, info },
      "findings": [
        {
          rule_id, rule_name, severity, points_deducted,
          occurrences,        # integer count
          description,        # generic rule-level description
          recommendation,     # shared fix (may be AI-enriched)
          affected_locations  # flat list of path strings — no repetitive detail text
        }, ...
      ]
    }
    """
    bd = result.severity_breakdown
    report = {
        "meta": {
            "tool":         "API Security Analyzer",
            "api":          result.api_title,
            "api_version":  result.api_version,
            "spec_version": result.spec_version,
        },
        "score": {
            "value":             result.score,
            "grade":             result.grade,
            "rules_violated":    f"{result.violated_rules} / 10",
            "total_occurrences": result.total_findings,
        },
        "severity_breakdown": {
            "critical": bd.critical,
            "high":     bd.high,
            "medium":   bd.medium,
            "low":      bd.low,
            "info":     bd.info,
        },
        "findings": [
            {
                "rule_id":            g.rule_id,
                "rule_name":          g.rule_name,
                "severity":           g.severity.value.upper(),
                "points_deducted":    g.points_deducted,
                "occurrences":        g.count,
                "description":        g.description,
                "recommendation":     g.recommendation,
                # Flat list of location strings — no repetitive detail field
                "affected_locations": [o.location for o in g.occurrences],
            }
            for g in result.findings
        ],
    }

    fname = f"security-report-{_safe_filename(result.api_title)}.json"
    return Response(
        content=json.dumps(report, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── CSV export ────────────────────────────────────────────────────────────────

def to_csv_response(result: AnalysisResult) -> StreamingResponse:
    """
    Two-section CSV designed to be usable in Excel / Google Sheets.

    Section 1 — RULE SUMMARY  (one row per violated rule)
      Columns: rule_id, rule_name, severity, points_deducted,
               total_occurrences, description, recommendation

    Section 2 — OCCURRENCES  (one row per location — flat, filterable)
      Columns: rule_id, rule_name, severity, location

    Sections are separated by a blank line so each can be imported
    independently if needed.
    """
    buf = io.StringIO()
    bd = result.severity_breakdown

    # ── Top summary block ──────────────────────────────────────────────────────
    buf.write("# API Security Analyzer Report\n")
    buf.write(f"# API: {result.api_title} {result.api_version}  |  {result.spec_version}\n")
    buf.write(
        f"# Score: {result.score}/100  |  Grade: {result.grade}  |  "
        f"{result.violated_rules}/10 rules violated  |  {result.total_findings} total occurrences\n"
    )
    buf.write(
        f"# Violated rules by severity —  "
        f"CRITICAL: {bd.critical}   HIGH: {bd.high}   "
        f"MEDIUM: {bd.medium}   LOW: {bd.low}   INFO: {bd.info}\n"
    )
    buf.write("#\n\n")

    sorted_groups = sorted(result.findings, key=lambda x: _SEV_ORDER.get(x.severity.value, 99))

    # ── Section 1: Rule summary ────────────────────────────────────────────────
    buf.write("# SECTION 1 — Rule Summary (one row per violated rule)\n")
    s1 = csv.DictWriter(
        buf,
        fieldnames=[
            "rule_id", "rule_name", "severity", "points_deducted",
            "total_occurrences", "description", "recommendation",
        ],
        lineterminator="\n",
    )
    s1.writeheader()
    for g in sorted_groups:
        s1.writerow({
            "rule_id":           g.rule_id,
            "rule_name":         g.rule_name,
            "severity":          g.severity.value.upper(),
            "points_deducted":   g.points_deducted,
            "total_occurrences": g.count,
            "description":       g.description,
            "recommendation":    g.recommendation,
        })

    buf.write("\n\n")

    # ── Section 2: Per-location occurrences ───────────────────────────────────
    buf.write("# SECTION 2 — All Occurrences (one row per location — filter by rule_id or severity)\n")
    s2 = csv.DictWriter(
        buf,
        fieldnames=["rule_id", "rule_name", "severity", "location"],
        lineterminator="\n",
    )
    s2.writeheader()
    for g in sorted_groups:
        for occ in g.occurrences:
            s2.writerow({
                "rule_id":   g.rule_id,
                "rule_name": g.rule_name,
                "severity":  g.severity.value.upper(),
                "location":  occ.location,
            })

    buf.seek(0)
    encoded = buf.getvalue().encode("utf-8")
    fname = f"security-report-{_safe_filename(result.api_title)}.csv"
    return StreamingResponse(
        iter([encoded]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── PDF export ────────────────────────────────────────────────────────────────

def to_pdf_response(result: AnalysisResult) -> Response:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as exc:
        raise ImportError(
            "reportlab is required for PDF export. "
            "Install it with: pip install reportlab"
        ) from exc

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=1.8 * cm, leftMargin=1.8 * cm,
        topMargin=1.8 * cm,   bottomMargin=1.8 * cm,
        title=f"Security Report — {result.api_title}",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=20, spaceAfter=4,
        textColor=colors.HexColor("#0d1117"),
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=13, spaceBefore=14, spaceAfter=6,
        textColor=colors.HexColor("#1f6feb"),
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, leading=13,
        textColor=colors.HexColor("#24292f"),
    )
    mono_style = ParagraphStyle(
        "Mono", parent=body_style,
        fontName="Courier", fontSize=8, leading=11,
        backColor=colors.HexColor("#f6f8fa"),
    )

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("API Security Analyzer Report", title_style))
    story.append(Paragraph(
        f"<b>{escape(result.api_title)}</b>  &nbsp;·&nbsp; "
        f"v{escape(result.api_version)}  &nbsp;·&nbsp; "
        f"{escape(result.spec_version)}",
        body_style,
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#d0d7de")))
    story.append(Spacer(1, 0.3 * cm))

    # ── Score summary ─────────────────────────────────────────────────────────
    story.append(Paragraph("Score Summary", h2_style))

    grade_colour = colors.HexColor(_GRADE_HEX.get(result.grade, "#888888"))
    score_data = [
        ["Score", "Grade", "Rules Violated", "Occurrences", "Operations"],
        [
            f"{result.score} / 100",
            result.grade,
            f"{result.violated_rules} / 10",
            str(result.total_findings),
            str(result.total_operations),
        ],
    ]
    score_table = Table(score_data, colWidths=[3 * cm, 2 * cm, 3.2 * cm, 3 * cm, 3 * cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#1f6feb")),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, 1),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f6f8fa")]),
        ("TEXTCOLOR",     (1, 1), (1, 1),   grade_colour),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.3 * cm))

    # ── Severity breakdown ────────────────────────────────────────────────────
    story.append(Paragraph("Violated Rules by Severity", h2_style))
    bd = result.severity_breakdown
    sev_data = [
        ["Severity",  "Rules Violated"],
        ["CRITICAL",  str(bd.critical)],
        ["HIGH",      str(bd.high)],
        ["MEDIUM",    str(bd.medium)],
        ["LOW",       str(bd.low)],
        ["INFO",      str(bd.info)],
    ]
    sev_colours = ["#ffd6d6", "#fff0c0", "#d6e8ff", "#d6f5e0", "#ebebeb"]
    sev_table = Table(sev_data, colWidths=[4 * cm, 3 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1f6feb")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("ALIGN",        (1, 0), (1, -1),  "CENTER"),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        *[("BACKGROUND", (0, i + 1), (-1, i + 1), colors.HexColor(c))
          for i, c in enumerate(sev_colours)],
    ]))
    story.append(sev_table)

    # ── Findings (grouped) ────────────────────────────────────────────────────
    # Max locations shown per rule in the PDF to avoid page-overflow crashes.
    # Specs like GitHub's have 800+ occurrences of a single rule.
    _PDF_MAX_LOCS = 25

    label_style = ParagraphStyle(
        "Label", parent=body_style,
        fontSize=8, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#57606a"),
    )
    loc_style = ParagraphStyle(
        "Loc", parent=body_style,
        fontName="Courier", fontSize=7, leading=10,
        leftIndent=8,
    )

    if result.findings:
        story.append(Paragraph("Findings", h2_style))

        for idx, g in enumerate(result.findings, 1):
            sev_bg = colors.HexColor(_SEV_HEX.get(g.severity.value, "#ebebeb"))

            # ── Group header row ───────────────────────────────────────────────
            hdr_table = Table([[
                Paragraph(
                    f"<b>{idx}. [{g.severity.value.upper()}]  {escape(g.rule_id)} — "
                    f"{escape(g.rule_name)}</b>  "
                    f"<font size='8' color='#555'>(-{g.points_deducted} pts, "
                    f"{g.count} occurrence(s))</font>",
                    ParagraphStyle("fhdr", parent=body_style, fontSize=9),
                )
            ]], colWidths=[16 * cm])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(hdr_table)

            # ── Description ────────────────────────────────────────────────────
            story.append(Paragraph("<b>Description</b>", label_style))
            story.append(Paragraph(escape(g.description), body_style))
            story.append(Spacer(1, 0.15 * cm))

            # ── Affected locations (capped to avoid page-overflow) ─────────────
            shown = g.occurrences[:_PDF_MAX_LOCS]
            hidden = g.count - len(shown)
            story.append(Paragraph(
                f"<b>Affected locations ({g.count})</b>", label_style
            ))
            for occ in shown:
                story.append(Paragraph(escape(occ.location), loc_style))
            if hidden > 0:
                story.append(Paragraph(
                    f"<i>... and {hidden} more (see JSON/CSV export for full list)</i>",
                    ParagraphStyle("more", parent=body_style, fontSize=7,
                                   textColor=colors.HexColor("#888888"), leftIndent=8),
                ))
            story.append(Spacer(1, 0.15 * cm))

            # ── Recommendation ─────────────────────────────────────────────────
            story.append(Paragraph("<b>Recommendation</b>", label_style))
            story.append(Paragraph(escape(g.recommendation), body_style))
            story.append(Spacer(1, 0.4 * cm))
    else:
        story.append(Paragraph("No findings — this spec passed all security rules.", body_style))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#d0d7de")))
    story.append(Paragraph(
        "Generated by API Security Analyzer · Rules based on OWASP API Security Top 10",
        ParagraphStyle("footer", parent=body_style, fontSize=7,
                       textColor=colors.HexColor("#888888")),
    ))

    doc.build(story)
    pdf_bytes = buf.getvalue()

    fname = f"security-report-{_safe_filename(result.api_title)}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Dispatch ──────────────────────────────────────────────────────────────────

def export_result(result: AnalysisResult, fmt: str) -> Response:
    """
    Dispatch to the correct export handler and always return a ``Response``
    subclass.  All three branches are now uniform so endpoints can be typed
    ``-> Response`` rather than ``-> Any``.

    json  → JSONResponse  (AnalysisResult serialised via model_dump)
    csv   → StreamingResponse  (two-section CSV file download)
    pdf   → Response  (PDF bytes download)
    """
    fmt = (fmt or "json").lower()
    if fmt == "csv":
        return to_csv_response(result)
    if fmt == "pdf":
        return to_pdf_response(result)
    # json (default): serialise the Pydantic model with mode="json" so that
    # enum values become strings, datetimes become ISO strings, etc.
    # The client-side JSON *download* in app.js builds its own clean report
    # from the already-received data — no separate Content-Disposition round-trip.
    return JSONResponse(content=result.model_dump(mode="json"))
