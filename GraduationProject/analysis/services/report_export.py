"""
Report export service.

Generates downloadable PDF and JSON reports from analysis results.

PDF reports include:
  - File info (name, hash, size, type)
  - Verdict banner with score
  - YARA matches table
  - VT enrichment summary
  - ML classification details
  - Top contributing features
  - Cluster info (if any)

This maps to the "export report" button in the prototype design
and Section 3.2.1.1.10 "Generate Analyst Report" in the report.
"""

import json
import logging
from datetime import datetime
from io import BytesIO

from django.utils import timezone

logger = logging.getLogger("analysis")


def export_as_json(result) -> dict:
    """
    Export a complete analysis report as JSON.

    Returns a dict ready to be serialized as a JSON response.
    """
    file_record = result.file
    features = {}
    try:
        features = file_record.features.data_json
    except Exception:
        pass

    yara_hits = []
    for hit in file_record.yara_hits.all():
        yara_hits.append({
            "rule_name": hit.rule_name,
            "details": hit.details,
        })

    cluster_info = None
    if result.cluster:
        cluster_info = {
            "id": str(result.cluster.id),
            "name": result.cluster.name,
            "size": result.cluster.size,
            "repr_sha256": result.cluster.repr_sha256,
        }

    return {
        "report_id": str(result.id),
        "generated_at": timezone.now().isoformat(),
        "file": {
            "name": file_record.original_name,
            "sha256": file_record.sha256,
            "mime": file_record.mime,
            "size_bytes": file_record.file_size,
            "uploaded_at": file_record.created_at.isoformat(),
        },
        "verdict": {
            "banner": result.banner,
            "ml_label": result.ml_label,
            "ml_score": result.ml_score,
        },
        "evidence": {
            "top_features": result.top_features,
            "yara_hits": yara_hits,
            "vt_summary": result.vt_summary_json,
        },
        "metadata": features.get("metadata", {}),
        "xmp": features.get("xmp", {}),
        "structural": features.get("structural", {}),
        "urls": features.get("urls", []),
        "cluster": cluster_info,
    }


def export_as_pdf(result) -> bytes:
    """
    Export a complete analysis report as a PDF document.

    Uses reportlab to generate a professional-looking report.
    Returns PDF bytes ready to be served as a file download.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable,
        )
    except ImportError:
        logger.error("reportlab not installed — PDF export unavailable")
        return None

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SectionHead",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=6,
        textColor=colors.HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        name="FieldLabel",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#666666"),
    ))
    styles.add(ParagraphStyle(
        name="FieldValue",
        parent=styles["Normal"],
        fontSize=10,
    ))

    elements = []
    file_record = result.file

    # --- Title ---
    elements.append(Paragraph("Malicious Document Detector — Analysis Report", styles["ReportTitle"]))
    elements.append(Paragraph(
        f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["FieldLabel"],
    ))
    elements.append(Spacer(1, 6))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e0e0e0")))
    elements.append(Spacer(1, 10))

    # --- Verdict banner ---
    banner_colors = {
        "clean": "#0F6E56",
        "suspicious": "#854F0B",
        "malicious": "#A32D2D",
        "needs_review": "#185FA5",
    }
    banner_color = banner_colors.get(result.banner, "#333333")
    elements.append(Paragraph(
        f'<font color="{banner_color}" size="14"><b>{result.banner.upper()}</b></font>'
        f'&nbsp;&nbsp;&nbsp;Score: {result.ml_score:.2f} / 1.00',
        styles["FieldValue"],
    ))
    elements.append(Spacer(1, 10))

    # --- File information ---
    elements.append(Paragraph("File information", styles["SectionHead"]))
    file_data = [
        ["Filename", file_record.original_name],
        ["SHA-256", file_record.sha256],
        ["MIME type", file_record.mime],
        ["Size", f"{file_record.file_size:,} bytes ({file_record.file_size / 1024 / 1024:.1f} MB)"],
        ["Uploaded", file_record.created_at.strftime("%Y-%m-%d %H:%M:%S")],
    ]
    t = Table(file_data, colWidths=[100, 400])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)

    # --- Metadata ---
    features = {}
    try:
        features = file_record.features.data_json
    except Exception:
        pass

    metadata = features.get("metadata", {})
    if any(metadata.values()):
        elements.append(Paragraph("Document metadata", styles["SectionHead"]))
        meta_rows = []
        for key in ["title", "author", "creator", "producer", "creation_date"]:
            val = metadata.get(key, "")
            if val:
                meta_rows.append([key.replace("_", " ").title(), str(val)])
        if meta_rows:
            t = Table(meta_rows, colWidths=[100, 400])
            t.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(t)

    # --- XMP identifiers ---
    xmp = features.get("xmp", {})
    if xmp.get("xmp_present"):
        elements.append(Paragraph("XMP identifiers", styles["SectionHead"]))
        xmp_rows = []
        for field in ["document_id", "instance_id", "original_document_id", "creator_tool"]:
            val = xmp.get(field, "")
            if val:
                xmp_rows.append([field.replace("_", " ").title(), str(val)])
        if xmp_rows:
            t = Table(xmp_rows, colWidths=[120, 380])
            t.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(t)

    # --- Top contributing features ---
    if result.top_features:
        elements.append(Paragraph("Detection evidence", styles["SectionHead"]))
        for feat in result.top_features:
            feature_name = feat.get("feature", "")
            detail = feat.get("detail", "")
            weight = feat.get("weight", "")
            elements.append(Paragraph(
                f'<b>{feature_name}</b>: {detail}'
                + (f' <font color="#999999">[{weight}]</font>' if weight else ""),
                styles["FieldValue"],
            ))
            elements.append(Spacer(1, 2))

    # --- YARA matches ---
    yara_hits = list(file_record.yara_hits.all())
    if yara_hits:
        elements.append(Paragraph("YARA matches", styles["SectionHead"]))
        yara_data = [["Rule", "Severity", "Tags"]]
        for hit in yara_hits:
            severity = hit.details.get("severity", "medium")
            tags = ", ".join(hit.details.get("tags", []))
            yara_data.append([hit.rule_name, severity, tags or "—"])
        t = Table(yara_data, colWidths=[200, 80, 220])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f5f5")),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#666666")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("YARA matches", styles["SectionHead"]))
        elements.append(Paragraph("No YARA rules matched.", styles["FieldLabel"]))

    # --- VirusTotal summary ---
    elements.append(Paragraph("VirusTotal enrichment", styles["SectionHead"]))
    vt = result.vt_summary_json
    vt_status = vt.get("enrichment_status", "unavailable")
    if vt_status.startswith("success"):
        vt_rows = [
            ["Malicious", str(vt.get("malicious", 0))],
            ["Suspicious", str(vt.get("suspicious", 0))],
            ["Harmless", str(vt.get("harmless", 0))],
            ["Total engines", str(vt.get("total_engines", 0))],
        ]
        t = Table(vt_rows, colWidths=[100, 400])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph(f"Status: {vt_status}", styles["FieldLabel"]))

    # --- Cluster info ---
    if result.cluster:
        elements.append(Paragraph("Campaign cluster", styles["SectionHead"]))
        cluster_rows = [
            ["Cluster name", result.cluster.name],
            ["Cluster size", str(result.cluster.size)],
            ["Representative hash", result.cluster.repr_sha256[:16] + "..."],
        ]
        t = Table(cluster_rows, colWidths=[120, 380])
        t.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)

    # --- Footer ---
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e0e0e0")))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        "Generated by Malicious Document Detector — Umm Al-Qura University",
        styles["FieldLabel"],
    ))

    # Build PDF
    doc.build(elements)
    return buffer.getvalue()
