
import hashlib
import json
import re

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def safe_text(value: Any, limit: int = 2000) -> str:
    """Escape untrusted text before inserting it into PDF paragraphs."""
    from xml.sax.saxutils import escape

    if value is None:
        return ""

    return escape(str(value)[:limit])


def build_report_data(incident: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(incident, dict):
        raise TypeError("incident must be a dictionary")

    analysis = incident.get("analysis", {})

    if not isinstance(analysis, dict):
        raise ValueError("Incident analysis must be a dictionary")

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": {
            "id": incident.get("id", ""),
            "subject": incident.get("subject", ""),
            "sender": incident.get("sender", ""),
            "risk_score": incident.get("risk_score", 0),
            "risk_level": incident.get("risk_level", "UNKNOWN"),
            "status": incident.get("status", "UNKNOWN"),
            "created_at": incident.get("created_at", ""),
            "updated_at": incident.get("updated_at", ""),
            "analyst_note": incident.get("analyst_note", ""),
        },
        "findings": analysis.get("findings", []),
        "mitre_techniques": analysis.get("mitre_techniques", []),
        "attachments": analysis.get("attachments", []),
        "authentication": analysis.get("authentication", {}),
    }


def generate_json_report(incident: dict[str, Any]) -> bytes:
    report_data = build_report_data(incident)

    return json.dumps(
        report_data,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")


def generate_pdf_report(incident: dict[str, Any]) -> bytes:
    report_data = build_report_data(incident)
    incident_data = report_data["incident"]

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="PhishGuard SOC Incident Report",
        author="PhishGuard SOC",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=20,
            spaceAfter=12,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#164E63"),
            spaceBefore=12,
            spaceAfter=7,
        )
    )

    story = []

    story.append(Paragraph("PHISHGUARD SOC", styles["ReportTitle"]))
    story.append(
        Paragraph("Security Incident Investigation Report", styles["Heading2"])
    )
    story.append(Spacer(1, 8))

    summary = [
        ["Incident ID", safe_text(incident_data["id"])],
        ["Subject", safe_text(incident_data["subject"])],
        ["Sender", safe_text(incident_data["sender"])],
        ["Risk Score", safe_text(incident_data["risk_score"]) + " / 100"],
        ["Risk Level", safe_text(incident_data["risk_level"])],
        ["Status", safe_text(incident_data["status"])],
        ["Created At", safe_text(incident_data["created_at"])],
        ["Updated At", safe_text(incident_data["updated_at"])],
        ["Generated At", safe_text(report_data["generated_at"])],
    ]

    table = Table(summary, colWidths=[42 * mm, 125 * mm])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E2E8F0")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#172033")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(table)

    story.append(
        Paragraph("Detection Findings", styles["SectionHeading"])
    )

    findings = report_data["findings"]

    if findings:
        for index, finding in enumerate(findings, start=1):
            story.append(
                Paragraph(
                    f"<b>{index}. {safe_text(finding.get('type', 'Unknown'))}</b>",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"Severity: {safe_text(finding.get('severity', 'UNKNOWN'))}",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    safe_text(finding.get("description", "")),
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"Evidence: {safe_text(finding.get('evidence', ''))}",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 7))
    else:
        story.append(Paragraph("No findings recorded.", styles["BodyText"]))

    story.append(
        Paragraph("MITRE ATT&amp;CK Mapping", styles["SectionHeading"])
    )

    techniques = report_data["mitre_techniques"]

    if techniques:
        for technique in techniques:
            story.append(
                Paragraph(
                    f"<b>{safe_text(technique.get('technique_id', ''))} "
                    f"- {safe_text(technique.get('technique_name', ''))}</b>",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"Tactic: {safe_text(technique.get('tactic', ''))}",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 5))
    else:
        story.append(Paragraph("No MITRE mapping recorded.", styles["BodyText"]))

    story.append(
        Paragraph("Attachment Analysis", styles["SectionHeading"])
    )

    attachments = report_data["attachments"]

    if attachments:
        for attachment in attachments:
            story.append(
                Paragraph(
                    f"Filename: {safe_text(attachment.get('filename', 'unknown'))}",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"SHA-256: {safe_text(attachment.get('sha256', ''))}",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"Size: {safe_text(attachment.get('size', 0))} bytes",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 5))
    else:
        story.append(Paragraph("No attachment information.", styles["BodyText"]))

    story.append(
        Paragraph("Authentication Analysis", styles["SectionHeading"])
    )

    authentication = report_data["authentication"]

    if isinstance(authentication, dict) and authentication:
        for key, value in authentication.items():
            story.append(
                Paragraph(
                    f"<b>{safe_text(key)}:</b> {safe_text(value)}",
                    styles["BodyText"],
                )
            )
    else:
        story.append(
            Paragraph("No authentication information recorded.", styles["BodyText"])
        )

    story.append(
        Paragraph("Analyst Notes", styles["SectionHeading"])
    )
    story.append(
        Paragraph(
            safe_text(incident_data["analyst_note"]),
            styles["BodyText"],
        )
    )

    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "Generated by PhishGuard SOC. Findings are heuristic indicators "
            "and require analyst validation.",
            styles["Italic"],
        )
    )

    document.build(story)

    return buffer.getvalue()


def calculate_sha256(content: bytes) -> str:
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")

    return hashlib.sha256(content).hexdigest()
