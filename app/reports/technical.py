"""Detailed technical and audit-oriented GRC PDF report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.data import load_report_snapshot, report_session
from app.reports.styles import (
    LIGHT_BLUE,
    NAVY,
    page_footer,
    report_styles,
    standard_table_style,
    text_paragraph,
)

DEFAULT_TITLE = "Technical Vulnerability and Treatment Report"
DEFAULT_ORGANIZATION = "Demonstration Organization"


def generate_technical_report(
    source,
    output_path: str | Path,
    *,
    scan_id: int | None = None,
    title: str = DEFAULT_TITLE,
    organization: str = DEFAULT_ORGANIZATION,
    generation_date: datetime | None = None,
) -> Path:
    """Generate a detailed PDF from one selected scan without database writes."""
    with report_session(source) as db:
        snapshot = load_report_snapshot(
            db, scan_id=scan_id, generation_date=generation_date
        )
    output = _prepare_output(output_path)
    _build_pdf(output, snapshot, title, organization)
    return output


def _build_pdf(output, snapshot, title, organization) -> None:
    styles = report_styles()
    document = SimpleDocTemplate(
        str(output), pagesize=landscape(A4), leftMargin=14 * mm,
        rightMargin=14 * mm, topMargin=12 * mm, bottomMargin=17 * mm,
        title=title, author=organization,
        subject="Technical GRC findings, alerts, and treatments",
    )
    story = [
        text_paragraph(title, styles["title"]),
        text_paragraph(organization, styles["subtitle"]),
        _metadata(snapshot, styles),
        text_paragraph("Scope and methodology", styles["h1"]),
        text_paragraph(
            "This report reflects OpenVAS findings imported for the selected scan. CVSS represents technical severity. Contextual business risk combines CVSS, asset criticality, and exposure using: risk = (CVSS x criticality x exposure factor / 75) x 100. Exposure factors are internal = 1.0 and external = 1.5. Thresholds are low 0-24.99, medium 25-49.99, high 50-74.99, and critical 75-100.",
            styles["body"],
        ),
        text_paragraph(
            "Automated remediation means creating and tracking a treatment task. It does not patch, isolate, or otherwise change a system automatically.",
            styles["body"],
        ),
        text_paragraph("Asset inventory summary", styles["h1"]),
        _asset_table(snapshot, styles),
        text_paragraph("Detailed prioritized findings", styles["h1"]),
    ]
    for position, finding in enumerate(snapshot.findings, start=1):
        story.extend(_finding_card(position, finding, snapshot, styles))
    story.extend(
        [
            PageBreak(),
            text_paragraph("Alerts", styles["h1"]),
            _alerts_table(snapshot, styles),
            text_paragraph("Treatment plan", styles["h1"]),
            _treatments_table(snapshot, styles),
            text_paragraph("Scan information", styles["h1"]),
            _scan_table(snapshot, styles),
            text_paragraph("Limitations", styles["h1"]),
        ]
    )
    limitations = [
        "This report reflects imported scan data and does not guarantee that every vulnerability has been detected.",
        "Contextual risk depends on the accuracy of asset criticality and exposure classifications.",
        "OpenVAS Community Edition is used in a laboratory or educational environment.",
        "Automated remediation creates tracked tasks and does not execute system changes.",
    ]
    story.extend(text_paragraph(f"- {item}", styles["body"]) for item in limitations)
    footer = page_footer(snapshot.generation_date)
    document.build(story, onFirstPage=footer, onLaterPages=footer)


def _metadata(snapshot, styles):
    rows = [
        ["Generated", snapshot.generation_date.strftime("%Y-%m-%d %H:%M UTC"), "Selected scan", snapshot.scan.scan_date.strftime("%Y-%m-%d %H:%M UTC"), "Source", snapshot.scan.source],
        ["Scan ID", snapshot.scan.id, "Imported relationships", len(snapshot.findings), "Overall posture", snapshot.posture],
    ]
    converted = [[text_paragraph(value, styles["small"]) for value in row] for row in rows]
    table = Table(converted, colWidths=[24 * mm, 52 * mm, 33 * mm, 48 * mm, 28 * mm, 65 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE), ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D2DA")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return table


def _asset_table(snapshot, styles):
    headers = ["Asset", "IP address", "Type", "Owner", "Criticality", "Exposure"]
    rows = [[text_paragraph(value, styles["table_header"]) for value in headers]]
    for asset in snapshot.assets:
        rows.append([text_paragraph(asset[key], styles["table"]) for key in ["asset_name", "ip_address", "asset_type", "owner", "business_criticality", "exposure"]])
    if len(rows) == 1:
        rows.append([text_paragraph("No assets in this scan.", styles["table"]), "", "", "", "", ""])
    table = Table(rows, colWidths=[48 * mm, 34 * mm, 30 * mm, 55 * mm, 25 * mm, 30 * mm], repeatRows=1)
    table.setStyle(standard_table_style())
    return table


def _finding_card(position, finding, snapshot, styles):
    alert = next((item for item in snapshot.alerts if item["finding_id"] == finding["finding_id"]), None)
    treatment = next((item for item in snapshot.treatments if item["finding_id"] == finding["finding_id"]), None)
    score = "Unscored" if finding["contextual_risk_score"] is None else f"{float(finding['contextual_risk_score']):.2f}"
    rows = [
        ["Asset", finding["asset_name"], "IP", finding["ip_address"], "Scan date", _date_time(finding["scan_date"])],
        ["Identity", finding["vulnerability"], "CVSS", f"{float(finding['cvss']):.1f}", "Technical severity", finding["technical_severity"]],
        ["Contextual risk", score, "Risk level", finding["contextual_risk_level"] or "unscored", "Finding status", finding["workflow_status"]],
        ["Asset criticality", finding["business_criticality"], "Exposure", finding["exposure"], "Asset owner", finding["asset_owner"]],
        ["Alert status", "None" if alert is None else ("Acknowledged" if alert["acknowledged"] else "Unacknowledged"), "Treatment owner", treatment["owner"] if treatment else "Unassigned", "Treatment status", treatment["status"] if treatment else "Not created"],
        ["Due date", _date(treatment["due_date"]) if treatment else "Not set", "Overdue", "Yes" if treatment and treatment["overdue"] else "No", "Auto-created", "Yes" if treatment and treatment["auto_created"] else "No"],
    ]
    converted = [[text_paragraph(value, styles["small"]) for value in row] for row in rows]
    table = Table(converted, colWidths=[27 * mm, 54 * mm, 25 * mm, 50 * mm, 31 * mm, 63 * mm])
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C8D2DA")), ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE), ("BACKGROUND", (2, 0), (2, -1), LIGHT_BLUE), ("BACKGROUND", (4, 0), (4, -1), LIGHT_BLUE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
    title = f"{position}. {score} {finding['contextual_risk_level'] or 'unscored'} - {finding['vulnerability']} - {finding['vulnerability_title']}"
    return [
        KeepTogether(
            [
                text_paragraph(title, styles["h2"]),
                table,
                text_paragraph(
                    f"Description: {_shorten(finding['vulnerability_description'], 900)}",
                    styles["body"],
                ),
                text_paragraph(
                    f"OpenVAS solution: {_shorten(finding['solution'], 700)}",
                    styles["body"],
                ),
                Spacer(1, 2 * mm),
            ]
        )
    ]


def _alerts_table(snapshot, styles):
    headers = ["Level", "Message", "Date", "Acknowledged", "Asset", "Vulnerability"]
    rows = [[text_paragraph(value, styles["table_header"]) for value in headers]]
    for alert in snapshot.alerts:
        rows.append([text_paragraph(value, styles["table"]) for value in [alert["level"], _shorten(alert["message"], 300), _date_time(alert["created_at"]), "Yes" if alert["acknowledged"] else "No", alert["asset"], alert["vulnerability"]]])
    if len(rows) == 1:
        rows.append([text_paragraph("No alerts for this scan.", styles["table"]), "", "", "", "", ""])
    table = Table(rows, colWidths=[20 * mm, 105 * mm, 34 * mm, 28 * mm, 40 * mm, 31 * mm], repeatRows=1)
    table.setStyle(standard_table_style())
    return table


def _treatments_table(snapshot, styles):
    headers = ["Asset / vulnerability", "Action", "Owner", "Due", "Status", "Auto", "Evidence / resolution", "Overdue"]
    rows = [[text_paragraph(value, styles["table_header"]) for value in headers]]
    for item in snapshot.treatments:
        evidence = f"{item['evidence'] or 'No evidence'}; resolved: {_date_time(item['resolved_at']) if item['resolved_at'] else 'not resolved'}"
        rows.append([text_paragraph(value, styles["table"]) for value in [f"{item['asset']} | {item['vulnerability']}", _shorten(item["action"], 500), item["owner"], _date(item["due_date"]), item["status"], "Yes" if item["auto_created"] else "No", _shorten(evidence, 350), "Yes" if item["overdue"] else "No"]])
    if len(rows) == 1:
        rows.append([text_paragraph("No treatments for this scan.", styles["table"]), "", "", "", "", "", "", ""])
    table = Table(rows, colWidths=[44 * mm, 70 * mm, 35 * mm, 24 * mm, 24 * mm, 16 * mm, 42 * mm, 18 * mm], repeatRows=1)
    table.setStyle(standard_table_style())
    return table


def _scan_table(snapshot, styles):
    distribution = snapshot.risk_distribution
    average = "Not scored" if snapshot.kpis.average_contextual_risk is None else f"{snapshot.kpis.average_contextual_risk:.2f}"
    rows = [
        ["Scan ID", "Scan date", "Source", "Imported", "Low", "Medium", "High", "Critical", "Unscored", "Average risk"],
        [snapshot.scan.id, _date_time(snapshot.scan.scan_date), snapshot.scan.source, len(snapshot.findings), distribution["low"], distribution["medium"], distribution["high"], distribution["critical"], distribution["unscored"], average],
    ]
    converted = [[text_paragraph(value, styles["table_header"] if row_index == 0 else styles["table"]) for value in row] for row_index, row in enumerate(rows)]
    table = Table(converted, colWidths=[19 * mm, 43 * mm, 28 * mm, 24 * mm, 20 * mm, 22 * mm, 20 * mm, 22 * mm, 23 * mm, 32 * mm], repeatRows=1)
    table.setStyle(standard_table_style())
    return table


def _prepare_output(output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("ab"):
            pass
    except OSError as exc:
        raise OSError(f"Cannot write technical report to '{output}': {exc}") from exc
    return output


def _date(value) -> str:
    return "Not set" if value is None else value.strftime("%Y-%m-%d")


def _date_time(value) -> str:
    return "Not available" if value is None else value.strftime("%Y-%m-%d %H:%M")


def _shorten(value, limit: int) -> str:
    if not value:
        return "Not available"
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
