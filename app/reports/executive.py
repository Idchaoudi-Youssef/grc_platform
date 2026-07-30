"""Professional one-page-oriented executive GRC PDF report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.charts import risk_distribution_chart, top_findings_chart
from app.reports.data import load_report_snapshot, report_session
from app.reports.styles import (
    GREEN,
    LIGHT_BLUE,
    NAVY,
    ORANGE,
    RED,
    TEAL,
    page_footer,
    report_styles,
    standard_table_style,
    text_paragraph,
)

DEFAULT_TITLE = "Executive GRC Risk Report"
DEFAULT_ORGANIZATION = "Demonstration Organization"
TEMP_ROOT = Path("tmp/pdfs")


def generate_executive_report(
    source,
    output_path: str | Path,
    *,
    scan_id: int | None = None,
    title: str = DEFAULT_TITLE,
    organization: str = DEFAULT_ORGANIZATION,
    generation_date: datetime | None = None,
    source_finding_count: int | None = None,
) -> Path:
    """Generate an executive PDF from one selected scan without database writes."""
    with report_session(source) as db:
        snapshot = load_report_snapshot(
            db, scan_id=scan_id, generation_date=generation_date
        )
    output = _prepare_output(output_path)
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="executive_", dir=TEMP_ROOT) as temp_directory:
        temp = Path(temp_directory)
        risk_chart = temp / "risk_distribution.png"
        top_chart = temp / "top_findings.png"
        risk_distribution_chart(snapshot.risk_distribution, risk_chart)
        top_findings_chart(snapshot.priorities, top_chart)
        _build_pdf(
            output,
            snapshot,
            risk_chart,
            top_chart,
            title,
            organization,
            source_finding_count,
        )
    return output


def _build_pdf(
    output,
    snapshot,
    risk_chart,
    top_chart,
    title,
    organization,
    source_finding_count,
) -> None:
    styles = report_styles()
    document = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=13 * mm,
        bottomMargin=17 * mm,
        title=title,
        author=organization,
        subject="Contextual GRC vulnerability posture",
    )
    story = [
        text_paragraph(title, styles["title"]),
        text_paragraph(organization, styles["subtitle"]),
        _metadata_table(snapshot, styles),
        text_paragraph(
            f"Source scanner findings: {_source_count(source_finding_count)}",
            styles["small"],
        ),
        Spacer(1, 2 * mm),
        _posture_banner(snapshot.posture, styles),
        text_paragraph("Executive posture summary", styles["h1"]),
        _kpi_table(snapshot, styles),
        text_paragraph("Top priorities", styles["h1"]),
        _priority_table(snapshot, styles),
        text_paragraph("Risk visuals", styles["h1"]),
        Table(
            [[Image(str(risk_chart), width=86 * mm, height=37 * mm), Image(str(top_chart), width=86 * mm, height=37 * mm)]],
            colWidths=[88 * mm, 88 * mm],
            style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]),
        ),
        text_paragraph(
            "Chart counts represent normalized relationships, not source scanner findings.",
            styles["small"],
        ),
        text_paragraph("Management recommendations", styles["h1"]),
    ]
    story.extend(
        text_paragraph(f"- {recommendation}", styles["body"])
        for recommendation in snapshot.recommendations
    )
    footer = page_footer(snapshot.generation_date)
    document.build(story, onFirstPage=footer, onLaterPages=footer)


def _metadata_table(snapshot, styles):
    rows = [
        [text_paragraph("Generated", styles["small"]), text_paragraph(snapshot.generation_date.strftime("%Y-%m-%d %H:%M UTC"), styles["small"]), text_paragraph("Selected scan", styles["small"]), text_paragraph(snapshot.scan.scan_date.strftime("%Y-%m-%d %H:%M UTC"), styles["small"])],
        [text_paragraph("Scan ID", styles["small"]), text_paragraph(snapshot.scan.id, styles["small"]), text_paragraph("Source", styles["small"]), text_paragraph(snapshot.scan.source, styles["small"])],
    ]
    table = Table(rows, colWidths=[23 * mm, 60 * mm, 24 * mm, 69 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C8D2DA")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return table


def _posture_banner(posture, styles):
    color = {"Critical": RED, "High": ORANGE, "Moderate": TEAL, "Low": GREEN}[posture]
    table = Table([[text_paragraph(f"Overall contextual risk posture: {posture}", styles["h2"])]], colWidths=[176 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.Color(color.red, color.green, color.blue, alpha=0.12)), ("BOX", (0, 0), (-1, -1), 1, color), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return table


def _kpi_table(snapshot, styles):
    kpis = snapshot.kpis
    values = [
        (kpis.total_assets, "Assets in selected scan"),
        (kpis.total_relationships, "Normalized relationships"),
        ("Not scored" if kpis.average_contextual_risk is None else f"{kpis.average_contextual_risk:.2f}", "Average contextual risk"),
        (snapshot.risk_distribution["critical"], "Critical contextual risks"),
        (snapshot.risk_distribution["high"], "High contextual risks"),
        (kpis.unacknowledged_alerts, "Unacknowledged alerts"),
        (sum(bool(item["overdue"]) for item in snapshot.treatments), "Overdue treatments"),
        (f"{kpis.treatment_completion_percentage:.2f}%", "Treatment completion"),
    ]
    cells = [
        [
            text_paragraph(value, styles["kpi_value"]),
            text_paragraph(label, styles["kpi_label"]),
        ]
        for value, label in values
    ]
    rows = [cells[:4], cells[4:]]
    table = Table(rows, colWidths=[44 * mm] * 4, rowHeights=[18 * mm, 18 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.white), ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#D5DDE3")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return table


def _priority_table(snapshot, styles):
    headers = ["Asset", "Identity", "Vulnerability", "Risk", "Owner", "Treatment / next action"]
    rows = [[text_paragraph(item, styles["table_header"]) for item in headers]]
    for item in snapshot.priorities:
        action = item["treatment_status"] or _shorten(str(item["next_action"]), 70)
        rows.append([
            text_paragraph(item["asset_name"], styles["table"]),
            text_paragraph(item["vulnerability"], styles["table"]),
            text_paragraph(_shorten(str(item["vulnerability_title"]), 65), styles["table"]),
            text_paragraph(_format_score(item["contextual_risk_score"]), styles["table"]),
            text_paragraph(item["asset_owner"], styles["table"]),
            text_paragraph(action, styles["table"]),
        ])
    if len(rows) == 1:
        rows.append([text_paragraph("No open normalized relationships for this scan.", styles["table"]), "", "", "", "", ""])
    table = Table(rows, colWidths=[29 * mm, 27 * mm, 41 * mm, 14 * mm, 25 * mm, 40 * mm], repeatRows=1)
    table.setStyle(standard_table_style(compact=True))
    return table


def _prepare_output(output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("ab"):
            pass
    except OSError as exc:
        raise OSError(f"Cannot write executive report to '{output}': {exc}") from exc
    return output


def _format_score(value) -> str:
    return "Unscored" if value is None else f"{float(value):.2f}"


def _shorten(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _source_count(value: int | None) -> str:
    return str(value) if value is not None else "Not retained in the current database"
