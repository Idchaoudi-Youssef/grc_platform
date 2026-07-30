"""Deterministic three-page technical governance summary."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.data import load_report_snapshot, report_session
from app.reports.styles import (
    LIGHT_BLUE,
    page_footer,
    report_styles,
    standard_table_style,
    text_paragraph,
)
from dashboard.data import get_top_risky_assets

DEFAULT_TITLE = "Technical GRC Summary Report"
DEFAULT_ORGANIZATION = "Demonstration Organization"
TOP_PRIORITY_LIMIT = 10
TOP_ASSET_LIMIT = 5
THEME_LIMIT = 4


def generate_technical_summary_report(
    source,
    output_path: str | Path,
    *,
    scan_id: int | None = None,
    title: str = DEFAULT_TITLE,
    organization: str = DEFAULT_ORGANIZATION,
    generation_date: datetime | None = None,
    source_finding_count: int | None = None,
) -> Path:
    """Generate an exactly three-page summary without database writes."""
    with report_session(source) as db:
        snapshot = load_report_snapshot(
            db, scan_id=scan_id, generation_date=generation_date
        )
    output = _prepare_output(output_path)
    _build_pdf(output, snapshot, title, organization, source_finding_count)
    return output


def select_summary_priorities(
    findings: list[dict[str, object]],
    *,
    limit: int = TOP_PRIORITY_LIMIT,
) -> list[dict[str, object]]:
    """Return only the highest-priority relationships for the concise report."""
    return findings[:limit]


def recurring_risk_themes(
    findings: list[dict[str, object]],
    *,
    limit: int = THEME_LIMIT,
) -> list[tuple[str, int]]:
    """Group normalized titles into transparent, deterministic themes."""
    counts: Counter[str] = Counter(_theme_for_title(str(row["vulnerability_title"])) for row in findings)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


def _build_pdf(output, snapshot, title, organization, source_finding_count) -> None:
    styles = report_styles()
    document = SimpleDocTemplate(
        str(output),
        pagesize=landscape(A4),
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=11 * mm,
        bottomMargin=17 * mm,
        title=title,
        author=organization,
        subject="Concise technical and governance vulnerability summary",
    )
    priorities = select_summary_priorities(snapshot.findings)
    top_assets = get_top_risky_assets(snapshot.findings)[:TOP_ASSET_LIMIT]
    themes = recurring_risk_themes(snapshot.findings)
    story = [
        *_page_one(
            snapshot,
            styles,
            title,
            organization,
            source_finding_count,
        ),
        PageBreak(),
        *_page_two(snapshot, priorities, top_assets, themes, styles),
        PageBreak(),
        *_page_three(snapshot, themes, styles),
    ]
    footer = page_footer(snapshot.generation_date)
    document.build(story, onFirstPage=footer, onLaterPages=footer)


def _page_one(snapshot, styles, title, organization, source_finding_count):
    technical_distribution = Counter(
        str(row["technical_severity"]) for row in snapshot.findings
    )
    return [
        text_paragraph(title, styles["title"]),
        text_paragraph(organization, styles["subtitle"]),
        _metadata_table(snapshot, styles),
        text_paragraph("Page 1 - Scope and security posture", styles["h1"]),
        text_paragraph(
            f"This report covers scan {snapshot.scan.id} and {len(snapshot.assets)} "
            f"asset(s). Source scanner findings: {_source_count(source_finding_count)}. "
            f"Normalized asset-vulnerability relationships: {len(snapshot.findings)}.",
            styles["body"],
        ),
        _asset_scope_table(snapshot, styles),
        text_paragraph("Methodology", styles["h1"]),
        text_paragraph(
            "OpenVAS CVSS measures technical vulnerability severity. Contextual business "
            "risk re-prioritizes each relationship using the affected asset's business "
            "criticality and exposure.",
            styles["body"],
        ),
        text_paragraph(
            "Contextual risk = (CVSS x criticality x exposure factor / 75) x 100. "
            "Internal exposure uses 1.0 and external exposure uses 1.5. Levels are "
            "low 0-24.99, medium 25-49.99, high 50-74.99, and critical 75-100.",
            styles["body"],
        ),
        text_paragraph("Risk overview", styles["h1"]),
        _risk_kpi_table(snapshot, styles),
        Spacer(1, 2 * mm),
        Table(
            [[
                _distribution_table(
                    "Normalized relationships by technical CVSS severity "
                    f"(n={len(snapshot.findings)})",
                    ["info", "low", "medium", "high", "critical"],
                    technical_distribution,
                    styles,
                ),
                _distribution_table(
                    "Normalized relationships by contextual business risk "
                    f"(n={len(snapshot.findings)})",
                    ["low", "medium", "high", "critical", "unscored"],
                    snapshot.risk_distribution,
                    styles,
                ),
            ]],
            colWidths=[128 * mm, 128 * mm],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]),
        ),
    ]


def _page_two(snapshot, priorities, top_assets, themes, styles):
    return [
        text_paragraph("Technical prioritization", styles["title"]),
        text_paragraph("Page 2 - Prioritization", styles["subtitle"]),
        text_paragraph(
            f"Showing the top {len(priorities)} of {len(snapshot.findings)} normalized "
            "relationships, ordered by contextual risk. Detailed evidence remains in "
            "the separate appendix.",
            styles["body"],
        ),
        _priority_table(priorities, styles),
        text_paragraph("Top risky assets", styles["h1"]),
        _top_assets_table(top_assets, styles),
        text_paragraph("Main recurring risk themes", styles["h1"]),
        _themes_table(themes, styles),
        text_paragraph(
            "Themes are deterministic keyword groupings for triage. They are not AI "
            "conclusions and should be validated by a security analyst.",
            styles["small"],
        ),
    ]


def _page_three(snapshot, themes, styles):
    owners = sorted(
        {
            str(asset["owner"])
            for asset in snapshot.assets
            if asset.get("owner")
        }
    )
    return [
        text_paragraph("Governance and remediation", styles["title"]),
        text_paragraph("Page 3 - Governance and remediation", styles["subtitle"]),
        _governance_kpi_table(snapshot, styles),
        text_paragraph("Ownership", styles["h1"]),
        text_paragraph(
            "Responsible asset owner(s): " + (", ".join(owners[:8]) or "Not assigned"),
            styles["body"],
        ),
        text_paragraph("Recommended remediation roadmap", styles["h1"]),
        _roadmap_table(snapshot, themes, styles),
        text_paragraph("Scan limitations", styles["h1"]),
        text_paragraph(
            "- This report reflects imported OpenVAS results for one selected scan and "
            "does not guarantee complete vulnerability detection.",
            styles["body"],
        ),
        text_paragraph(
            "- Contextual prioritization depends on accurate asset criticality and "
            "exposure classifications. Validate important decisions with asset owners.",
            styles["body"],
        ),
        text_paragraph(
            "- The concise summary omits descriptions, exploit evidence, credentials, "
            "sensitive URLs, and complete technical output. Use the findings appendix "
            "under appropriate access controls.",
            styles["body"],
        ),
        text_paragraph("Automation boundary", styles["h1"]),
        text_paragraph(
            "The platform can create and track alerts and remediation tasks. It does "
            "not automatically patch, isolate, exploit, or otherwise change systems.",
            styles["body"],
        ),
    ]


def _metadata_table(snapshot, styles):
    rows = [
        [
            "Generated",
            snapshot.generation_date.strftime("%Y-%m-%d %H:%M UTC"),
            "Scan ID",
            snapshot.scan.id,
            "Scan date",
            snapshot.scan.scan_date.strftime("%Y-%m-%d %H:%M UTC"),
        ],
        [
            "Source",
            snapshot.scan.source,
            "Normalized relationships",
            len(snapshot.findings),
            "Overall posture",
            snapshot.posture,
        ],
    ]
    converted = [
        [text_paragraph(value, styles["small"]) for value in row] for row in rows
    ]
    table = Table(
        converted,
        colWidths=[24 * mm, 50 * mm, 34 * mm, 35 * mm, 28 * mm, 79 * mm],
    )
    table.setStyle(_metadata_style())
    return table


def _asset_scope_table(snapshot, styles):
    headers = ["Asset", "IP address", "Type", "Owner", "Criticality", "Exposure"]
    rows = [[text_paragraph(value, styles["table_header"]) for value in headers]]
    for asset in snapshot.assets[:8]:
        rows.append([
            text_paragraph(_shorten(asset["asset_name"], 45), styles["table"]),
            text_paragraph(asset["ip_address"], styles["table"]),
            text_paragraph(asset["asset_type"], styles["table"]),
            text_paragraph(_shorten(asset["owner"], 40), styles["table"]),
            text_paragraph(asset["business_criticality"], styles["table"]),
            text_paragraph(asset["exposure"], styles["table"]),
        ])
    table = Table(
        rows,
        colWidths=[55 * mm, 34 * mm, 29 * mm, 54 * mm, 28 * mm, 30 * mm],
        repeatRows=1,
    )
    table.setStyle(standard_table_style(compact=True))
    return table


def _risk_kpi_table(snapshot, styles):
    scores = [
        float(row["contextual_risk_score"])
        for row in snapshot.findings
        if row["contextual_risk_score"] is not None
    ]
    values = [
        (len(snapshot.findings), "Normalized relationships"),
        (
            "Not scored"
            if snapshot.kpis.average_contextual_risk is None
            else f"{snapshot.kpis.average_contextual_risk:.2f}",
            "Average contextual risk",
        ),
        (f"{max(scores):.2f}" if scores else "Not scored", "Maximum contextual risk"),
        (snapshot.risk_distribution["critical"], "Critical contextual risks"),
    ]
    rows = [[
        Table(
            [[
                text_paragraph(value, styles["kpi_value"]),
            ], [
                text_paragraph(label, styles["kpi_label"]),
            ]],
            colWidths=[58 * mm],
        )
        for value, label in values
    ]]
    table = Table(rows, colWidths=[62 * mm] * 4, rowHeights=[20 * mm])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DDE3")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return table


def _distribution_table(title, levels, counts, styles):
    rows = [[
        text_paragraph(title, styles["table_header"]),
        text_paragraph("Count", styles["table_header"]),
    ]]
    for level in levels:
        rows.append([
            text_paragraph(level.title(), styles["table"]),
            text_paragraph(counts.get(level, 0), styles["table"]),
        ])
    table = Table(rows, colWidths=[93 * mm, 28 * mm], repeatRows=1)
    table.setStyle(standard_table_style(compact=True))
    return table


def _priority_table(priorities, styles):
    headers = ["Identity", "Sanitized title", "CVSS", "Risk", "Level", "Asset"]
    rows = [[text_paragraph(value, styles["table_header"]) for value in headers]]
    for item in priorities:
        rows.append([
            text_paragraph(_shorten(item["vulnerability"], 34), styles["table"]),
            text_paragraph(_shorten(item["vulnerability_title"], 62), styles["table"]),
            text_paragraph(f"{float(item['cvss']):.1f}", styles["table"]),
            text_paragraph(_format_score(item["contextual_risk_score"]), styles["table"]),
            text_paragraph(item["contextual_risk_level"] or "unscored", styles["table"]),
            text_paragraph(_shorten(item["asset_name"], 42), styles["table"]),
        ])
    if len(rows) == 1:
        rows.append([text_paragraph("No normalized relationships.", styles["table"]), "", "", "", "", ""])
    table = Table(
        rows,
        colWidths=[38 * mm, 82 * mm, 20 * mm, 23 * mm, 25 * mm, 62 * mm],
        repeatRows=1,
    )
    table.setStyle(standard_table_style(compact=True))
    return table


def _top_assets_table(top_assets, styles):
    headers = ["Asset", "IP address", "Normalized relationships", "Average risk", "Maximum risk"]
    rows = [[text_paragraph(value, styles["table_header"]) for value in headers]]
    for asset in top_assets:
        rows.append([
            text_paragraph(_shorten(asset["asset_name"], 55), styles["table"]),
            text_paragraph(asset["ip_address"], styles["table"]),
            text_paragraph(asset["total_findings"], styles["table"]),
            text_paragraph(_format_score(asset["average_risk_score"]), styles["table"]),
            text_paragraph(_format_score(asset["maximum_risk_score"]), styles["table"]),
        ])
    table = Table(
        rows,
        colWidths=[75 * mm, 42 * mm, 30 * mm, 40 * mm, 40 * mm],
        repeatRows=1,
    )
    table.setStyle(standard_table_style(compact=True))
    return table


def _themes_table(themes, styles):
    rows = [[
        text_paragraph("Theme", styles["table_header"]),
        text_paragraph("Normalized relationships", styles["table_header"]),
    ]]
    rows.extend([
        [
            text_paragraph(theme, styles["table"]),
            text_paragraph(count, styles["table"]),
        ]
        for theme, count in themes
    ])
    table = Table(rows, colWidths=[170 * mm, 45 * mm], repeatRows=1)
    table.setStyle(standard_table_style(compact=True))
    return table


def _governance_kpi_table(snapshot, styles):
    values = [
        (len(snapshot.alerts), "Alerts"),
        (snapshot.kpis.unacknowledged_alerts, "Unacknowledged alerts"),
        (len(snapshot.treatments), "Treatments"),
        (snapshot.kpis.active_treatments, "Active treatments"),
        (
            f"{snapshot.kpis.treatment_completion_percentage:.2f}%",
            "Treatment completion",
        ),
    ]
    rows = [[
        Table(
            [[text_paragraph(value, styles["kpi_value"])],
             [text_paragraph(label, styles["kpi_label"])]],
            colWidths=[44 * mm],
        )
        for value, label in values
    ]]
    table = Table(rows, colWidths=[48 * mm] * 5, rowHeights=[20 * mm])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DDE3")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return table


def _roadmap_table(snapshot, themes, styles):
    has_urgent = bool(
        snapshot.risk_distribution["critical"] or snapshot.risk_distribution["high"]
    )
    immediate = (
        "Validate and assign every high or critical contextual risk; apply approved "
        "mitigations and define near-term verification dates."
        if has_urgent
        else "Validate the highest medium contextual risks and confirm that asset "
        "criticality and exposure accurately reflect business impact."
    )
    theme_names = ", ".join(theme for theme, _count in themes[:3]) or "observed weaknesses"
    rows = [
        ["Horizon", "Recommended action", "Primary responsibility"],
        [
            "Immediate",
            immediate,
            _first_owner(snapshot),
        ],
        [
            "Short-term",
            f"Remediate recurring themes ({theme_names}); assign treatment owners, "
            "deadlines, and validation evidence.",
            "Asset owners and security team",
        ],
        [
            "Medium-term",
            "Harden exposed services, improve patch and lifecycle management, then "
            "rescan and compare risk trends.",
            "Infrastructure, application, and governance leads",
        ],
    ]
    converted = [
        [
            text_paragraph(value, styles["table_header"] if index == 0 else styles["table"])
            for value in row
        ]
        for index, row in enumerate(rows)
    ]
    table = Table(
        converted,
        colWidths=[30 * mm, 145 * mm, 73 * mm],
        repeatRows=1,
    )
    table.setStyle(standard_table_style(compact=True))
    return table


def _theme_for_title(title: str) -> str:
    lowered = title.lower()
    rules = (
        (("credential", "password", "login", "authentication"), "Credentials and authentication"),
        (("ssl", "tls", "cipher", "certificate", "crypto"), "Cryptography and transport security"),
        (("http", "web", "xss", "php", "tomcat"), "Web and application services"),
        (("end of life", "unsupported", "obsolete", "deprecated"), "Lifecycle and unsupported software"),
        (("remote", "service", "port", "network"), "Network-exposed services"),
    )
    for keywords, label in rules:
        if any(keyword in lowered for keyword in keywords):
            return label
    return "Other technical weaknesses"


def _first_owner(snapshot) -> str:
    for asset in snapshot.assets:
        if asset.get("owner"):
            return str(asset["owner"])
    return "Security team"


def _metadata_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D2DA")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])


def _prepare_output(output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("ab"):
            pass
    except OSError as exc:
        raise OSError(f"Cannot write technical summary to '{output}': {exc}") from exc
    return output


def _format_score(value) -> str:
    return "Unscored" if value is None else f"{float(value):.2f}"


def _shorten(value: object, limit: int) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _source_count(value: int | None) -> str:
    return str(value) if value is not None else "Not retained in the current database"
