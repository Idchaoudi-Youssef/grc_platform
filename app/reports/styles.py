"""Shared ReportLab styles and safe text helpers."""

from __future__ import annotations

from datetime import datetime
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, TableStyle

NAVY = colors.HexColor("#17324D")
TEAL = colors.HexColor("#197A83")
LIGHT_BLUE = colors.HexColor("#EAF2F7")
LIGHT_GREY = colors.HexColor("#F3F5F7")
MID_GREY = colors.HexColor("#697782")
RED = colors.HexColor("#B42318")
ORANGE = colors.HexColor("#C96812")
GREEN = colors.HexColor("#27864A")
WHITE = colors.white


def report_styles() -> dict[str, ParagraphStyle]:
    """Return a compact professional typography set using built-in fonts."""
    sample = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ReportTitle", parent=sample["Title"], fontName="Helvetica-Bold", fontSize=19, leading=22, textColor=NAVY, alignment=TA_LEFT, spaceAfter=4 * mm),
        "subtitle": ParagraphStyle("ReportSubtitle", parent=sample["Normal"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=MID_GREY, spaceAfter=2 * mm),
        "h1": ParagraphStyle("ReportH1", parent=sample["Heading1"], fontName="Helvetica-Bold", fontSize=12, leading=14, textColor=NAVY, spaceBefore=3 * mm, spaceAfter=2 * mm),
        "h2": ParagraphStyle("ReportH2", parent=sample["Heading2"], fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=TEAL, spaceBefore=2 * mm, spaceAfter=1.5 * mm),
        "body": ParagraphStyle("ReportBody", parent=sample["BodyText"], fontName="Helvetica", fontSize=8, leading=10.5, textColor=colors.HexColor("#263746"), spaceAfter=1.5 * mm),
        "small": ParagraphStyle("ReportSmall", parent=sample["BodyText"], fontName="Helvetica", fontSize=6.7, leading=8.2, textColor=colors.HexColor("#263746")),
        "table": ParagraphStyle("ReportTable", parent=sample["BodyText"], fontName="Helvetica", fontSize=6.7, leading=8.2, textColor=colors.HexColor("#263746")),
        "table_header": ParagraphStyle("ReportTableHeader", parent=sample["BodyText"], fontName="Helvetica-Bold", fontSize=6.6, leading=8, textColor=WHITE, alignment=TA_CENTER),
        "kpi_value": ParagraphStyle("KpiValue", parent=sample["Normal"], fontName="Helvetica-Bold", fontSize=15, leading=17, textColor=NAVY, alignment=TA_CENTER),
        "kpi_label": ParagraphStyle("KpiLabel", parent=sample["Normal"], fontName="Helvetica", fontSize=6.5, leading=8, textColor=MID_GREY, alignment=TA_CENTER),
        "center": ParagraphStyle("Center", parent=sample["BodyText"], fontSize=7, leading=9, alignment=TA_CENTER),
    }


def text_paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    """Escape untrusted database text before placing it in a PDF paragraph."""
    if value is None or value == "":
        value = "Not available"
    clean = str(value).replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")
    return Paragraph(escape(clean), style)


def standard_table_style(*, header: bool = True, compact: bool = False) -> TableStyle:
    padding = 2 if compact else 3
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C8D2DA")),
        ("LEFTPADDING", (0, 0), (-1, -1), padding),
        ("RIGHTPADDING", (0, 0), (-1, -1), padding),
        ("TOPPADDING", (0, 0), (-1, -1), padding),
        ("BOTTOMPADDING", (0, 0), (-1, -1), padding),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [WHITE, LIGHT_GREY]),
    ]
    if header:
        commands.extend(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ]
        )
    return TableStyle(commands)


def page_footer(generated_at: datetime):
    """Create a ReportLab page callback with generation time and page number."""
    timestamp = generated_at.strftime("%Y-%m-%d %H:%M UTC")

    def draw(canvas, document) -> None:
        canvas.saveState()
        width, _height = document.pagesize
        canvas.setStrokeColor(colors.HexColor("#D5DDE3"))
        canvas.line(document.leftMargin, 12 * mm, width - document.rightMargin, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MID_GREY)
        canvas.drawString(document.leftMargin, 7.5 * mm, f"Generated {timestamp}")
        canvas.drawRightString(width - document.rightMargin, 7.5 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    return draw
