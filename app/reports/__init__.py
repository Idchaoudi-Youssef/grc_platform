"""Read-only executive and technical PDF report generation."""

from app.reports.executive import generate_executive_report
from app.reports.technical import generate_technical_report

__all__ = ["generate_executive_report", "generate_technical_report"]
