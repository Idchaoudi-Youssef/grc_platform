"""Generate read-only executive and technical GRC PDF reports."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.reports import generate_executive_report, generate_technical_report  # noqa: E402
from app.reports.data import ReportDataError  # noqa: E402
from dashboard.data import DashboardDatabaseError  # noqa: E402


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate two read-only GRC PDF reports from an existing SQLite database."
    )
    parser.add_argument("--database", required=True, help="Existing SQLite database path")
    parser.add_argument("--output-dir", default="output/pdf", help="Directory for the two report files")
    parser.add_argument("--organization", default="Demonstration Organization")
    parser.add_argument("--scan-id", type=int)
    parser.add_argument("--title", help="Optional common report title prefix")
    parser.add_argument("--generation-date", type=_parse_generation_date)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    output_directory = Path(arguments.output_dir).expanduser().resolve()
    executive_path = output_directory / "executive_report.pdf"
    technical_path = output_directory / "technical_report.pdf"
    executive_title = (
        f"{arguments.title} - Executive Report"
        if arguments.title
        else "Executive GRC Risk Report"
    )
    technical_title = (
        f"{arguments.title} - Technical Report"
        if arguments.title
        else "Technical Vulnerability and Treatment Report"
    )

    try:
        generate_executive_report(
            arguments.database,
            executive_path,
            scan_id=arguments.scan_id,
            title=executive_title,
            organization=arguments.organization,
            generation_date=arguments.generation_date,
        )
        generate_technical_report(
            arguments.database,
            technical_path,
            scan_id=arguments.scan_id,
            title=technical_title,
            organization=arguments.organization,
            generation_date=arguments.generation_date,
        )
    except (DashboardDatabaseError, ReportDataError, OSError) as exc:
        print(f"Report generation failed: {exc}", file=sys.stderr)
        return 1

    print("=== GRC PDF REPORT GENERATION ===")
    print(f"Database (read-only): {Path(arguments.database).resolve()}")
    _print_report_summary("Executive report", executive_path)
    _print_report_summary("Technical report", technical_path)
    print("Database records were not modified.")
    return 0


def _parse_generation_date(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "generation date must be ISO format, for example 2026-04-02T12:00:00+00:00"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _print_report_summary(label: str, path: Path) -> None:
    reader = PdfReader(path)
    print(f"{label}: {path} ({path.stat().st_size} bytes, {len(reader.pages)} pages)")


if __name__ == "__main__":
    raise SystemExit(main())
