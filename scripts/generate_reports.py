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

from app.reports import (  # noqa: E402
    generate_executive_report,
    generate_technical_findings_appendix,
    generate_technical_summary_report,
)
from app.reports.data import ReportDataError  # noqa: E402
from dashboard.data import DashboardDatabaseError  # noqa: E402


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate three read-only GRC PDF reports from an existing SQLite database."
    )
    parser.add_argument("--database", required=True, help="Existing SQLite database path")
    parser.add_argument(
        "--output-dir",
        default="output/pdf",
        help="Directory for the three report files",
    )
    parser.add_argument("--organization", default="Demonstration Organization")
    parser.add_argument("--scan-id", type=int)
    parser.add_argument(
        "--source-finding-count",
        type=_nonnegative_integer,
        help=(
            "Original scanner result count. If omitted, reports state that this "
            "value was not retained in the database."
        ),
    )
    parser.add_argument("--title", help="Optional common report title prefix")
    parser.add_argument("--generation-date", type=_parse_generation_date)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    output_directory = Path(arguments.output_dir).expanduser().resolve()
    executive_path = output_directory / "executive_report.pdf"
    summary_path = output_directory / "technical_summary_report.pdf"
    appendix_path = output_directory / "technical_findings_appendix.pdf"
    executive_title = (
        f"{arguments.title} - Executive Report"
        if arguments.title
        else "Executive GRC Risk Report"
    )
    summary_title = (
        f"{arguments.title} - Technical Summary"
        if arguments.title
        else "Technical GRC Summary Report"
    )
    appendix_title = (
        f"{arguments.title} - Technical Findings Appendix"
        if arguments.title
        else "Technical Findings Appendix"
    )

    try:
        generate_executive_report(
            arguments.database,
            executive_path,
            scan_id=arguments.scan_id,
            title=executive_title,
            organization=arguments.organization,
            generation_date=arguments.generation_date,
            source_finding_count=arguments.source_finding_count,
        )
        generate_technical_summary_report(
            arguments.database,
            summary_path,
            scan_id=arguments.scan_id,
            title=summary_title,
            organization=arguments.organization,
            generation_date=arguments.generation_date,
            source_finding_count=arguments.source_finding_count,
        )
        generate_technical_findings_appendix(
            arguments.database,
            appendix_path,
            scan_id=arguments.scan_id,
            title=appendix_title,
            organization=arguments.organization,
            generation_date=arguments.generation_date,
            source_finding_count=arguments.source_finding_count,
        )
    except (DashboardDatabaseError, ReportDataError, OSError) as exc:
        print(f"Report generation failed: {exc}", file=sys.stderr)
        return 1

    print("=== GRC PDF REPORT GENERATION ===")
    print(f"Database (read-only): {Path(arguments.database).resolve()}")
    _print_report_summary("Executive report", executive_path)
    _print_report_summary("Technical summary", summary_path)
    _print_report_summary("Technical findings appendix", appendix_path)
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


def _nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _print_report_summary(label: str, path: Path) -> None:
    reader = PdfReader(path)
    print(f"{label}: {path} ({path.stat().st_size} bytes, {len(reader.pages)} pages)")


if __name__ == "__main__":
    raise SystemExit(main())
