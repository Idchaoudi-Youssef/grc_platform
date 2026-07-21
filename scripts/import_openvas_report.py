"""Dry-run or explicitly confirm the existing full GRC pipeline for one report."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.lab.report_import import LabImportError, import_report_safely  # noqa: E402


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dry-run an OpenVAS report against a temporary database copy, or explicitly import it.")
    parser.add_argument("xml_report", help="Path to the XML report")
    parser.add_argument("--database", required=True, help="Existing GRC SQLite database path")
    parser.add_argument("--scan-date", type=_parse_datetime, help="Optional ISO-8601 scan date")
    parser.add_argument("--confirm-import", action="store_true", help="Write to the selected database; without this flag the command uses a temporary copy")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        outcome = import_report_safely(
            args.xml_report,
            args.database,
            confirm_import=args.confirm_import,
            scan_date=args.scan_date,
        )
    except LabImportError as exc:
        print(f"Import refused: {exc}", file=sys.stderr)
        return 1
    result = outcome.pipeline_result
    imported = result.import_result.imported_relationships_count if result.import_result else 0
    scored = result.scoring_result.scored_count if result.scoring_result else 0
    automation = result.detection_remediation_result
    print(f"=== OPENVAS {outcome.mode} ===")
    print(f"Selected database: {outcome.database_path}")
    print(f"Pipeline success: {result.success}")
    print(f"Scan ID: {result.scan_id}")
    print(f"Parsed findings: {result.parser_summary.findings_count}")
    print(f"Imported relationships: {imported}")
    print(f"Scored relationships: {scored}")
    print(f"Alerts created: {automation.alerts_created_count if automation else 0}")
    print(f"Treatments created: {automation.treatments_created_count if automation else 0}")
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    for error in result.errors:
        print(f"ERROR: {error}")
    if outcome.mode == "DRY RUN":
        print("Dry run used and removed a temporary database copy; the selected database was not written.")
    else:
        print("Import was explicitly confirmed and the pipeline committed once on success.")
    return 0 if result.success else 1


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("scan date must use ISO-8601 format") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


if __name__ == "__main__":
    raise SystemExit(main())
