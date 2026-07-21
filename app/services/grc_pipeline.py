"""End-to-end orchestration of the first complete GRC pipeline."""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import IO

from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.parsers.openvas import OpenVASParseResult, ParserIssue, parse_openvas
from app.services.detection_remediation import (
    BulkAutomationResult,
    run_detection_remediation,
)
from app.services.openvas_import import ImportResult, import_openvas_results
from app.services.risk_scoring import BulkScoringResult, score_asset_vulnerabilities


class ParserResultSummary(BaseModel):
    """Compact parser information included in a pipeline result."""

    findings_count: int = 0
    warnings_count: int = 0
    errors_count: int = 0


class PipelineResult(BaseModel):
    """Aggregated result of parse, import, score, and automation stages."""

    parser_summary: ParserResultSummary
    import_result: ImportResult | None = None
    scoring_result: BulkScoringResult | None = None
    detection_remediation_result: BulkAutomationResult | None = None
    scan_id: int | None = None
    success: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def run_grc_pipeline(
    xml_source: str | Path | bytes | bytearray | IO[str] | IO[bytes],
    db: Session,
    *,
    scan_date: datetime | None = None,
    source: str = "openvas",
    force_risk_recalculation: bool = False,
    evaluation_date: date | None = None,
) -> PipelineResult:
    """Run the complete M7 workflow as one database transaction."""
    parsed = parse_openvas(xml_source)
    result = PipelineResult(
        parser_summary=_summarize_parser_result(parsed),
        warnings=[_format_parser_issue("warning", issue) for issue in parsed.warnings],
        errors=[_format_parser_issue("error", issue) for issue in parsed.errors],
    )

    if parsed.errors and not parsed.findings:
        db.rollback()
        _append_unique(result.errors, "Pipeline stopped because XML parsing failed.")
        return result

    try:
        import_result = import_openvas_results(
            parsed,
            db,
            scan_date=scan_date,
            source=source,
            commit=False,
        )
        result.import_result = import_result
        result.scan_id = import_result.scan_id
        _extend_unique(result.warnings, import_result.warnings)
        _extend_unique(result.errors, import_result.errors)
        if import_result.database_failure or import_result.scan_id is None:
            db.rollback()
            return result

        scoring_result = score_asset_vulnerabilities(
            db,
            scan_id=import_result.scan_id,
            force=force_risk_recalculation,
            commit=False,
        )
        result.scoring_result = scoring_result
        _extend_unique(result.warnings, scoring_result.warnings)
        _extend_unique(result.errors, scoring_result.errors)
        if scoring_result.database_failure:
            db.rollback()
            return result

        automation_result = run_detection_remediation(
            db,
            scan_id=import_result.scan_id,
            evaluation_date=evaluation_date,
            commit=False,
        )
        result.detection_remediation_result = automation_result
        _extend_unique(result.warnings, automation_result.warnings)
        _extend_unique(result.errors, automation_result.errors)
        if automation_result.database_failure:
            db.rollback()
            return result

        db.commit()
        result.success = (
            scoring_result.failed_count == 0
            and automation_result.failed_count == 0
        )
        if not result.success:
            _append_unique(
                result.errors,
                "Pipeline committed with one or more record-level failures.",
            )
        return result
    except SQLAlchemyError as exc:
        db.rollback()
        result.success = False
        _append_unique(result.errors, f"Pipeline database failure; rolled back: {exc}")
        return result


def _summarize_parser_result(parsed: OpenVASParseResult) -> ParserResultSummary:
    return ParserResultSummary(
        findings_count=len(parsed.findings),
        warnings_count=len(parsed.warnings),
        errors_count=len(parsed.errors),
    )


def _format_parser_issue(kind: str, issue: ParserIssue) -> str:
    location = f" result {issue.result_index}" if issue.result_index else ""
    return f"Parser {kind}{location}: {issue.message}"


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _extend_unique(values: list[str], additions: list[str]) -> None:
    for value in additions:
        _append_unique(values, value)
