"""Transactional database import for normalized OpenVAS parser results."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetVulnerability,
    Scan,
    Severity,
    Vulnerability,
)
from app.parsers.openvas import OpenVASParseResult, ParsedFinding, ParsedSeverity


class ImportResult(BaseModel):
    """Summary of one attempted OpenVAS database import."""

    scan_id: int | None = None
    parsed_findings_count: int = 0
    imported_relationships_count: int = 0
    created_vulnerabilities_count: int = 0
    reused_vulnerabilities_count: int = 0
    skipped_unknown_assets_count: int = 0
    skipped_findings_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    database_failure: bool = False


@dataclass(frozen=True)
class _VulnerabilityIdentity:
    cve_id: str | None
    technical_id: str | None

    @property
    def key(self) -> str:
        return self.cve_id or self.technical_id or ""


SEVERITY_MAP = {
    ParsedSeverity.INFORMATIONAL: Severity.INFO,
    ParsedSeverity.LOW: Severity.LOW,
    ParsedSeverity.MEDIUM: Severity.MEDIUM,
    ParsedSeverity.HIGH: Severity.HIGH,
    ParsedSeverity.CRITICAL: Severity.CRITICAL,
}


def import_openvas_results(
    parse_result: OpenVASParseResult,
    db: Session,
    *,
    scan_date: datetime | None = None,
    source: str = "openvas",
    commit: bool = True,
) -> ImportResult:
    """Store normalized findings atomically without scoring or automation."""
    result = ImportResult(
        parsed_findings_count=len(parse_result.findings),
        warnings=[_format_parser_issue("warning", issue) for issue in parse_result.warnings],
        errors=[_format_parser_issue("error", issue) for issue in parse_result.errors],
    )

    if parse_result.errors and not parse_result.findings:
        result.errors.append("Import rejected because the XML had fatal errors.")
        return result

    normalized_source = source.strip() or "openvas"
    effective_scan_date = _normalize_datetime(scan_date or datetime.now(timezone.utc))

    try:
        scan = Scan(
            scan_date=effective_scan_date,
            source=normalized_source,
            total_vulnerabilities=0,
        )
        db.add(scan)
        db.flush()
        result.scan_id = scan.id

        seen_relationships: set[tuple[int, str]] = set()
        for finding_index, finding in enumerate(parse_result.findings, start=1):
            asset = db.scalar(
                select(Asset).where(Asset.ip_address == finding.host)
            )
            if asset is None:
                result.skipped_unknown_assets_count += 1
                result.skipped_findings_count += 1
                result.warnings.append(
                    f"Finding {finding_index} skipped: no asset matches host '{finding.host}'."
                )
                continue

            relationships_for_finding = 0
            for identity in _finding_identities(finding):
                duplicate_key = (asset.id, identity.key)
                if duplicate_key in seen_relationships:
                    result.warnings.append(
                        f"Finding {finding_index} duplicate ignored for asset "
                        f"{asset.id} and identity '{identity.key}'."
                    )
                    continue

                vulnerability, was_created = _get_or_create_vulnerability(
                    db,
                    identity,
                    finding,
                    normalized_source,
                    effective_scan_date,
                    result.warnings,
                )
                if was_created:
                    result.created_vulnerabilities_count += 1
                else:
                    result.reused_vulnerabilities_count += 1

                db.add(
                    AssetVulnerability(
                        asset=asset,
                        vulnerability=vulnerability,
                        scan=scan,
                        risk_score=None,
                        first_seen_at=effective_scan_date,
                        last_seen_at=effective_scan_date,
                    )
                )
                seen_relationships.add(duplicate_key)
                relationships_for_finding += 1
                result.imported_relationships_count += 1

            if relationships_for_finding == 0:
                result.skipped_findings_count += 1

        scan.total_vulnerabilities = result.imported_relationships_count
        if commit:
            db.commit()
        else:
            db.flush()
        return result
    except SQLAlchemyError as exc:
        db.rollback()
        result.database_failure = True
        result.scan_id = None
        result.imported_relationships_count = 0
        result.created_vulnerabilities_count = 0
        result.reused_vulnerabilities_count = 0
        result.errors.append(f"Database import failed and was rolled back: {exc}")
        return result


def _finding_identities(finding: ParsedFinding) -> list[_VulnerabilityIdentity]:
    if finding.cve_ids:
        return [
            _VulnerabilityIdentity(cve_id=cve_id, technical_id=None)
            for cve_id in finding.cve_ids
        ]
    return [
        _VulnerabilityIdentity(
            cve_id=None,
            technical_id=_build_non_cve_technical_id(finding),
        )
    ]


def _build_non_cve_technical_id(finding: ParsedFinding) -> str:
    if finding.nvt_oid:
        return f"nvt:{finding.nvt_oid}"

    fingerprint_parts = [
        finding.title,
        finding.port or "",
        finding.description or "",
        finding.solution or "",
        finding.threat or "",
    ]
    normalized = "\x1f".join(_normalize_fingerprint_part(part) for part in fingerprint_parts)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"fingerprint:{digest}"


def _normalize_fingerprint_part(value: str) -> str:
    return " ".join(value.lower().split())


def _get_or_create_vulnerability(
    db: Session,
    identity: _VulnerabilityIdentity,
    finding: ParsedFinding,
    source: str,
    detected_at: datetime,
    warnings: list[str],
) -> tuple[Vulnerability, bool]:
    if identity.cve_id is not None:
        query = select(Vulnerability).where(
            Vulnerability.source == source,
            Vulnerability.cve_id == identity.cve_id,
        )
    else:
        query = select(Vulnerability).where(
            Vulnerability.source == source,
            Vulnerability.technical_id == identity.technical_id,
        )

    vulnerability = db.scalar(query)
    if vulnerability is not None:
        _warn_about_metadata_conflict(vulnerability, finding, warnings)
        return vulnerability, False

    vulnerability = Vulnerability(
        cve_id=identity.cve_id,
        technical_id=identity.technical_id,
        cvss_score=finding.cvss_score,
        title=finding.title,
        description=finding.description,
        solution=finding.solution,
        severity=SEVERITY_MAP[finding.severity],
        detected_at=detected_at,
        source=source,
    )
    db.add(vulnerability)
    db.flush()
    return vulnerability, True


def _warn_about_metadata_conflict(
    vulnerability: Vulnerability,
    finding: ParsedFinding,
    warnings: list[str],
) -> None:
    incoming_severity = SEVERITY_MAP[finding.severity]
    conflicting_fields = []
    if vulnerability.title != finding.title:
        conflicting_fields.append("title")
    if vulnerability.description != finding.description:
        conflicting_fields.append("description")
    if vulnerability.solution != finding.solution:
        conflicting_fields.append("solution")
    if vulnerability.cvss_score != finding.cvss_score:
        conflicting_fields.append("cvss_score")
    if vulnerability.severity != incoming_severity:
        conflicting_fields.append("severity")

    if conflicting_fields:
        warnings.append(
            f"Reused vulnerability {vulnerability.id}; preserved its original "
            f"metadata despite differences in: {', '.join(conflicting_fields)}."
        )


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_parser_issue(kind: str, issue) -> str:
    location = f" result {issue.result_index}" if issue.result_index else ""
    return f"Parser {kind}{location}: {issue.message}"
