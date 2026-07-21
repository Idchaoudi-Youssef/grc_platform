"""Shared read-only data snapshot for PDF reports."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import FindingStatus, Scan
from app.services.risk_scoring import RiskLevel
from dashboard.data import (
    DashboardFilters,
    DashboardKpis,
    aggregate_risk_levels,
    calculate_kpis,
    get_alerts,
    get_findings,
    get_treatments,
    read_only_session,
)


class ReportDataError(RuntimeError):
    """Raised when a report cannot obtain a meaningful data snapshot."""


class EmptyReportDatabaseError(ReportDataError):
    """Raised when no scan exists in the selected database."""


class UnknownScanError(ReportDataError):
    """Raised when an explicitly selected scan does not exist."""


@dataclass(frozen=True)
class ScanSnapshot:
    id: int
    scan_date: datetime
    source: str
    total_vulnerabilities: int


@dataclass(frozen=True)
class ReportSnapshot:
    """All values needed by both report formats, detached from SQLAlchemy."""

    scan: ScanSnapshot
    generation_date: datetime
    findings: list[dict[str, object]]
    assets: list[dict[str, object]]
    alerts: list[dict[str, object]]
    treatments: list[dict[str, object]]
    kpis: DashboardKpis
    risk_distribution: dict[str, int]
    posture: str
    priorities: list[dict[str, object]]
    recommendations: list[str]


@contextmanager
def report_session(source: Session | str | Path) -> Iterator[Session]:
    """Use an existing session or open an existing SQLite file read-only."""
    if isinstance(source, Session):
        yield source
        return
    with read_only_session(source) as db:
        yield db


def load_report_snapshot(
    db: Session,
    *,
    scan_id: int | None = None,
    generation_date: datetime | None = None,
) -> ReportSnapshot:
    """Select one scan and calculate deterministic report data without writes."""
    scan = _select_scan(db, scan_id)
    filters = DashboardFilters(scan_ids=frozenset({scan.id}))
    findings = get_findings(db, filters)
    generated_at = generation_date or datetime.now(timezone.utc)
    alerts = get_alerts(db, findings)
    treatments = get_treatments(db, findings, as_of=generated_at.date())
    kpis = calculate_kpis(db, findings, filters)
    distribution = aggregate_risk_levels(findings)
    posture = classify_posture(findings)
    priorities = select_top_priorities(findings, treatments)
    assets = _asset_inventory(findings)
    recommendations = management_recommendations(
        findings, treatments, distribution
    )
    return ReportSnapshot(
        scan=ScanSnapshot(
            id=scan.id,
            scan_date=scan.scan_date,
            source=scan.source,
            total_vulnerabilities=scan.total_vulnerabilities,
        ),
        generation_date=generated_at,
        findings=findings,
        assets=assets,
        alerts=alerts,
        treatments=treatments,
        kpis=kpis,
        risk_distribution=distribution,
        posture=posture,
        priorities=priorities,
        recommendations=recommendations,
    )


def classify_posture(findings: list[dict[str, object]]) -> str:
    """Classify overall posture from open contextual risks using fixed rules."""
    open_levels = {
        str(row["contextual_risk_level"])
        for row in findings
        if row["workflow_status"]
        in {FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value}
        and row["contextual_risk_level"] is not None
    }
    if RiskLevel.CRITICAL.value in open_levels:
        return "Critical"
    if RiskLevel.HIGH.value in open_levels:
        return "High"
    if RiskLevel.MEDIUM.value in open_levels:
        return "Moderate"
    return "Low"


def select_top_priorities(
    findings: list[dict[str, object]],
    treatments: list[dict[str, object]],
    *,
    limit: int = 5,
) -> list[dict[str, object]]:
    """Return the highest scored open findings and their next action."""
    treatment_by_finding = {
        int(item["finding_id"]): item for item in treatments
    }
    open_findings = [
        row
        for row in findings
        if row["workflow_status"]
        in {FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value}
    ]
    priorities = []
    for row in open_findings[:limit]:
        treatment = treatment_by_finding.get(int(row["finding_id"]))
        priorities.append(
            {
                **row,
                "treatment_status": treatment["status"] if treatment else None,
                "next_action": (
                    treatment["action"]
                    if treatment
                    else row["solution"]
                    or "Review the finding, assign an owner, and define a remediation plan."
                ),
            }
        )
    return priorities


def management_recommendations(
    findings: list[dict[str, object]],
    treatments: list[dict[str, object]],
    distribution: dict[str, int],
) -> list[str]:
    """Create fixed recommendations from visible conditions, never AI text."""
    recommendations = []
    if any(
        row["contextual_risk_level"] == RiskLevel.CRITICAL.value
        and row["workflow_status"]
        in {FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value}
        for row in findings
    ):
        recommendations.append(
            "Prioritize immediate remediation of critical risks and rescan within seven days."
        )
    if any(bool(row["overdue"]) for row in treatments):
        recommendations.append(
            "Review overdue treatment ownership, deadlines, and escalation paths."
        )
    if distribution["unscored"]:
        recommendations.append(
            "Complete asset classification and contextual risk evaluation for unscored findings."
        )
    if not recommendations:
        recommendations.append(
            "Maintain treatment monitoring and validate completed actions with future scans."
        )
    return recommendations


def _select_scan(db: Session, scan_id: int | None) -> Scan:
    if scan_id is not None:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise UnknownScanError(f"Scan {scan_id} does not exist.")
        return scan
    scan = db.scalar(select(Scan).order_by(Scan.scan_date.desc(), Scan.id.desc()))
    if scan is None:
        raise EmptyReportDatabaseError("The selected database contains no scans.")
    return scan


def _asset_inventory(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    assets: dict[int, dict[str, object]] = {}
    for row in findings:
        assets.setdefault(
            int(row["asset_id"]),
            {
                "asset_name": row["asset_name"],
                "ip_address": row["ip_address"],
                "asset_type": row["asset_type"],
                "owner": row["asset_owner"],
                "business_criticality": row["business_criticality"],
                "exposure": row["exposure"],
            },
        )
    return sorted(assets.values(), key=lambda item: str(item["asset_name"]))
