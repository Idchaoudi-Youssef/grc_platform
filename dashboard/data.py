"""Read-only queries and aggregations used by the Streamlit dashboard."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, joinedload, sessionmaker

from app.models import (
    Alert,
    Asset,
    AssetVulnerability,
    FindingStatus,
    RiskTreatment,
    Scan,
    TreatmentStatus,
)
from app.services.risk_scoring import RiskLevel, classify_risk_level

REQUIRED_TABLES = {
    "assets",
    "scans",
    "vulnerabilities",
    "asset_vulnerabilities",
    "alerts",
    "risk_treatments",
}


class DashboardDatabaseError(RuntimeError):
    """Raised when the selected database cannot be read safely."""


class DatabaseNotFoundError(DashboardDatabaseError):
    """Raised when the selected SQLite file does not exist."""


class DatabaseSchemaError(DashboardDatabaseError):
    """Raised when the selected SQLite file lacks the application tables."""


@dataclass(frozen=True)
class DashboardFilters:
    """Selections shared by dashboard tables and aggregations."""

    scan_ids: frozenset[int] = field(default_factory=frozenset)
    asset_ids: frozenset[int] = field(default_factory=frozenset)
    asset_types: frozenset[str] = field(default_factory=frozenset)
    exposures: frozenset[str] = field(default_factory=frozenset)
    risk_levels: frozenset[str] = field(default_factory=frozenset)
    finding_statuses: frozenset[str] = field(default_factory=frozenset)
    technical_severities: frozenset[str] = field(default_factory=frozenset)

    @property
    def active(self) -> bool:
        return any(
            (
                self.scan_ids,
                self.asset_ids,
                self.asset_types,
                self.exposures,
                self.risk_levels,
                self.finding_statuses,
                self.technical_severities,
            )
        )


@dataclass(frozen=True)
class DashboardKpis:
    total_assets: int
    total_scans: int
    total_relationships: int
    open_critical_risks: int
    unacknowledged_alerts: int
    active_treatments: int
    treatment_completion_percentage: float
    average_contextual_risk: float | None


def create_read_only_engine(database_path: str | Path) -> Engine:
    """Open an existing SQLite database without permission to write."""
    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        raise DatabaseNotFoundError(f"Database does not exist: {path}")

    engine = create_engine(
        f"sqlite:///file:{path.as_posix()}?mode=ro&uri=true",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _force_query_only(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA query_only=ON")
        cursor.close()

    try:
        table_names = set(inspect(engine).get_table_names())
    except Exception as exc:
        engine.dispose()
        raise DashboardDatabaseError(f"Database read failed: {exc}") from exc
    missing = sorted(REQUIRED_TABLES - table_names)
    if missing:
        engine.dispose()
        raise DatabaseSchemaError(
            "Database tables are missing: " + ", ".join(missing)
        )
    return engine


@contextmanager
def read_only_session(database_path: str | Path) -> Iterator[Session]:
    """Yield a short-lived session connected to a query-only SQLite engine."""
    engine = create_read_only_engine(database_path)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def list_filter_options(db: Session) -> dict[str, list[tuple[str, int] | str]]:
    """Return readable values for sidebar filters."""
    scans = list(db.scalars(select(Scan).order_by(Scan.scan_date.desc())).all())
    assets = list(db.scalars(select(Asset).order_by(Asset.name)).all())
    return {
        "scans": [(f"Scan {scan.id} - {_format_datetime(scan.scan_date)}", scan.id) for scan in scans],
        "assets": [(f"{asset.name} ({asset.ip_address})", asset.id) for asset in assets],
        "asset_types": sorted({asset.asset_type.value for asset in assets}),
        "exposures": sorted({asset.exposure.value for asset in assets}),
        "risk_levels": [level.value for level in RiskLevel],
        "finding_statuses": [status.value for status in FindingStatus],
        "technical_severities": ["info", "low", "medium", "high", "critical"],
    }


def get_findings(
    db: Session, filters: DashboardFilters | None = None
) -> list[dict[str, object]]:
    """Return normalized finding rows, sorted by contextual risk descending."""
    selected = filters or DashboardFilters()
    records = list(
        db.scalars(
            select(AssetVulnerability)
            .options(
                joinedload(AssetVulnerability.asset),
                joinedload(AssetVulnerability.vulnerability),
                joinedload(AssetVulnerability.scan),
            )
            .order_by(AssetVulnerability.id)
        ).all()
    )
    rows = [_finding_row(record) for record in records]
    rows = [row for row in rows if _matches_filters(row, selected)]
    return sorted(
        rows,
        key=lambda row: (
            row["contextual_risk_score"] is not None,
            row["contextual_risk_score"] or 0,
            row["finding_id"],
        ),
        reverse=True,
    )


def calculate_kpis(
    db: Session,
    findings: list[dict[str, object]],
    filters: DashboardFilters | None = None,
) -> DashboardKpis:
    """Calculate the main GRC indicators for the selected finding population."""
    selected = filters or DashboardFilters()
    all_alerts = get_alerts(db, findings)
    all_treatments = get_treatments(db, findings)
    scores = [float(row["contextual_risk_score"]) for row in findings if row["contextual_risk_score"] is not None]

    if selected.active:
        total_assets = len({int(row["asset_id"]) for row in findings})
        total_scans = len({int(row["scan_id"]) for row in findings})
    else:
        total_assets = len(list(db.scalars(select(Asset.id)).all()))
        total_scans = len(list(db.scalars(select(Scan.id)).all()))

    completed = sum(
        row["status"] in {TreatmentStatus.COMPLETED.value, TreatmentStatus.ACCEPTED.value}
        for row in all_treatments
    )
    completion = round((completed / len(all_treatments)) * 100, 2) if all_treatments else 0.0
    return DashboardKpis(
        total_assets=total_assets,
        total_scans=total_scans,
        total_relationships=len(findings),
        open_critical_risks=sum(
            row["contextual_risk_level"] == RiskLevel.CRITICAL.value
            and row["workflow_status"] in {FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value}
            for row in findings
        ),
        unacknowledged_alerts=sum(not bool(row["acknowledged"]) for row in all_alerts),
        active_treatments=sum(
            row["status"] in {TreatmentStatus.PENDING.value, TreatmentStatus.IN_PROGRESS.value}
            for row in all_treatments
        ),
        treatment_completion_percentage=completion,
        average_contextual_risk=round(sum(scores) / len(scores), 2) if scores else None,
    )


def aggregate_risk_levels(findings: list[dict[str, object]]) -> dict[str, int]:
    """Count contextual levels and keep unscored findings visible."""
    counts = {level.value: 0 for level in RiskLevel}
    counts["unscored"] = 0
    for row in findings:
        level = row["contextual_risk_level"] or "unscored"
        counts[str(level)] += 1
    return counts


def get_top_risky_assets(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Aggregate risk metrics per asset."""
    grouped: dict[int, dict[str, object]] = {}
    for row in findings:
        asset_id = int(row["asset_id"])
        item = grouped.setdefault(
            asset_id,
            {
                "asset_name": row["asset_name"],
                "ip_address": row["ip_address"],
                "scores": [],
                "open_critical_findings": 0,
                "total_findings": 0,
            },
        )
        item["total_findings"] = int(item["total_findings"]) + 1
        score = row["contextual_risk_score"]
        if score is not None:
            item["scores"].append(float(score))
        if (
            row["contextual_risk_level"] == RiskLevel.CRITICAL.value
            and row["workflow_status"] in {FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value}
        ):
            item["open_critical_findings"] = int(item["open_critical_findings"]) + 1

    results = []
    for item in grouped.values():
        scores = item.pop("scores")
        results.append(
            {
                **item,
                "maximum_risk_score": max(scores) if scores else None,
                "average_risk_score": round(sum(scores) / len(scores), 2) if scores else None,
            }
        )
    return sorted(
        results,
        key=lambda row: (row["maximum_risk_score"] is not None, row["maximum_risk_score"] or 0),
        reverse=True,
    )


def get_alerts(db: Session, findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Return alerts whose related findings match the current filters."""
    finding_ids = {int(row["finding_id"]) for row in findings}
    if not finding_ids:
        return []
    alerts = list(
        db.scalars(
            select(Alert)
            .where(Alert.asset_vulnerability_id.in_(finding_ids))
            .options(
                joinedload(Alert.asset_vulnerability).joinedload(AssetVulnerability.asset),
                joinedload(Alert.asset_vulnerability).joinedload(AssetVulnerability.vulnerability),
            )
            .order_by(Alert.created_at.desc())
        ).all()
    )
    return [
        {
            "alert_id": alert.id,
            "level": alert.level.value,
            "message": alert.message,
            "created_at": alert.created_at,
            "acknowledged": alert.acknowledged,
            "asset": alert.asset_vulnerability.asset.name,
            "vulnerability": _vulnerability_identity(alert.asset_vulnerability),
        }
        for alert in alerts
    ]


def get_treatments(
    db: Session,
    findings: list[dict[str, object]],
    *,
    as_of: date | None = None,
) -> list[dict[str, object]]:
    """Return treatments and derive overdue state without changing records."""
    finding_ids = {int(row["finding_id"]) for row in findings}
    if not finding_ids:
        return []
    today = as_of or date.today()
    treatments = list(
        db.scalars(
            select(RiskTreatment)
            .where(RiskTreatment.asset_vulnerability_id.in_(finding_ids))
            .options(
                joinedload(RiskTreatment.asset_vulnerability).joinedload(AssetVulnerability.asset),
                joinedload(RiskTreatment.asset_vulnerability).joinedload(AssetVulnerability.vulnerability),
            )
            .order_by(RiskTreatment.due_date)
        ).all()
    )
    return [
        {
            "treatment_id": treatment.id,
            "asset": treatment.asset_vulnerability.asset.name,
            "vulnerability": _vulnerability_identity(treatment.asset_vulnerability),
            "action": treatment.action,
            "owner": treatment.owner,
            "due_date": treatment.due_date,
            "status": treatment.status.value,
            "auto_created": treatment.auto_created,
            "overdue": bool(
                treatment.due_date
                and treatment.due_date < today
                and treatment.status not in {TreatmentStatus.COMPLETED, TreatmentStatus.ACCEPTED}
            ),
        }
        for treatment in treatments
    ]


def get_scan_history(
    db: Session,
    findings: list[dict[str, object]],
    filters: DashboardFilters | None = None,
) -> list[dict[str, object]]:
    """Aggregate relationship, risk, critical, and alert counts per scan."""
    selected = filters or DashboardFilters()
    grouped: dict[int, list[dict[str, object]]] = {}
    for row in findings:
        grouped.setdefault(int(row["scan_id"]), []).append(row)

    query = select(Scan).order_by(Scan.scan_date)
    if selected.scan_ids:
        query = query.where(Scan.id.in_(selected.scan_ids))
    scans = list(db.scalars(query).all())
    if selected.active and not selected.scan_ids:
        scans = [scan for scan in scans if scan.id in grouped]

    alerts = get_alerts(db, findings)
    alert_finding_to_scan = {int(row["finding_id"]): int(row["scan_id"]) for row in findings}
    alert_scan_counts: dict[int, int] = {}
    alert_ids = {int(row["alert_id"]) for row in alerts}
    if alert_ids:
        for alert in db.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all():
            scan_id = alert_finding_to_scan.get(alert.asset_vulnerability_id)
            if scan_id is not None:
                alert_scan_counts[scan_id] = alert_scan_counts.get(scan_id, 0) + 1

    history = []
    for scan in scans:
        rows = grouped.get(scan.id, [])
        scores = [float(row["contextual_risk_score"]) for row in rows if row["contextual_risk_score"] is not None]
        history.append(
            {
                "scan_id": scan.id,
                "scan_date": scan.scan_date,
                "source": scan.source,
                "imported_relationship_count": len(rows),
                "average_risk": round(sum(scores) / len(scores), 2) if scores else None,
                "critical_risk_count": sum(row["contextual_risk_level"] == RiskLevel.CRITICAL.value for row in rows),
                "alert_count": alert_scan_counts.get(scan.id, 0),
            }
        )
    return history


def executive_summary(
    findings: list[dict[str, object]],
    treatments: list[dict[str, object]],
    scan_history: list[dict[str, object]],
) -> dict[str, object]:
    """Build a deterministic posture summary from existing data."""
    top_assets = get_top_risky_assets(findings)
    latest_scan = max((row["scan_date"] for row in scan_history), default=None)
    return {
        "critical_risks": aggregate_risk_levels(findings)[RiskLevel.CRITICAL.value],
        "most_exposed_asset": top_assets[0]["asset_name"] if top_assets else None,
        "overdue_treatments": sum(bool(row["overdue"]) for row in treatments),
        "latest_scan_date": latest_scan,
    }


def _finding_row(record: AssetVulnerability) -> dict[str, object]:
    score = record.risk_score
    return {
        "finding_id": record.id,
        "asset_id": record.asset_id,
        "scan_id": record.scan_id,
        "asset_name": record.asset.name,
        "ip_address": record.asset.ip_address,
        "asset_type": record.asset.asset_type.value,
        "business_criticality": record.asset.business_criticality,
        "exposure": record.asset.exposure.value,
        "vulnerability": _vulnerability_identity(record),
        "vulnerability_title": record.vulnerability.title,
        "cvss": record.vulnerability.cvss_score,
        "technical_severity": record.vulnerability.severity.value,
        "contextual_risk_score": score,
        "contextual_risk_level": classify_risk_level(score).value if score is not None else None,
        "workflow_status": record.status.value,
        "scan_date": record.scan.scan_date,
    }


def _matches_filters(row: dict[str, object], filters: DashboardFilters) -> bool:
    checks = (
        (filters.scan_ids, row["scan_id"]),
        (filters.asset_ids, row["asset_id"]),
        (filters.asset_types, row["asset_type"]),
        (filters.exposures, row["exposure"]),
        (filters.risk_levels, row["contextual_risk_level"] or "unscored"),
        (filters.finding_statuses, row["workflow_status"]),
        (filters.technical_severities, row["technical_severity"]),
    )
    return all(not choices or value in choices for choices, value in checks)


def _vulnerability_identity(record: AssetVulnerability) -> str:
    return record.vulnerability.cve_id or record.vulnerability.technical_id or "unknown"


def _format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M")
