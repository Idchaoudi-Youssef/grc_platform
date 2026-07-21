"""Prepare safe, sanitized data for every M8 dashboard section."""

from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import Base, configure_sqlite_foreign_keys  # noqa: E402
from app.models import (  # noqa: E402
    Alert,
    AlertLevel,
    Asset,
    AssetType,
    AssetVulnerability,
    Exposure,
    FindingStatus,
    RiskTreatment,
    Scan,
    Severity,
    TreatmentStatus,
    Vulnerability,
)
from app.services.detection_remediation import run_detection_remediation  # noqa: E402
from app.services.risk_scoring import score_asset_vulnerabilities  # noqa: E402

DEMO_DATABASE = Path(__file__).resolve().with_name("grc_dashboard_demo.db")


def reset_demo_database() -> None:
    """Reset only the explicitly named dashboard demonstration database."""
    expected = Path(__file__).resolve().parent / "grc_dashboard_demo.db"
    if DEMO_DATABASE != expected:
        raise RuntimeError(f"Unexpected demo database path: {DEMO_DATABASE}")
    if DEMO_DATABASE.exists():
        DEMO_DATABASE.unlink()


def main() -> int:
    reset_demo_database()
    engine = create_engine(f"sqlite:///{DEMO_DATABASE}", connect_args={"check_same_thread": False})
    configure_sqlite_foreign_keys(engine)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False)
    db = session_factory()
    try:
        assets = _create_assets(db)
        vulnerabilities = _create_vulnerabilities(db)
        scans = _create_scans(db)
        findings = _create_findings(db, assets, vulnerabilities, scans)
        db.commit()

        score_asset_vulnerabilities(db)
        run_detection_remediation(db, evaluation_date=date(2026, 4, 1))
        _add_workflow_examples(db, findings)
        db.commit()

        print("=== GRC DASHBOARD DEMO PREPARATION ===")
        print(f"Dedicated database: {DEMO_DATABASE}")
        print("Data label: SANITIZED DEMONSTRATION DATA ONLY")
        print("Assets: 4")
        print("Scans: 2")
        print("Findings: 6 (low, medium, high, and critical contextual risk)")
        print("Alerts: acknowledged and unacknowledged examples")
        print("Treatments: pending, in-progress, completed, and overdue examples")
        print("Normal grc.db was not opened or modified.")
        return 0
    finally:
        db.close()
        engine.dispose()


def _create_assets(db) -> dict[str, Asset]:
    assets = {
        "critical": Asset(name="DEMO - Public payment server", ip_address="192.0.2.80", asset_type=AssetType.SERVER, owner="Demo SOC Team", business_criticality=5, exposure=Exposure.EXTERNAL, description="Dashboard demonstration only"),
        "high": Asset(name="DEMO - Internal database", ip_address="192.0.2.81", asset_type=AssetType.DATABASE, owner="Demo Database Team", business_criticality=5, exposure=Exposure.INTERNAL, description="Dashboard demonstration only"),
        "medium": Asset(name="DEMO - Business application", ip_address="192.0.2.82", asset_type=AssetType.APPLICATION, owner="Demo Application Team", business_criticality=4, exposure=Exposure.INTERNAL, description="Dashboard demonstration only"),
        "low": Asset(name="DEMO - Analyst workstation", ip_address="192.0.2.83", asset_type=AssetType.WORKSTATION, owner="Demo Endpoint Team", business_criticality=2, exposure=Exposure.INTERNAL, description="Dashboard demonstration only"),
    }
    db.add_all(assets.values())
    db.flush()
    return assets


def _create_vulnerabilities(db) -> dict[str, Vulnerability]:
    detected = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
    vulnerabilities = {
        "critical": Vulnerability(cve_id="CVE-2026-8001", technical_id=None, cvss_score=9.0, title="Critical exposed service flaw", description="Sanitized critical example", solution="Apply the approved vendor update and rescan.", severity=Severity.CRITICAL, detected_at=detected, source="openvas"),
        "high": Vulnerability(cve_id="CVE-2026-8002", technical_id=None, cvss_score=8.0, title="Database service vulnerability", description="Sanitized high-risk example", solution="Apply the tested database mitigation.", severity=Severity.HIGH, detected_at=detected, source="openvas"),
        "medium": Vulnerability(cve_id="CVE-2026-8003", technical_id=None, cvss_score=8.0, title="Application component weakness", description="Technically high but contextually medium sanitized example", solution="Upgrade the affected component.", severity=Severity.HIGH, detected_at=detected, source="openvas"),
        "low": Vulnerability(cve_id="CVE-2026-8004", technical_id=None, cvss_score=3.0, title="Workstation information exposure", description="Sanitized low-risk example", solution="Apply endpoint hardening guidance.", severity=Severity.LOW, detected_at=detected, source="openvas"),
    }
    db.add_all(vulnerabilities.values())
    db.flush()
    return vulnerabilities


def _create_scans(db) -> list[Scan]:
    scans = [
        Scan(scan_date=datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc), source="openvas", total_vulnerabilities=4),
        Scan(scan_date=datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc), source="openvas", total_vulnerabilities=2),
    ]
    db.add_all(scans)
    db.flush()
    return scans


def _create_findings(db, assets, vulnerabilities, scans) -> dict[str, AssetVulnerability]:
    first = scans[0].scan_date
    second = scans[1].scan_date
    findings = {
        "critical_old": AssetVulnerability(asset=assets["critical"], vulnerability=vulnerabilities["critical"], scan=scans[0], status=FindingStatus.OPEN, first_seen_at=first, last_seen_at=first),
        "high": AssetVulnerability(asset=assets["high"], vulnerability=vulnerabilities["high"], scan=scans[0], status=FindingStatus.IN_PROGRESS, first_seen_at=first, last_seen_at=first),
        "medium": AssetVulnerability(asset=assets["medium"], vulnerability=vulnerabilities["medium"], scan=scans[0], status=FindingStatus.ACCEPTED, first_seen_at=first, last_seen_at=first),
        "low": AssetVulnerability(asset=assets["low"], vulnerability=vulnerabilities["low"], scan=scans[0], status=FindingStatus.FIXED, first_seen_at=first, last_seen_at=first),
        "critical_new": AssetVulnerability(asset=assets["critical"], vulnerability=vulnerabilities["critical"], scan=scans[1], status=FindingStatus.OPEN, first_seen_at=first, last_seen_at=second),
        "medium_new": AssetVulnerability(asset=assets["medium"], vulnerability=vulnerabilities["medium"], scan=scans[1], status=FindingStatus.OPEN, first_seen_at=first, last_seen_at=second),
    }
    db.add_all(findings.values())
    return findings


def _add_workflow_examples(db, findings) -> None:
    automatic_alerts = list(findings["critical_old"].alerts + findings["critical_new"].alerts)
    automatic_treatments = list(findings["critical_old"].treatments + findings["critical_new"].treatments)
    automatic_alerts[0].acknowledged = True
    automatic_treatments[0].status = TreatmentStatus.PENDING
    automatic_treatments[0].due_date = date(2026, 3, 15)
    automatic_treatments[1].status = TreatmentStatus.IN_PROGRESS
    automatic_treatments[1].due_date = date(2026, 4, 8)

    db.add(
        Alert(asset_vulnerability=findings["high"], rule_key="dashboard_demo_review", level=AlertLevel.HIGH, message="Demo high-risk finding requires analyst review.", created_at=datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc), acknowledged=False)
    )
    db.add(
        RiskTreatment(asset_vulnerability=findings["low"], rule_key="dashboard_demo_completed", action="Endpoint hardening completed and verified.", owner="Demo Endpoint Team", due_date=date(2026, 3, 10), status=TreatmentStatus.COMPLETED, resolved_at=datetime(2026, 3, 8, 12, 0, tzinfo=timezone.utc), evidence="Sanitized verification note", auto_created=False)
    )


if __name__ == "__main__":
    raise SystemExit(main())
