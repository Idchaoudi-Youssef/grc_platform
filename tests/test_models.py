"""Database tests for the M2 scan, finding, treatment, and alert models."""

from datetime import date, datetime, timezone

import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError

from app.models import (
    Alert,
    AlertLevel,
    Asset,
    AssetType,
    AssetVulnerability,
    FindingStatus,
    RiskTreatment,
    Scan,
    Severity,
    TreatmentStatus,
    Vulnerability,
)


def make_asset(ip_address: str = "192.0.2.20") -> Asset:
    return Asset(
        name="Database server",
        ip_address=ip_address,
        asset_type=AssetType.DATABASE,
        owner="Database Team",
        business_criticality=5,
        exposure="internal",
        description="Stores regulated business data",
    )


def make_scan() -> Scan:
    return Scan(
        scan_date=datetime.now(timezone.utc),
        source="openvas",
        total_vulnerabilities=1,
    )


def make_vulnerability(cvss_score: float = 9.8) -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2024-0001",
        cvss_score=cvss_score,
        title="Remote code execution",
        description="A sanitized example vulnerability.",
        severity=Severity.CRITICAL,
        detected_at=datetime.now(timezone.utc),
    )


def create_complete_finding(db_session) -> AssetVulnerability:
    finding = AssetVulnerability(
        asset=make_asset(),
        vulnerability=make_vulnerability(),
        scan=make_scan(),
    )
    finding.treatments.append(
        RiskTreatment(
            action="Apply the vendor security update",
            owner="Database Team",
            due_date=date.today(),
        )
    )
    finding.alerts.append(
        Alert(level=AlertLevel.CRITICAL, message="Critical database finding")
    )
    db_session.add(finding)
    db_session.commit()
    return finding


def test_schema_contains_all_core_tables(test_engine):
    table_names = set(inspect(test_engine).get_table_names())
    assert {
        "assets",
        "scans",
        "vulnerabilities",
        "asset_vulnerabilities",
        "risk_treatments",
        "alerts",
    }.issubset(table_names)


def test_required_columns_are_not_nullable(test_engine):
    inspector = inspect(test_engine)
    required_columns = {
        "scans": {"scan_date", "source", "total_vulnerabilities", "imported_at"},
        "vulnerabilities": {
            "cvss_score",
            "title",
            "severity",
            "detected_at",
            "source",
        },
        "asset_vulnerabilities": {
            "asset_id",
            "vulnerability_id",
            "scan_id",
            "status",
            "first_seen_at",
            "last_seen_at",
        },
        "risk_treatments": {
            "asset_vulnerability_id",
            "action",
            "owner",
            "status",
            "auto_created",
        },
        "alerts": {
            "asset_vulnerability_id",
            "level",
            "message",
            "created_at",
            "acknowledged",
        },
    }

    for table_name, expected_required in required_columns.items():
        columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        assert all(not columns[name]["nullable"] for name in expected_required)


def test_model_relationships_and_defaults(db_session):
    finding = create_complete_finding(db_session)

    assert finding in finding.asset.asset_vulnerabilities
    assert finding in finding.vulnerability.asset_vulnerabilities
    assert finding in finding.scan.asset_vulnerabilities
    assert finding.treatments[0].asset_vulnerability is finding
    assert finding.alerts[0].asset_vulnerability is finding
    assert finding.status is FindingStatus.OPEN
    assert finding.risk_score is None
    assert finding.vulnerability.source == "openvas"
    assert finding.treatments[0].status is TreatmentStatus.PENDING
    assert finding.treatments[0].auto_created is False
    assert finding.alerts[0].acknowledged is False


def test_missing_required_field_is_rejected(db_session):
    vulnerability = make_vulnerability()
    vulnerability.title = None
    db_session.add(vulnerability)

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_negative_scan_total_is_rejected(db_session):
    scan = make_scan()
    scan.total_vulnerabilities = -1
    db_session.add(scan)

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_enum_constraints_reject_unknown_values(db_session):
    finding = create_complete_finding(db_session)
    invalid_updates = [
        ("vulnerabilities", "severity", finding.vulnerability_id),
        ("asset_vulnerabilities", "status", finding.id),
        ("risk_treatments", "status", finding.treatments[0].id),
        ("alerts", "level", finding.alerts[0].id),
    ]

    for table_name, column_name, record_id in invalid_updates:
        statement = text(
            f"UPDATE {table_name} SET {column_name} = :value WHERE id = :record_id"
        )
        with pytest.raises(IntegrityError):
            db_session.execute(
                statement, {"value": "not_a_valid_value", "record_id": record_id}
            )
        db_session.rollback()


def test_sqlite_foreign_keys_are_enabled(db_session):
    enabled = db_session.execute(text("PRAGMA foreign_keys")).scalar_one()
    assert enabled == 1


def test_unknown_foreign_keys_are_rejected(db_session):
    finding = AssetVulnerability(
        asset_id=999,
        vulnerability_id=999,
        scan_id=999,
    )
    db_session.add(finding)

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_deleting_asset_cascades_to_finding_data(db_session):
    finding = create_complete_finding(db_session)
    asset = finding.asset
    db_session.delete(asset)
    db_session.commit()

    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0


def test_duplicate_asset_vulnerability_is_rejected(db_session):
    finding = AssetVulnerability(
        asset=make_asset(),
        vulnerability=make_vulnerability(),
        scan=make_scan(),
    )
    db_session.add(finding)
    db_session.commit()

    duplicate = AssetVulnerability(
        asset_id=finding.asset_id,
        vulnerability_id=finding.vulnerability_id,
        scan_id=finding.scan_id,
    )
    db_session.add(duplicate)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_vulnerability_can_have_no_cve(db_session):
    vulnerability = make_vulnerability()
    vulnerability.cve_id = None
    db_session.add(vulnerability)
    db_session.commit()

    assert vulnerability.cve_id is None


@pytest.mark.parametrize("cvss_score", [0.0, 10.0])
def test_cvss_boundary_values_are_accepted(db_session, cvss_score):
    vulnerability = make_vulnerability(cvss_score=cvss_score)
    db_session.add(vulnerability)
    db_session.commit()

    assert vulnerability.cvss_score == cvss_score


@pytest.mark.parametrize("cvss_score", [-0.1, 10.1])
def test_cvss_outside_boundaries_is_rejected(db_session, cvss_score):
    vulnerability = make_vulnerability(cvss_score=cvss_score)
    db_session.add(vulnerability)

    with pytest.raises(IntegrityError):
        db_session.commit()
