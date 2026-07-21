"""Tests for contextual GRC risk calculation and persistence."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

import app.services.risk_scoring as risk_scoring_module
from app.models import (
    Alert,
    Asset,
    AssetType,
    AssetVulnerability,
    Exposure,
    FindingStatus,
    RiskTreatment,
    Scan,
    Severity,
    Vulnerability,
)
from app.services.risk_scoring import (
    RiskLevel,
    RiskScoringError,
    calculate_risk,
    clamp_risk_score,
    classify_risk_level,
    score_asset_vulnerabilities,
    score_asset_vulnerability,
)

SCORING_DATE = datetime(2026, 2, 1, 9, 0, tzinfo=timezone.utc)


def create_scan(db_session, source: str = "openvas") -> Scan:
    scan = Scan(
        scan_date=SCORING_DATE,
        source=source,
        total_vulnerabilities=0,
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def create_finding(
    db_session,
    *,
    suffix: int = 1,
    scan: Scan | None = None,
    cvss_score: float = 9.0,
    criticality: int = 5,
    exposure: Exposure = Exposure.EXTERNAL,
    risk_score: float | None = None,
    status: FindingStatus = FindingStatus.OPEN,
) -> AssetVulnerability:
    scan = scan or create_scan(db_session)
    asset = Asset(
        name=f"Asset {suffix}",
        ip_address=f"192.0.2.{suffix}",
        asset_type=AssetType.SERVER,
        owner="Infrastructure Team",
        business_criticality=criticality,
        exposure=exposure,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2026-{1000 + suffix}",
        technical_id=None,
        cvss_score=cvss_score,
        title=f"Vulnerability {suffix}",
        severity=Severity.CRITICAL,
        detected_at=SCORING_DATE,
        source="openvas",
    )
    finding = AssetVulnerability(
        asset=asset,
        vulnerability=vulnerability,
        scan=scan,
        status=status,
        risk_score=risk_score,
        first_seen_at=SCORING_DATE,
        last_seen_at=SCORING_DATE,
    )
    db_session.add(finding)
    db_session.flush()
    scan.total_vulnerabilities += 1
    db_session.commit()
    return finding


@pytest.mark.parametrize(
    ("cvss", "criticality", "exposure", "expected_score", "expected_level"),
    [
        (0.0, 1, Exposure.INTERNAL, 0.0, RiskLevel.LOW),
        (10.0, 5, Exposure.EXTERNAL, 100.0, RiskLevel.CRITICAL),
        (10.0, 1, Exposure.INTERNAL, 13.33, RiskLevel.LOW),
        (10.0, 1, Exposure.EXTERNAL, 20.0, RiskLevel.LOW),
        (10.0, 5, Exposure.INTERNAL, 66.67, RiskLevel.HIGH),
    ],
)
def test_pure_formula_core_inputs(
    cvss, criticality, exposure, expected_score, expected_level
):
    result = calculate_risk(cvss, criticality, exposure)
    assert result.normalized_risk_score == expected_score
    assert result.risk_level is expected_level


def test_external_critical_server_example():
    result = calculate_risk(9.0, 5, Exposure.EXTERNAL)
    assert result.raw_score == 67.5
    assert result.normalized_risk_score == 90.0
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.calculation_details.exposure_factor == 1.5


def test_internal_workstation_example_and_rounding():
    result = calculate_risk(8.5, 2, Exposure.INTERNAL)
    assert result.raw_score == 17.0
    assert result.normalized_risk_score == 22.67
    assert result.risk_level is RiskLevel.LOW


def test_internal_database_example():
    result = calculate_risk(7.5, 5, Exposure.INTERNAL)
    assert result.raw_score == 37.5
    assert result.normalized_risk_score == 50.0
    assert result.risk_level is RiskLevel.HIGH


def test_score_clamping():
    assert clamp_risk_score(-0.01) == 0.0
    assert clamp_risk_score(100.01) == 100.0


@pytest.mark.parametrize(
    ("risk_score", "expected_level"),
    [
        (0.0, RiskLevel.LOW),
        (24.99, RiskLevel.LOW),
        (25.0, RiskLevel.MEDIUM),
        (49.99, RiskLevel.MEDIUM),
        (50.0, RiskLevel.HIGH),
        (74.99, RiskLevel.HIGH),
        (75.0, RiskLevel.CRITICAL),
        (100.0, RiskLevel.CRITICAL),
    ],
)
def test_exact_risk_level_boundaries(risk_score, expected_level):
    assert classify_risk_level(risk_score) is expected_level


def test_scores_one_asset_vulnerability(db_session):
    finding = create_finding(db_session)

    calculation = score_asset_vulnerability(finding)

    assert calculation.normalized_risk_score == 90.0
    assert finding.risk_score == 90.0


def test_scores_findings_for_only_one_scan(db_session):
    first_scan = create_scan(db_session, "first")
    first = create_finding(db_session, suffix=1, scan=first_scan)
    second_scan = create_scan(db_session, "second")
    second = create_finding(db_session, suffix=2, scan=second_scan)

    result = score_asset_vulnerabilities(db_session, scan_id=first_scan.id)

    assert result.examined_count == 1
    assert result.scored_count == 1
    assert first.risk_score == 90.0
    assert second.risk_score is None


def test_scores_only_null_records_by_default(db_session):
    unscored = create_finding(db_session, suffix=1)
    already_scored = create_finding(db_session, suffix=2, risk_score=12.34)

    result = score_asset_vulnerabilities(db_session)

    assert result.examined_count == 2
    assert result.scored_count == 1
    assert result.skipped_count == 1
    assert unscored.risk_score == 90.0
    assert already_scored.risk_score == 12.34


def test_force_recalculates_existing_score(db_session):
    finding = create_finding(db_session, risk_score=1.0)

    result = score_asset_vulnerabilities(db_session, force=True)

    assert result.scored_count == 1
    assert result.skipped_count == 0
    assert finding.risk_score == 90.0


def test_scoring_preserves_status_and_relationships(db_session):
    finding = create_finding(db_session, status=FindingStatus.IN_PROGRESS)
    asset_id = finding.asset_id
    vulnerability_id = finding.vulnerability_id
    scan_id = finding.scan_id

    score_asset_vulnerabilities(db_session)

    assert finding.status is FindingStatus.IN_PROGRESS
    assert finding.asset_id == asset_id
    assert finding.vulnerability_id == vulnerability_id
    assert finding.scan_id == scan_id


@pytest.mark.parametrize(
    "finding",
    [
        SimpleNamespace(asset=None, vulnerability=SimpleNamespace(cvss_score=5), risk_score=None),
        SimpleNamespace(asset=SimpleNamespace(business_criticality=3, exposure="internal"), vulnerability=None, risk_score=None),
        SimpleNamespace(asset=SimpleNamespace(business_criticality=3, exposure="internal"), vulnerability=SimpleNamespace(cvss_score=None), risk_score=None),
        SimpleNamespace(asset=SimpleNamespace(business_criticality=0, exposure="internal"), vulnerability=SimpleNamespace(cvss_score=5), risk_score=None),
        SimpleNamespace(asset=SimpleNamespace(business_criticality=3, exposure="partner"), vulnerability=SimpleNamespace(cvss_score=5), risk_score=None),
    ],
)
def test_invalid_or_incomplete_finding_data_is_rejected(finding):
    with pytest.raises(RiskScoringError):
        score_asset_vulnerability(finding)


def test_one_invalid_record_does_not_block_valid_records(db_session, monkeypatch):
    valid = create_finding(db_session, suffix=1)
    invalid = create_finding(db_session, suffix=2)
    real_score_function = risk_scoring_module.score_asset_vulnerability

    def fail_one_finding(finding, *, force=False):
        if finding.id == invalid.id:
            raise RiskScoringError("Simulated invalid legacy data.")
        return real_score_function(finding, force=force)

    monkeypatch.setattr(
        risk_scoring_module, "score_asset_vulnerability", fail_one_finding
    )
    result = score_asset_vulnerabilities(db_session)

    assert result.scored_count == 1
    assert result.failed_count == 1
    assert valid.risk_score == 90.0
    assert invalid.risk_score is None


def test_database_failure_rolls_back_all_scores(db_session, monkeypatch):
    first = create_finding(db_session, suffix=1)
    second = create_finding(db_session, suffix=2)

    def fail_commit():
        raise IntegrityError("forced test failure", {}, Exception("forced"))

    monkeypatch.setattr(db_session, "commit", fail_commit)
    result = score_asset_vulnerabilities(db_session)

    assert result.scored_count == 0
    assert result.failed_count == 2
    assert any("rolled back" in error for error in result.errors)
    assert db_session.get(AssetVulnerability, first.id).risk_score is None
    assert db_session.get(AssetVulnerability, second.id).risk_score is None


def test_scoring_does_not_create_alerts_or_treatments(db_session):
    create_finding(db_session)

    score_asset_vulnerabilities(db_session)

    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0
