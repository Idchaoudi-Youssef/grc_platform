"""Tests for M6 rule-based detection and automatic task creation."""

from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

import app.services.detection_remediation as automation_module
from app.models import (
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
from app.services.detection_remediation import (
    CRITICAL_CONTEXTUAL_RISK_RULE,
    GENERIC_REMEDIATION,
    DetectionRemediationError,
    evaluate_critical_contextual_risk,
    process_asset_vulnerability,
    run_detection_remediation,
)

DETECTION_DATE = date(2026, 3, 1)
OBSERVED_AT = datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc)


def create_finding(
    db_session,
    *,
    suffix: int = 1,
    scan: Scan | None = None,
    risk_score: float | None = 90.0,
    criticality: int = 5,
    status: FindingStatus = FindingStatus.OPEN,
    owner: str = "Infrastructure Team",
    solution: str | None = "Apply the tested vendor mitigation.",
) -> AssetVulnerability:
    if scan is None:
        scan = Scan(
            scan_date=OBSERVED_AT,
            source=f"openvas-{suffix}",
            total_vulnerabilities=1,
        )
    asset = Asset(
        name=f"Critical server {suffix}",
        ip_address=f"192.0.2.{suffix}",
        asset_type=AssetType.SERVER,
        owner=owner,
        business_criticality=criticality,
        exposure=Exposure.EXTERNAL,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2026-{2000 + suffix}",
        technical_id=None,
        cvss_score=9.0,
        title=f"Remote service vulnerability {suffix}",
        description="Sanitized finding",
        solution=solution,
        severity=Severity.CRITICAL,
        detected_at=OBSERVED_AT,
        source="openvas",
    )
    finding = AssetVulnerability(
        asset=asset,
        vulnerability=vulnerability,
        scan=scan,
        status=status,
        risk_score=risk_score,
        first_seen_at=OBSERVED_AT,
        last_seen_at=OBSERVED_AT,
    )
    db_session.add(finding)
    db_session.commit()
    return finding


@pytest.mark.parametrize(
    ("risk_score", "criticality", "status", "matched"),
    [
        (74.99, 5, FindingStatus.OPEN, False),
        (75.0, 4, FindingStatus.OPEN, True),
        (100.0, 5, FindingStatus.OPEN, True),
        (90.0, 3, FindingStatus.OPEN, False),
        (90.0, 4, FindingStatus.FIXED, False),
        (90.0, 4, FindingStatus.OPEN, True),
        (None, 5, FindingStatus.OPEN, False),
    ],
)
def test_pure_critical_rule(risk_score, criticality, status, matched):
    result = evaluate_critical_contextual_risk(
        risk_score,
        criticality,
        status,
        evaluation_date=DETECTION_DATE,
    )
    assert result.matched is matched
    assert result.rule_key == CRITICAL_CONTEXTUAL_RISK_RULE
    if matched:
        assert result.alert_level is AlertLevel.CRITICAL
        assert result.recommended_deadline == date(2026, 3, 8)


def test_matching_record_creates_alert_and_treatment_with_context(db_session):
    finding = create_finding(db_session)

    outcome = process_asset_vulnerability(
        db_session, finding, evaluation_date=DETECTION_DATE
    )
    alert = db_session.scalar(select(Alert))
    treatment = db_session.scalar(select(RiskTreatment))

    assert outcome.matched is True
    assert outcome.alert_created is True
    assert outcome.treatment_created is True
    assert alert.level is AlertLevel.CRITICAL
    assert alert.acknowledged is False
    assert alert.rule_key == CRITICAL_CONTEXTUAL_RISK_RULE
    assert finding.asset.name in alert.message
    assert finding.asset.ip_address in alert.message
    assert finding.vulnerability.title in alert.message
    assert finding.vulnerability.cve_id in alert.message
    assert "90.00" in alert.message
    assert treatment.owner == finding.asset.owner
    assert treatment.action == finding.vulnerability.solution
    assert treatment.status is TreatmentStatus.PENDING
    assert treatment.auto_created is True
    assert treatment.due_date == date(2026, 3, 8)
    assert treatment.evidence is None
    assert treatment.resolved_at is None


def test_nonmatching_record_creates_nothing(db_session):
    finding = create_finding(db_session, risk_score=50.0)

    outcome = process_asset_vulnerability(db_session, finding)

    assert outcome.skipped is True
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0


def test_null_risk_score_creates_nothing(db_session):
    finding = create_finding(db_session, risk_score=None)

    outcome = process_asset_vulnerability(db_session, finding)

    assert outcome.skipped is True
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0


@pytest.mark.parametrize(
    "finding",
    [
        SimpleNamespace(id=1, asset=None, vulnerability=object()),
        SimpleNamespace(id=2, asset=object(), vulnerability=None),
    ],
)
def test_missing_relationship_is_reported_safely(db_session, finding):
    with pytest.raises(DetectionRemediationError):
        process_asset_vulnerability(db_session, finding)


def test_generic_recommendation_is_used_without_solution(db_session):
    finding = create_finding(db_session, solution=None)

    process_asset_vulnerability(db_session, finding)
    treatment = db_session.scalar(select(RiskTreatment))

    assert treatment.action == GENERIC_REMEDIATION


def test_blank_owner_creates_alert_but_reports_treatment_failure(db_session):
    finding = create_finding(db_session)
    finding.asset.owner = "   "

    outcome = process_asset_vulnerability(db_session, finding)

    assert outcome.alert_created is True
    assert outcome.failed is True
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 1
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0


def test_second_execution_reuses_records_without_duplicates(db_session):
    finding = create_finding(db_session)
    first = process_asset_vulnerability(db_session, finding)
    second = process_asset_vulnerability(db_session, finding)

    assert first.alert_created and first.treatment_created
    assert second.alert_reused and second.treatment_reused
    assert not second.alert_created and not second.treatment_created
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 1
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 1


def test_bulk_rerun_reuses_or_optionally_skips_completed_rule(db_session):
    create_finding(db_session)
    first = run_detection_remediation(db_session)
    second = run_detection_remediation(db_session)
    third = run_detection_remediation(db_session, include_processed=False)

    assert first.alerts_created_count == 1
    assert first.treatments_created_count == 1
    assert second.alerts_reused_count == 1
    assert second.treatments_reused_count == 1
    assert third.skipped_count == 1
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 1
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 1


def test_existing_automatic_alert_allows_missing_treatment_creation(db_session):
    finding = create_finding(db_session)
    db_session.add(
        Alert(
            asset_vulnerability=finding,
            rule_key=CRITICAL_CONTEXTUAL_RISK_RULE,
            level=AlertLevel.CRITICAL,
            message="Existing automatic alert",
        )
    )
    db_session.commit()

    outcome = process_asset_vulnerability(db_session, finding)

    assert outcome.alert_reused is True
    assert outcome.treatment_created is True


def test_existing_automatic_treatment_allows_missing_alert_creation(db_session):
    finding = create_finding(db_session)
    db_session.add(
        RiskTreatment(
            asset_vulnerability=finding,
            rule_key=CRITICAL_CONTEXTUAL_RISK_RULE,
            action="Existing automatic action",
            owner=finding.asset.owner,
            auto_created=True,
        )
    )
    db_session.commit()

    outcome = process_asset_vulnerability(db_session, finding)

    assert outcome.treatment_reused is True
    assert outcome.alert_created is True


def test_manual_alert_does_not_block_automatic_alert(db_session):
    finding = create_finding(db_session)
    db_session.add(
        Alert(
            asset_vulnerability=finding,
            rule_key=None,
            level=AlertLevel.HIGH,
            message="Manual analyst alert",
        )
    )
    db_session.commit()

    process_asset_vulnerability(db_session, finding)

    assert db_session.scalar(select(func.count()).select_from(Alert)) == 2


def test_manual_treatment_does_not_block_automatic_treatment(db_session):
    finding = create_finding(db_session)
    db_session.add(
        RiskTreatment(
            asset_vulnerability=finding,
            rule_key=None,
            action="Manual analyst action",
            owner="SOC Team",
            auto_created=False,
        )
    )
    db_session.commit()

    process_asset_vulnerability(db_session, finding)

    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 2


def test_database_rejects_duplicate_automatic_alert_rule(db_session):
    finding = create_finding(db_session)
    for message in ["First", "Duplicate"]:
        db_session.add(
            Alert(
                asset_vulnerability=finding,
                rule_key=CRITICAL_CONTEXTUAL_RISK_RULE,
                level=AlertLevel.CRITICAL,
                message=message,
            )
        )

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_database_rejects_duplicate_automatic_treatment_rule(db_session):
    finding = create_finding(db_session)
    for action in ["First", "Duplicate"]:
        db_session.add(
            RiskTreatment(
                asset_vulnerability=finding,
                rule_key=CRITICAL_CONTEXTUAL_RISK_RULE,
                action=action,
                owner="SOC Team",
                auto_created=True,
            )
        )

    with pytest.raises(IntegrityError):
        db_session.commit()


def test_bulk_processes_only_requested_scan(db_session):
    first = create_finding(db_session, suffix=1)
    second = create_finding(db_session, suffix=2)

    result = run_detection_remediation(
        db_session, scan_id=first.scan_id, evaluation_date=DETECTION_DATE
    )

    assert result.examined_count == 1
    assert result.matched_count == 1
    assert db_session.scalar(select(Alert.asset_vulnerability_id)) == first.id
    assert second.alerts == []


def test_bulk_processes_all_scored_records_and_mixed_rules(db_session):
    matching = create_finding(db_session, suffix=1, risk_score=90.0)
    create_finding(db_session, suffix=2, risk_score=60.0)
    create_finding(db_session, suffix=3, risk_score=None)

    result = run_detection_remediation(db_session, evaluation_date=DETECTION_DATE)

    assert result.examined_count == 2
    assert result.matched_count == 1
    assert result.skipped_count == 1
    assert result.alerts_created_count == 1
    assert result.treatments_created_count == 1
    assert db_session.scalar(select(Alert.asset_vulnerability_id)) == matching.id


def test_bulk_preserves_finding_and_vulnerability_state(db_session):
    finding = create_finding(
        db_session, status=FindingStatus.IN_PROGRESS, risk_score=88.5
    )
    original_severity = finding.vulnerability.severity

    run_detection_remediation(db_session)

    assert finding.status is FindingStatus.IN_PROGRESS
    assert finding.risk_score == 88.5
    assert finding.vulnerability.severity is original_severity


def test_one_validation_failure_does_not_stop_bulk(db_session, monkeypatch):
    valid = create_finding(db_session, suffix=1)
    invalid = create_finding(db_session, suffix=2)
    real_processor = automation_module.process_asset_vulnerability

    def fail_one(db, finding, *, evaluation_date=None):
        if finding.id == invalid.id:
            raise DetectionRemediationError("Simulated invalid legacy record.")
        return real_processor(db, finding, evaluation_date=evaluation_date)

    monkeypatch.setattr(automation_module, "process_asset_vulnerability", fail_one)
    result = run_detection_remediation(db_session)

    assert result.matched_count == 1
    assert result.failed_count == 1
    assert db_session.scalar(select(Alert.asset_vulnerability_id)) == valid.id


def test_fatal_database_failure_rolls_back_entire_bulk(db_session, monkeypatch):
    create_finding(db_session, suffix=1)
    create_finding(db_session, suffix=2)

    def fail_commit():
        raise IntegrityError("forced test failure", {}, Exception("forced"))

    monkeypatch.setattr(db_session, "commit", fail_commit)
    result = run_detection_remediation(db_session)

    assert result.alerts_created_count == 0
    assert result.treatments_created_count == 0
    assert result.failed_count == 2
    assert any("rolled back" in error for error in result.errors)
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0
