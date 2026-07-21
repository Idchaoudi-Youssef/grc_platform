"""End-to-end tests for the M7 GRC orchestration pipeline."""

from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

import app.services.grc_pipeline as pipeline_module
from app.models import (
    Alert,
    Asset,
    AssetType,
    AssetVulnerability,
    Exposure,
    RiskTreatment,
    Scan,
    Vulnerability,
)
from app.services.detection_remediation import run_detection_remediation
from app.services.grc_pipeline import run_grc_pipeline

FIXTURES = Path(__file__).parent / "fixtures" / "openvas"
PIPELINE_DATE = datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc)
EVALUATION_DATE = date(2026, 4, 1)


def add_pipeline_assets(db_session) -> None:
    db_session.add_all(
        [
            Asset(
                name="Public customer portal",
                ip_address="192.0.2.70",
                asset_type=AssetType.SERVER,
                owner="Web Operations Team",
                business_criticality=5,
                exposure=Exposure.EXTERNAL,
            ),
            Asset(
                name="Internal analyst workstation",
                ip_address="192.0.2.71",
                asset_type=AssetType.WORKSTATION,
                owner="Endpoint Team",
                business_criticality=2,
                exposure=Exposure.INTERNAL,
            ),
        ]
    )
    db_session.commit()


def run_test_pipeline(db_session):
    add_pipeline_assets(db_session)
    return run_grc_pipeline(
        FIXTURES / "end_to_end_report.xml",
        db_session,
        scan_date=PIPELINE_DATE,
        evaluation_date=EVALUATION_DATE,
    )


def test_successful_full_pipeline_and_result_aggregation(db_session):
    result = run_test_pipeline(db_session)

    assert result.success is True
    assert result.scan_id is not None
    assert result.parser_summary.findings_count == 3
    assert result.parser_summary.warnings_count == 1
    assert result.import_result.parsed_findings_count == 3
    assert result.import_result.imported_relationships_count == 3
    assert result.import_result.skipped_unknown_assets_count == 1
    assert result.scoring_result.examined_count == 3
    assert result.scoring_result.scored_count == 3
    assert result.detection_remediation_result.examined_count == 3
    assert result.detection_remediation_result.matched_count == 1
    assert result.detection_remediation_result.alerts_created_count == 1
    assert result.detection_remediation_result.treatments_created_count == 1
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 1


def test_multi_cve_and_all_imported_relationships_are_scored(db_session):
    result = run_test_pipeline(db_session)
    relationships = list(
        db_session.scalars(
            select(AssetVulnerability).order_by(AssetVulnerability.risk_score.desc())
        ).all()
    )

    assert result.import_result.created_vulnerabilities_count == 3
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 3
    assert len(relationships) == 3
    assert all(finding.risk_score is not None for finding in relationships)
    assert [finding.risk_score for finding in relationships] == [90.0, 22.67, 22.67]
    assert db_session.get(Scan, result.scan_id).total_vulnerabilities == 3


def test_only_critical_finding_creates_alert_and_treatment(db_session):
    run_test_pipeline(db_session)
    alert = db_session.scalar(select(Alert))
    treatment = db_session.scalar(select(RiskTreatment))

    assert alert.asset_vulnerability.asset.ip_address == "192.0.2.70"
    assert treatment.asset_vulnerability.asset.ip_address == "192.0.2.70"
    noncritical_ids = list(
        db_session.scalars(
            select(AssetVulnerability.id)
            .join(AssetVulnerability.asset)
            .where(Asset.ip_address == "192.0.2.71")
        ).all()
    )
    assert all(alert.asset_vulnerability_id != item for item in noncritical_ids)


def test_unknown_asset_and_parser_warning_do_not_abort_pipeline(db_session):
    result = run_test_pipeline(db_session)

    assert result.success is True
    assert any("Missing severity" in warning for warning in result.warnings)
    assert any("no asset matches host '192.0.2.72'" in warning for warning in result.warnings)


def test_repeated_rule_execution_after_pipeline_is_idempotent(db_session):
    result = run_test_pipeline(db_session)

    rerun = run_detection_remediation(db_session, scan_id=result.scan_id)

    assert rerun.alerts_created_count == 0
    assert rerun.treatments_created_count == 0
    assert rerun.alerts_reused_count == 1
    assert rerun.treatments_reused_count == 1
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 1
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 1


def test_fatal_parser_error_rejects_pipeline_without_database_changes(db_session):
    add_pipeline_assets(db_session)

    result = run_grc_pipeline(FIXTURES / "malformed_report.xml", db_session)

    assert result.success is False
    assert result.scan_id is None
    assert result.import_result is None
    assert result.parser_summary.errors_count == 1
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 0


def test_scoring_failure_rolls_back_imported_scan(db_session, monkeypatch):
    add_pipeline_assets(db_session)

    def fail_scoring(*args, **kwargs):
        raise IntegrityError("forced scoring failure", {}, Exception("forced"))

    monkeypatch.setattr(
        pipeline_module, "score_asset_vulnerabilities", fail_scoring
    )
    result = run_grc_pipeline(
        FIXTURES / "end_to_end_report.xml", db_session, scan_date=PIPELINE_DATE
    )

    assert result.success is False
    assert any("rolled back" in error for error in result.errors)
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 0
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 0
    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == 0


def test_detection_failure_rolls_back_import_and_scores(db_session, monkeypatch):
    add_pipeline_assets(db_session)

    def fail_detection(*args, **kwargs):
        raise IntegrityError("forced detection failure", {}, Exception("forced"))

    monkeypatch.setattr(pipeline_module, "run_detection_remediation", fail_detection)
    result = run_grc_pipeline(
        FIXTURES / "end_to_end_report.xml", db_session, scan_date=PIPELINE_DATE
    )

    assert result.success is False
    assert any("rolled back" in error for error in result.errors)
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 0
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 0
    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == 0
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0
