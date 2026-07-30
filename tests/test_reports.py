"""Deterministic tests for read-only M9 PDF reports."""

import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from pypdf import PdfReader
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.database import Base, configure_sqlite_foreign_keys
from app.models import FindingStatus, RiskTreatment, Vulnerability
from app.reports.data import (
    EmptyReportDatabaseError,
    UnknownScanError,
    classify_posture,
    load_report_snapshot,
)
from app.reports.executive import generate_executive_report
from app.reports.technical import (
    generate_technical_findings_appendix,
    generate_technical_report,
)
from app.reports.technical_summary import (
    TOP_PRIORITY_LIMIT,
    generate_technical_summary_report,
    select_summary_priorities,
)
from app.services.detection_remediation import run_detection_remediation
from app.services.risk_scoring import score_asset_vulnerabilities
from dashboard.data import (
    DashboardDatabaseError,
    DatabaseNotFoundError,
    DatabaseSchemaError,
    create_read_only_engine,
    read_only_session,
)
from scripts import generate_reports as report_cli
from scripts.prepare_dashboard_demo import (
    _add_workflow_examples,
    _create_assets,
    _create_findings,
    _create_scans,
    _create_vulnerabilities,
)

GENERATED_AT = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def report_database(tmp_path):
    database = tmp_path / "report_test.db"
    engine = create_engine(
        f"sqlite:///{database}", connect_args={"check_same_thread": False}
    )
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
    finally:
        db.close()
        engine.dispose()
    return database


def test_executive_report_generation_signature_pages_and_text(report_database, tmp_path):
    output = generate_executive_report(
        report_database,
        tmp_path / "executive.pdf",
        organization="Test Organization",
        generation_date=GENERATED_AT,
    )
    reader = PdfReader(output)
    text_content = _pdf_text(reader)

    assert output.read_bytes().startswith(b"%PDF-")
    assert output.stat().st_size > 1_000
    assert len(reader.pages) == 1
    assert "Executive GRC Risk Report" in text_content
    assert "Executive posture summary" in text_content
    assert "Average contextual risk" in text_content
    assert "Management recommendations" in text_content
    assert "Normalized relationships" in text_content
    assert "Imported findings" not in text_content
    assert (
        "Chart counts represent normalized relationships, not source scanner findings."
        in _normalized_text(text_content)
    )
    assert (
        "Source scanner findings: Not retained in the current database"
        in _normalized_text(text_content)
    )


def test_technical_summary_is_exactly_three_pages_and_extractable(
    report_database, tmp_path
):
    output = generate_technical_summary_report(
        report_database,
        tmp_path / "technical_summary.pdf",
        scan_id=1,
        generation_date=GENERATED_AT,
        source_finding_count=3,
    )
    reader = PdfReader(output)
    text_content = _pdf_text(reader)

    assert output.read_bytes().startswith(b"%PDF-")
    assert len(reader.pages) == 3
    assert all((page.extract_text() or "").strip() for page in reader.pages)
    assert "Page 1 - Scope and security posture" in text_content
    assert "Page 2 - Prioritization" in text_content
    assert "Page 3 - Governance and remediation" in text_content
    normalized = _normalized_text(text_content)
    assert "Source scanner findings: 3" in normalized
    assert "Normalized asset-vulnerability relationships: 4" in normalized
    assert "Showing the top 4 of 4 normalized relationships" in normalized
    assert (
        "Normalized relationships by technical CVSS severity (n=4)"
        in normalized
    )
    assert (
        "Normalized relationships by contextual business risk (n=4)"
        in normalized
    )
    assert "does not automatically patch" in text_content
    assert "CVE-2026-8001" in text_content
    assert "Description:" not in text_content
    assert "OpenVAS solution:" not in text_content


def test_technical_appendix_preserves_every_detailed_finding(
    report_database, tmp_path
):
    output = generate_technical_findings_appendix(
        report_database,
        tmp_path / "technical_findings_appendix.pdf",
        scan_id=1,
        generation_date=GENERATED_AT,
        source_finding_count=3,
    )
    reader = PdfReader(output)
    text_content = _pdf_text(reader)

    assert output.read_bytes().startswith(b"%PDF-")
    assert len(reader.pages) >= 2
    assert "Technical Findings Appendix" in text_content
    assert "Source scanner findings: 3" in _normalized_text(text_content)
    assert "all 4 normalized asset-vulnerability relationships" in _normalized_text(
        text_content
    )
    assert "Detailed normalized relationships" in text_content
    assert text_content.count("Relationship status") == 4
    assert "Description:" in text_content
    assert "OpenVAS solution:" in text_content


def test_summary_priority_subset_is_capped_without_reordering():
    findings = [{"finding_id": index} for index in range(TOP_PRIORITY_LIMIT + 4)]

    selected = select_summary_priorities(findings)

    assert len(selected) == TOP_PRIORITY_LIMIT
    assert selected == findings[:TOP_PRIORITY_LIMIT]


def test_missing_source_count_is_not_reconstructed_from_relationships(
    report_database, tmp_path
):
    output = generate_technical_summary_report(
        report_database,
        tmp_path / "missing_source_count.pdf",
        scan_id=1,
        generation_date=GENERATED_AT,
    )
    text_content = _normalized_text(_pdf_text(PdfReader(output)))

    assert "Normalized asset-vulnerability relationships: 4" in text_content
    assert (
        "Source scanner findings: Not retained in the current database"
        in text_content
    )
    assert "Source scanner findings: 4" not in text_content


def test_latest_scan_is_selected_by_default(report_database):
    with read_only_session(report_database) as db:
        snapshot = load_report_snapshot(db, generation_date=GENERATED_AT)

    assert snapshot.scan.scan_date == datetime(2026, 4, 1, 10, 0)
    assert snapshot.kpis.total_relationships == 2


def test_explicit_scan_selection(report_database):
    with read_only_session(report_database) as db:
        snapshot = load_report_snapshot(db, scan_id=1, generation_date=GENERATED_AT)

    assert snapshot.scan.id == 1
    assert snapshot.kpis.total_relationships == 4


def test_unknown_scan_id_is_rejected(report_database):
    with read_only_session(report_database) as db:
        with pytest.raises(UnknownScanError, match="Scan 999 does not exist"):
            load_report_snapshot(db, scan_id=999, generation_date=GENERATED_AT)


def test_empty_database_is_rejected(test_engine):
    session_factory = sessionmaker(bind=test_engine)
    db = session_factory()
    try:
        with pytest.raises(EmptyReportDatabaseError, match="contains no scans"):
            load_report_snapshot(db, generation_date=GENERATED_AT)
    finally:
        db.close()


def test_missing_schema_is_rejected(tmp_path):
    database = tmp_path / "wrong_schema.db"
    engine = create_engine(f"sqlite:///{database}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"))
    engine.dispose()

    with pytest.raises(DatabaseSchemaError, match="tables are missing"):
        generate_executive_report(database, tmp_path / "never_created.pdf")


def test_missing_database_is_rejected(tmp_path):
    with pytest.raises(DatabaseNotFoundError, match="does not exist"):
        generate_executive_report(
            tmp_path / "missing.db", tmp_path / "never_created.pdf"
        )


def test_invalid_database_is_rejected(tmp_path):
    database = tmp_path / "invalid.db"
    database.write_bytes(b"not a SQLite database")
    with pytest.raises(DashboardDatabaseError, match="Database read failed"):
        generate_technical_report(database, tmp_path / "never_created.pdf")


def test_selected_scan_kpis_are_accurate(report_database):
    with read_only_session(report_database) as db:
        snapshot = load_report_snapshot(db, generation_date=GENERATED_AT)

    assert snapshot.kpis.total_assets == 2
    assert snapshot.kpis.total_relationships == 2
    assert snapshot.kpis.average_contextual_risk == 66.34
    assert snapshot.kpis.open_critical_risks == 1
    assert snapshot.kpis.unacknowledged_alerts == 1
    assert snapshot.kpis.active_treatments == 1
    assert snapshot.kpis.treatment_completion_percentage == 0.0


@pytest.mark.parametrize(
    ("level", "expected"),
    [("critical", "Critical"), ("high", "High"), ("medium", "Moderate"), ("low", "Low")],
)
def test_posture_classification(level, expected):
    finding = {
        "contextual_risk_level": level,
        "workflow_status": FindingStatus.OPEN.value,
    }
    assert classify_posture([finding]) == expected


def test_fixed_critical_does_not_raise_posture():
    finding = {
        "contextual_risk_level": "critical",
        "workflow_status": FindingStatus.FIXED.value,
    }
    assert classify_posture([finding]) == "Low"


def test_top_priorities_are_ordered_by_descending_risk(report_database):
    with read_only_session(report_database) as db:
        snapshot = load_report_snapshot(db, scan_id=1, generation_date=GENERATED_AT)

    scores = [item["contextual_risk_score"] for item in snapshot.priorities]
    assert scores == sorted(scores, reverse=True)
    assert snapshot.priorities[0]["vulnerability"] == "CVE-2026-8001"


def test_overdue_treatment_logic_uses_generation_date(report_database):
    with read_only_session(report_database) as db:
        snapshot = load_report_snapshot(db, generation_date=GENERATED_AT)

    assert len(snapshot.treatments) == 1
    assert snapshot.treatments[0]["status"] == "in_progress"
    assert snapshot.treatments[0]["overdue"] is True
    assert any("overdue treatment" in item.lower() for item in snapshot.recommendations)


def test_risk_level_distribution_for_latest_scan(report_database):
    with read_only_session(report_database) as db:
        snapshot = load_report_snapshot(db, generation_date=GENERATED_AT)

    assert snapshot.risk_distribution == {
        "low": 0,
        "medium": 1,
        "high": 0,
        "critical": 1,
        "unscored": 0,
    }


def test_long_text_wraps_without_generation_failure(report_database, tmp_path):
    engine = create_engine(f"sqlite:///{report_database}")
    session_factory = sessionmaker(bind=engine)
    db = session_factory()
    try:
        vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-8001"))
        vulnerability.title = "Very long vulnerability title " * 20
        vulnerability.description = "Long technical description for wrapping verification. " * 80
        treatment = db.scalar(select(RiskTreatment).where(RiskTreatment.asset_vulnerability_id.is_not(None)))
        treatment.action = "Long remediation action for wrapping verification. " * 80
        db.commit()
    finally:
        db.close()
        engine.dispose()

    output = generate_technical_report(
        report_database, tmp_path / "long_text.pdf", scan_id=1, generation_date=GENERATED_AT
    )
    text_content = _pdf_text(PdfReader(output))
    assert "Very long vulnerability title" in text_content
    assert "Long technical description" in text_content
    assert len(PdfReader(output).pages) >= 2


def test_summary_handles_empty_alerts_and_treatments(report_database, tmp_path):
    engine = create_engine(f"sqlite:///{report_database}")
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM alerts"))
        connection.execute(text("DELETE FROM risk_treatments"))
    engine.dispose()

    output = generate_technical_summary_report(
        report_database,
        tmp_path / "empty_governance.pdf",
        scan_id=1,
        generation_date=GENERATED_AT,
    )
    reader = PdfReader(output)
    text_content = _pdf_text(reader)

    assert len(reader.pages) == 3
    assert re.search(r"\b0\s+Alerts\b", text_content)
    assert re.search(r"\b0\s+Treatments\b", text_content)
    assert "Automation boundary" in text_content


def test_summary_keeps_technical_severity_distinct_from_contextual_risk(
    report_database, tmp_path
):
    output = generate_technical_summary_report(
        report_database,
        tmp_path / "risk_concepts.pdf",
        scan_id=1,
        generation_date=GENERATED_AT,
    )
    text_content = _pdf_text(PdfReader(output))

    assert "OpenVAS CVSS measures technical vulnerability severity." in text_content
    assert "Contextual business risk re-prioritizes each relationship" in text_content
    normalized = _normalized_text(text_content)
    assert "Normalized relationships by technical CVSS severity (n=4)" in normalized
    assert "Normalized relationships by contextual business risk (n=4)" in normalized


def test_temporary_chart_images_are_removed(report_database, tmp_path, monkeypatch):
    temp_root = tmp_path / "chart_temp"
    monkeypatch.setattr("app.reports.executive.TEMP_ROOT", temp_root)
    generate_executive_report(
        report_database, tmp_path / "executive.pdf", generation_date=GENERATED_AT
    )

    assert temp_root.exists()
    assert list(temp_root.rglob("*.png")) == []
    assert [path for path in temp_root.iterdir()] == []


def test_report_generation_performs_no_database_writes(report_database, tmp_path):
    before = _database_fingerprint(report_database)
    executive_path = generate_executive_report(
        report_database, tmp_path / "executive.pdf", generation_date=GENERATED_AT
    )
    summary_path = generate_technical_summary_report(
        report_database, tmp_path / "technical_summary.pdf", generation_date=GENERATED_AT
    )
    appendix_path = generate_technical_findings_appendix(
        report_database, tmp_path / "technical_appendix.pdf", generation_date=GENERATED_AT
    )
    after = _database_fingerprint(report_database)

    assert before == after
    for path in (executive_path, summary_path, appendix_path):
        assert (
            "Source scanner findings: Not retained in the current database"
            in _normalized_text(_pdf_text(PdfReader(path)))
        )
    read_only_engine = create_read_only_engine(report_database)
    try:
        with read_only_engine.connect() as connection:
            assert connection.execute(text("PRAGMA query_only")).scalar_one() == 1
    finally:
        read_only_engine.dispose()


def test_cli_generates_all_three_named_reports(report_database, tmp_path, monkeypatch):
    output_directory = tmp_path / "cli_reports"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate_reports.py",
            "--database",
            str(report_database),
            "--output-dir",
            str(output_directory),
            "--scan-id",
            "1",
            "--source-finding-count",
            "3",
            "--generation-date",
            "2026-05-01T12:00:00+00:00",
        ],
    )

    assert report_cli.main() == 0
    executive = PdfReader(output_directory / "executive_report.pdf")
    summary = PdfReader(output_directory / "technical_summary_report.pdf")
    appendix = PdfReader(output_directory / "technical_findings_appendix.pdf")

    assert len(executive.pages) == 1
    assert len(summary.pages) == 3
    for reader in (executive, summary, appendix):
        assert "Source scanner findings: 3" in _normalized_text(_pdf_text(reader))
    assert _pdf_text(appendix).count("Relationship status") == 4
    assert sorted(path.name for path in output_directory.iterdir()) == [
        "executive_report.pdf",
        "technical_findings_appendix.pdf",
        "technical_summary_report.pdf",
    ]


def test_unwritable_output_target_has_clear_error(report_database, tmp_path):
    directory_target = tmp_path / "is_a_directory"
    directory_target.mkdir()
    with pytest.raises(OSError, match="Cannot write executive report"):
        generate_executive_report(
            report_database, directory_target, generation_date=GENERATED_AT
        )


def _pdf_text(reader: PdfReader) -> str:
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _normalized_text(value: str) -> str:
    return " ".join(value.split())


def _database_fingerprint(path: Path) -> tuple[int, int, bytes]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, path.read_bytes()
