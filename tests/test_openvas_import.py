"""Tests for transactional import of normalized OpenVAS findings."""

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import (
    Alert,
    Asset,
    AssetType,
    AssetVulnerability,
    RiskTreatment,
    Scan,
    Severity,
    Vulnerability,
)
from app.parsers.openvas import (
    OpenVASParseResult,
    ParsedFinding,
    ParsedSeverity,
    ParserIssue,
    parse_openvas,
)
from app.services.openvas_import import import_openvas_results

FIXTURES = Path(__file__).parent / "fixtures" / "openvas"
SCAN_DATE = datetime(2026, 1, 15, 10, 30, tzinfo=timezone.utc)


def add_asset(db_session, ip_address: str, name: str = "Lab server") -> Asset:
    asset = Asset(
        name=name,
        ip_address=ip_address,
        asset_type=AssetType.SERVER,
        owner="Infrastructure Team",
        business_criticality=4,
        exposure="internal",
    )
    db_session.add(asset)
    db_session.commit()
    return asset


def make_finding(
    host: str = "192.0.2.10",
    *,
    title: str = "Outdated service",
    cvss_score: float = 7.5,
    cve_ids: list[str] | None = None,
    nvt_oid: str | None = "1.3.6.1.4.1.25623.1.0.200001",
) -> ParsedFinding:
    return ParsedFinding(
        host=host,
        port="443/tcp",
        title=title,
        description="Sanitized vulnerability description",
        cvss_score=cvss_score,
        severity=(
            ParsedSeverity.CRITICAL if cvss_score >= 9 else ParsedSeverity.HIGH
        ),
        cve_ids=cve_ids or [],
        solution="Apply the vendor update",
        threat="High",
        nvt_oid=nvt_oid,
    )


def test_imports_one_valid_finding_and_matches_asset_by_ip(db_session):
    asset = add_asset(db_session, "2001:db8::10")
    parsed = parse_openvas(FIXTURES / "valid_report.xml")

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.scan_id is not None
    assert result.parsed_findings_count == 1
    assert result.imported_relationships_count == 1
    finding = db_session.scalar(select(AssetVulnerability))
    assert finding.asset_id == asset.id
    assert finding.risk_score is None
    assert finding.first_seen_at == finding.last_seen_at
    assert finding.first_seen_at == finding.scan.scan_date
    assert finding.vulnerability.detected_at == finding.scan.scan_date
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0
    assert db_session.scalar(select(func.count()).select_from(RiskTreatment)) == 0


def test_imports_multiple_findings(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[
            make_finding(cve_ids=["CVE-2025-1001"]),
            make_finding(title="Second service issue", cve_ids=["CVE-2025-1002"]),
        ]
    )

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.imported_relationships_count == 2
    assert result.created_vulnerabilities_count == 2
    assert db_session.get(Scan, result.scan_id).total_vulnerabilities == 2


def test_unknown_asset_is_skipped_without_creating_vulnerability(db_session):
    parsed = OpenVASParseResult(
        findings=[make_finding(host="192.0.2.99", cve_ids=["CVE-2025-2001"])]
    )

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.scan_id is not None
    assert result.skipped_unknown_assets_count == 1
    assert result.skipped_findings_count == 1
    assert result.imported_relationships_count == 0
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 0
    assert db_session.get(Scan, result.scan_id).total_vulnerabilities == 0


def test_one_finding_with_multiple_cves_creates_one_relationship_per_cve(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[
            make_finding(cve_ids=["CVE-2025-3001", "CVE-2025-3002"])
        ]
    )

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.created_vulnerabilities_count == 2
    assert result.imported_relationships_count == 2
    assert db_session.get(Scan, result.scan_id).total_vulnerabilities == 2


def test_reuses_existing_cve_vulnerability_and_preserves_metadata(db_session):
    add_asset(db_session, "192.0.2.10")
    existing = Vulnerability(
        cve_id="CVE-2025-4001",
        technical_id=None,
        cvss_score=5.0,
        title="Original trusted title",
        description="Original description",
        severity=Severity.MEDIUM,
        detected_at=SCAN_DATE,
        source="openvas",
    )
    db_session.add(existing)
    db_session.commit()

    parsed = OpenVASParseResult(
        findings=[make_finding(cve_ids=["CVE-2025-4001"])]
    )
    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.created_vulnerabilities_count == 0
    assert result.reused_vulnerabilities_count == 1
    assert existing.title == "Original trusted title"
    assert existing.cvss_score == 5.0
    assert any("preserved its original metadata" in warning for warning in result.warnings)


def test_non_cve_finding_uses_nvt_oid_identity(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(findings=[make_finding(cve_ids=[])])

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)
    vulnerability = db_session.scalar(select(Vulnerability))

    assert result.created_vulnerabilities_count == 1
    assert vulnerability.cve_id is None
    assert vulnerability.technical_id == "nvt:1.3.6.1.4.1.25623.1.0.200001"


def test_non_cve_finding_uses_stable_fallback_fingerprint(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[make_finding(cve_ids=[], nvt_oid=None)]
    )

    first = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)
    second = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)
    vulnerability = db_session.scalar(select(Vulnerability))

    assert vulnerability.technical_id.startswith("fingerprint:")
    assert first.created_vulnerabilities_count == 1
    assert second.reused_vulnerabilities_count == 1
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 1


def test_duplicate_finding_inside_one_scan_is_ignored(db_session):
    add_asset(db_session, "192.0.2.10")
    duplicate = make_finding(cve_ids=["CVE-2025-5001"])
    parsed = OpenVASParseResult(findings=[duplicate, duplicate.model_copy()])

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.imported_relationships_count == 1
    assert result.skipped_findings_count == 1
    assert any("duplicate ignored" in warning for warning in result.warnings)
    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == 1


def test_same_vulnerability_can_be_imported_on_two_assets(db_session):
    add_asset(db_session, "192.0.2.10", "First server")
    add_asset(db_session, "192.0.2.11", "Second server")
    parsed = OpenVASParseResult(
        findings=[
            make_finding(host="192.0.2.10", cve_ids=["CVE-2025-6001"]),
            make_finding(host="192.0.2.11", cve_ids=["CVE-2025-6001"]),
        ]
    )

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.created_vulnerabilities_count == 1
    assert result.reused_vulnerabilities_count == 1
    assert result.imported_relationships_count == 2
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 1


def test_same_report_imported_twice_creates_two_scans(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[make_finding(cve_ids=["CVE-2025-7001"])]
    )

    first = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)
    second = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert first.scan_id != second.scan_id
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 2
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 1
    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == 2


def test_parser_warnings_are_propagated(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[make_finding(cve_ids=["CVE-2025-8001"])],
        warnings=[ParserIssue(result_index=1, message="Example parser warning")],
    )

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert "Parser warning result 1: Example parser warning" in result.warnings


def test_fatal_parser_result_is_rejected_without_scan(db_session):
    parsed = parse_openvas(FIXTURES / "malformed_report.xml")

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.scan_id is None
    assert result.imported_relationships_count == 0
    assert any("fatal errors" in error for error in result.errors)
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 0


def test_database_failure_rolls_back_entire_import(db_session, monkeypatch):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[make_finding(cve_ids=["CVE-2025-9001"])]
    )

    def fail_commit():
        raise IntegrityError("forced test failure", {}, Exception("forced"))

    monkeypatch.setattr(db_session, "commit", fail_commit)
    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)

    assert result.scan_id is None
    assert result.imported_relationships_count == 0
    assert any("rolled back" in error for error in result.errors)
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 0
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 0
    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == 0


def test_imported_relationship_has_valid_foreign_keys(db_session):
    add_asset(db_session, "192.0.2.10")
    parsed = OpenVASParseResult(
        findings=[make_finding(cve_ids=["CVE-2025-9999"])]
    )

    result = import_openvas_results(parsed, db_session, scan_date=SCAN_DATE)
    relationship = db_session.scalar(select(AssetVulnerability))

    assert relationship.asset is not None
    assert relationship.vulnerability is not None
    assert relationship.scan_id == result.scan_id
