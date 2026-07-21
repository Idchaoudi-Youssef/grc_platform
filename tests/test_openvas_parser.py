"""Tests for secure, database-independent OpenVAS XML parsing."""

from io import BytesIO
from pathlib import Path

import pytest

from app.parsers.openvas import ParsedSeverity, classify_severity, parse_openvas

FIXTURES = Path(__file__).parent / "fixtures" / "openvas"


def test_parses_one_valid_finding_from_file_path():
    result = parse_openvas(FIXTURES / "valid_report.xml")

    assert result.errors == []
    assert result.warnings == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.host == "2001:db8::10"
    assert finding.port == "443/tcp"
    assert finding.title == "Outdated TLS service"
    assert finding.description is not None
    assert finding.cvss_score == 9.8
    assert finding.severity is ParsedSeverity.CRITICAL
    assert finding.cve_ids == ["CVE-2024-10001"]
    assert finding.solution == "Upgrade the service to a supported release."
    assert finding.threat == "High"
    assert finding.nvt_oid == "1.3.6.1.4.1.25623.1.0.100001"


def test_accepts_xml_bytes():
    xml_content = (FIXTURES / "valid_report.xml").read_bytes()
    result = parse_openvas(xml_content)
    assert len(result.findings) == 1


def test_accepts_file_like_object():
    xml_content = (FIXTURES / "valid_report.xml").read_bytes()
    result = parse_openvas(BytesIO(xml_content))
    assert len(result.findings) == 1


def test_parses_multiple_findings_and_skips_empty_result():
    result = parse_openvas(FIXTURES / "imperfect_report.xml")

    assert len(result.findings) == 3
    assert any("required field(s) are missing" in issue.message for issue in result.warnings)


def test_normalizes_multiple_and_duplicate_cves():
    result = parse_openvas(FIXTURES / "imperfect_report.xml")
    assert result.findings[0].cve_ids == ["CVE-2023-1111", "CVE-2023-22222"]


def test_nocve_and_missing_cve_produce_empty_list():
    result = parse_openvas(FIXTURES / "imperfect_report.xml")
    assert result.findings[1].cve_ids == []
    assert result.findings[2].cve_ids == []


def test_missing_optional_fields_are_none():
    finding = parse_openvas(FIXTURES / "imperfect_report.xml").findings[1]
    assert finding.port is None
    assert finding.description is None
    assert finding.solution is None
    assert finding.threat is None


def test_missing_severity_defaults_to_informational_with_warning():
    result = parse_openvas(FIXTURES / "imperfect_report.xml")
    finding = result.findings[1]
    assert finding.cvss_score == 0.0
    assert finding.severity is ParsedSeverity.INFORMATIONAL
    assert any("Missing severity" in issue.message for issue in result.warnings)


def test_invalid_severity_defaults_to_informational_with_warning():
    result = parse_openvas(FIXTURES / "imperfect_report.xml")
    finding = result.findings[2]
    assert finding.cvss_score == 0.0
    assert finding.severity is ParsedSeverity.INFORMATIONAL
    assert any("Invalid severity" in issue.message for issue in result.warnings)


@pytest.mark.parametrize(
    ("cvss_score", "expected"),
    [
        (0.0, ParsedSeverity.INFORMATIONAL),
        (0.1, ParsedSeverity.LOW),
        (3.9, ParsedSeverity.LOW),
        (4.0, ParsedSeverity.MEDIUM),
        (6.9, ParsedSeverity.MEDIUM),
        (7.0, ParsedSeverity.HIGH),
        (8.9, ParsedSeverity.HIGH),
        (9.0, ParsedSeverity.CRITICAL),
        (10.0, ParsedSeverity.CRITICAL),
    ],
)
def test_cvss_boundary_classification(cvss_score, expected):
    assert classify_severity(cvss_score) is expected


def test_malformed_xml_returns_error_without_raising():
    result = parse_openvas(FIXTURES / "malformed_report.xml")
    assert result.findings == []
    assert len(result.errors) == 1
    assert "Malformed XML" in result.errors[0].message


def test_external_entity_declaration_is_rejected():
    result = parse_openvas(FIXTURES / "external_entity_report.xml")
    assert result.findings == []
    assert len(result.errors) == 1
    assert "not allowed" in result.errors[0].message


def test_empty_report_is_valid_and_has_no_findings():
    result = parse_openvas(FIXTURES / "empty_report.xml")
    assert result.findings == []
    assert result.errors == []


def test_xml_namespaces_are_supported():
    result = parse_openvas(FIXTURES / "namespaced_report.xml")
    assert result.errors == []
    assert len(result.findings) == 1
    assert result.findings[0].host == "scanner-target.example.test"
    assert result.findings[0].severity is ParsedSeverity.MEDIUM
    assert result.findings[0].cve_ids == ["CVE-2022-9876"]
