"""Tests for read-only M8 dashboard queries and aggregations."""

from datetime import date, datetime, timezone

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError

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
from dashboard.data import (
    DashboardFilters,
    aggregate_risk_levels,
    calculate_kpis,
    create_read_only_engine,
    get_alerts,
    get_findings,
    get_scan_history,
    get_top_risky_assets,
    get_treatments,
)


@pytest.fixture()
def dashboard_records(db_session):
    scan_old = Scan(
        scan_date=datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
        source="openvas",
        total_vulnerabilities=4,
    )
    scan_new = Scan(
        scan_date=datetime(2026, 2, 1, 9, 0, tzinfo=timezone.utc),
        source="openvas",
        total_vulnerabilities=1,
    )
    server = Asset(
        name="Public server",
        ip_address="192.0.2.90",
        asset_type=AssetType.SERVER,
        owner="SOC",
        business_criticality=5,
        exposure=Exposure.EXTERNAL,
    )
    workstation = Asset(
        name="Internal workstation",
        ip_address="192.0.2.91",
        asset_type=AssetType.WORKSTATION,
        owner="Endpoint",
        business_criticality=2,
        exposure=Exposure.INTERNAL,
    )
    vulnerabilities = [
        Vulnerability(cve_id=f"CVE-2026-90{index:02d}", technical_id=None, cvss_score=cvss, title=title, severity=severity, detected_at=scan_old.scan_date, source="openvas")
        for index, (cvss, title, severity) in enumerate(
            [
                (9.0, "Critical service flaw", Severity.CRITICAL),
                (8.0, "High technical flaw", Severity.HIGH),
                (7.0, "High technical on lower-context asset", Severity.HIGH),
                (3.0, "Low technical flaw", Severity.LOW),
                (7.0, "Unscored technical flaw", Severity.HIGH),
            ],
            start=1,
        )
    ]
    db_session.add_all([scan_old, scan_new, server, workstation, *vulnerabilities])
    db_session.flush()
    findings = [
        AssetVulnerability(asset=server, vulnerability=vulnerabilities[0], scan=scan_old, risk_score=90.0, status=FindingStatus.OPEN),
        AssetVulnerability(asset=server, vulnerability=vulnerabilities[1], scan=scan_old, risk_score=60.0, status=FindingStatus.IN_PROGRESS),
        AssetVulnerability(asset=workstation, vulnerability=vulnerabilities[2], scan=scan_old, risk_score=30.0, status=FindingStatus.ACCEPTED),
        AssetVulnerability(asset=workstation, vulnerability=vulnerabilities[3], scan=scan_old, risk_score=10.0, status=FindingStatus.FIXED),
        AssetVulnerability(asset=workstation, vulnerability=vulnerabilities[4], scan=scan_new, risk_score=None, status=FindingStatus.OPEN),
    ]
    db_session.add_all(findings)
    db_session.flush()
    db_session.add_all(
        [
            Alert(asset_vulnerability=findings[0], rule_key="dashboard-critical", level=AlertLevel.CRITICAL, message="Critical contextual risk", acknowledged=False),
            Alert(asset_vulnerability=findings[1], rule_key="dashboard-high", level=AlertLevel.HIGH, message="High contextual risk", acknowledged=True),
            RiskTreatment(asset_vulnerability=findings[0], rule_key="dashboard-pending", action="Patch server", owner="SOC", due_date=date(2026, 1, 15), status=TreatmentStatus.PENDING, auto_created=True),
            RiskTreatment(asset_vulnerability=findings[1], rule_key="dashboard-complete", action="Mitigation completed", owner="SOC", due_date=date(2026, 1, 10), status=TreatmentStatus.COMPLETED, auto_created=False),
            RiskTreatment(asset_vulnerability=findings[2], rule_key="dashboard-progress", action="Upgrade component", owner="Endpoint", due_date=date(2026, 3, 1), status=TreatmentStatus.IN_PROGRESS, auto_created=False),
        ]
    )
    db_session.commit()
    return {
        "scan_old": scan_old,
        "scan_new": scan_new,
        "server": server,
        "workstation": workstation,
    }


def test_empty_database_behavior(db_session):
    findings = get_findings(db_session)
    kpis = calculate_kpis(db_session, findings)

    assert findings == []
    assert kpis.total_assets == 0
    assert kpis.total_scans == 0
    assert kpis.total_relationships == 0
    assert kpis.average_contextual_risk is None
    assert aggregate_risk_levels(findings)["unscored"] == 0


def test_kpi_calculations(db_session, dashboard_records):
    findings = get_findings(db_session)
    kpis = calculate_kpis(db_session, findings)

    assert kpis.total_assets == 2
    assert kpis.total_scans == 2
    assert kpis.total_relationships == 5
    assert kpis.open_critical_risks == 1
    assert kpis.unacknowledged_alerts == 1
    assert kpis.active_treatments == 2
    assert kpis.treatment_completion_percentage == 33.33
    assert kpis.average_contextual_risk == 47.5


def test_risk_level_aggregation_includes_unscored(db_session, dashboard_records):
    counts = aggregate_risk_levels(get_findings(db_session))

    assert counts == {"low": 1, "medium": 1, "high": 1, "critical": 1, "unscored": 1}


def test_technical_severity_is_distinct_from_contextual_risk(db_session, dashboard_records):
    rows = get_findings(db_session)
    high_technical = next(
        row
        for row in rows
        if row["vulnerability_title"] == "High technical on lower-context asset"
    )

    assert high_technical["technical_severity"] == "high"
    assert high_technical["contextual_risk_level"] == "medium"
    low_context = next(row for row in rows if row["vulnerability_title"] == "Low technical flaw")
    assert low_context["technical_severity"] == "low"
    assert low_context["contextual_risk_level"] == "low"


def test_prioritized_findings_sort_scored_descending_then_unscored(db_session, dashboard_records):
    rows = get_findings(db_session)

    assert [row["contextual_risk_score"] for row in rows] == [90.0, 60.0, 30.0, 10.0, None]


def test_top_risky_assets_aggregation(db_session, dashboard_records):
    assets = get_top_risky_assets(get_findings(db_session))

    assert assets[0]["asset_name"] == "Public server"
    assert assets[0]["maximum_risk_score"] == 90.0
    assert assets[0]["average_risk_score"] == 75.0
    assert assets[0]["open_critical_findings"] == 1
    assert assets[0]["total_findings"] == 2


def test_alert_query_returns_related_asset_and_vulnerability(db_session, dashboard_records):
    alerts = get_alerts(db_session, get_findings(db_session))

    assert len(alerts) == 2
    assert alerts[0]["asset"] == "Public server"
    assert alerts[0]["vulnerability"].startswith("CVE-")
    assert {row["acknowledged"] for row in alerts} == {True, False}


def test_treatment_query_and_overdue_calculation(db_session, dashboard_records):
    treatments = get_treatments(db_session, get_findings(db_session), as_of=date(2026, 2, 1))

    pending = next(row for row in treatments if row["status"] == "pending")
    completed = next(row for row in treatments if row["status"] == "completed")
    assert pending["overdue"] is True
    assert completed["overdue"] is False
    assert {row["status"] for row in treatments} == {"pending", "in_progress", "completed"}


def test_scan_history_aggregation(db_session, dashboard_records):
    findings = get_findings(db_session)
    history = get_scan_history(db_session, findings)

    assert len(history) == 2
    assert history[0]["imported_relationship_count"] == 4
    assert history[0]["average_risk"] == 47.5
    assert history[0]["critical_risk_count"] == 1
    assert history[0]["alert_count"] == 2
    assert history[1]["imported_relationship_count"] == 1
    assert history[1]["average_risk"] is None


def test_filtering_by_scan(db_session, dashboard_records):
    filters = DashboardFilters(scan_ids=frozenset({dashboard_records["scan_new"].id}))
    rows = get_findings(db_session, filters)

    assert len(rows) == 1
    assert rows[0]["scan_id"] == dashboard_records["scan_new"].id


def test_filtering_by_asset(db_session, dashboard_records):
    filters = DashboardFilters(asset_ids=frozenset({dashboard_records["server"].id}))
    rows = get_findings(db_session, filters)

    assert len(rows) == 2
    assert {row["asset_name"] for row in rows} == {"Public server"}


def test_filtering_by_contextual_risk_level(db_session, dashboard_records):
    filters = DashboardFilters(risk_levels=frozenset({"critical"}))
    rows = get_findings(db_session, filters)

    assert len(rows) == 1
    assert rows[0]["contextual_risk_score"] == 90.0


def test_filtering_unscored_findings(db_session, dashboard_records):
    filters = DashboardFilters(risk_levels=frozenset({"unscored"}))
    rows = get_findings(db_session, filters)

    assert len(rows) == 1
    assert rows[0]["contextual_risk_score"] is None


def test_dashboard_data_functions_perform_no_writes(db_session, dashboard_records):
    before = db_session.scalar(select(func.count()).select_from(AssetVulnerability))
    db_session.expunge_all()

    findings = get_findings(db_session)
    calculate_kpis(db_session, findings)
    aggregate_risk_levels(findings)
    get_top_risky_assets(findings)
    get_alerts(db_session, findings)
    get_treatments(db_session, findings)
    get_scan_history(db_session, findings)

    assert not db_session.new
    assert not db_session.dirty
    assert not db_session.deleted
    assert db_session.scalar(select(func.count()).select_from(AssetVulnerability)) == before


def test_read_only_engine_rejects_database_writes(test_engine):
    read_only = create_read_only_engine(test_engine.url.database)
    try:
        with read_only.connect() as connection:
            with pytest.raises(OperationalError):
                connection.execute(text("INSERT INTO scans (scan_date, source, total_vulnerabilities, imported_at) VALUES ('2026-01-01', 'test', 0, '2026-01-01')"))
    finally:
        read_only.dispose()


def test_streamlit_dashboard_module_imports_without_running():
    import dashboard.streamlit_app

    assert callable(dashboard.streamlit_app.main)
