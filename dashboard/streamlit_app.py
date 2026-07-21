"""Simple read-only Streamlit dashboard for the GRC platform."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.data import (  # noqa: E402
    DashboardDatabaseError,
    DashboardFilters,
    aggregate_risk_levels,
    calculate_kpis,
    executive_summary,
    get_alerts,
    get_findings,
    get_scan_history,
    get_top_risky_assets,
    get_treatments,
    list_filter_options,
    read_only_session,
)

DEFAULT_DATABASE = PROJECT_ROOT / "grc.db"
DATABASE_ENVIRONMENT_VARIABLE = "GRC_DASHBOARD_DB"


def main() -> None:
    """Render the dashboard without offering any database write action."""
    st.set_page_config(page_title="GRC Risk Dashboard", page_icon="🛡️", layout="wide")
    st.title("GRC vulnerability management dashboard")
    st.caption(
        "Read-only view. Technical severity comes from OpenVAS; contextual risk "
        "adds asset criticality and exposure using the M5 thresholds."
    )

    default_path = os.getenv(DATABASE_ENVIRONMENT_VARIABLE, str(DEFAULT_DATABASE))
    database_path = st.sidebar.text_input("SQLite database path", value=default_path)
    st.sidebar.caption("The dashboard opens this file in SQLite read-only/query-only mode.")

    try:
        with read_only_session(database_path) as db:
            options = list_filter_options(db)
            filters = _sidebar_filters(options)
            findings = get_findings(db, filters)
            if not options["assets"] and not options["scans"]:
                st.info("The selected database contains the required tables but no data yet.")
                return
            if not findings:
                st.warning("No findings match the selected filters.")

            alerts = get_alerts(db, findings)
            treatments = get_treatments(db, findings)
            history = get_scan_history(db, findings, filters)
            kpis = calculate_kpis(db, findings, filters)
            summary = executive_summary(findings, treatments, history)
    except DashboardDatabaseError as exc:
        st.error(str(exc))
        return
    except Exception as exc:
        st.error(f"The dashboard could not read the selected database: {exc}")
        return

    _render_executive_overview(kpis, summary)
    _render_risk_levels(findings)
    _render_technical_contextual_comparison(findings)
    _render_prioritized_findings(findings)
    _render_top_assets(findings)
    _render_alerts(alerts)
    _render_treatments(treatments)
    _render_scan_history(history)


def _sidebar_filters(options: dict[str, list]) -> DashboardFilters:
    st.sidebar.header("Filters")
    if st.sidebar.button("Reset filters", width="stretch"):
        for key in list(st.session_state):
            if key.startswith("filter_"):
                del st.session_state[key]
        st.rerun()

    scan_label_to_id = dict(options["scans"])
    asset_label_to_id = dict(options["assets"])
    selected_scans = st.sidebar.multiselect("Scan", list(scan_label_to_id), key="filter_scans")
    selected_assets = st.sidebar.multiselect("Asset", list(asset_label_to_id), key="filter_assets")
    asset_types = st.sidebar.multiselect("Asset type", options["asset_types"], key="filter_asset_types")
    exposures = st.sidebar.multiselect("Exposure", options["exposures"], key="filter_exposures")
    risk_levels = st.sidebar.multiselect(
        "Contextual risk level",
        [*options["risk_levels"], "unscored"],
        key="filter_risk_levels",
    )
    statuses = st.sidebar.multiselect("Finding status", options["finding_statuses"], key="filter_statuses")
    severities = st.sidebar.multiselect(
        "Technical severity", options["technical_severities"], key="filter_severities"
    )
    return DashboardFilters(
        scan_ids=frozenset(scan_label_to_id[label] for label in selected_scans),
        asset_ids=frozenset(asset_label_to_id[label] for label in selected_assets),
        asset_types=frozenset(asset_types),
        exposures=frozenset(exposures),
        risk_levels=frozenset(risk_levels),
        finding_statuses=frozenset(statuses),
        technical_severities=frozenset(severities),
    )


def _render_executive_overview(kpis, summary) -> None:
    st.header("Executive overview")
    first = st.columns(4)
    first[0].metric("Assets", kpis.total_assets)
    first[1].metric("Scans", kpis.total_scans)
    first[2].metric("Imported relationships", kpis.total_relationships)
    first[3].metric("Open critical contextual risks", kpis.open_critical_risks)
    second = st.columns(4)
    second[0].metric("Unacknowledged alerts", kpis.unacknowledged_alerts)
    second[1].metric("Active treatments", kpis.active_treatments)
    second[2].metric("Treatment completion", f"{kpis.treatment_completion_percentage:.2f}%")
    average = "Not scored" if kpis.average_contextual_risk is None else f"{kpis.average_contextual_risk:.2f}"
    second[3].metric("Average contextual risk", average)

    latest = summary["latest_scan_date"]
    latest_text = latest.strftime("%Y-%m-%d %H:%M") if latest else "No scan"
    st.info(
        f"Critical risks: {summary['critical_risks']} | "
        f"Most exposed asset: {summary['most_exposed_asset'] or 'None'} | "
        f"Overdue treatments: {summary['overdue_treatments']} | "
        f"Latest scan: {latest_text}"
    )


def _render_risk_levels(findings) -> None:
    st.header("Risks by contextual level")
    counts = aggregate_risk_levels(findings)
    chart_rows = [{"level": level, "count": count} for level, count in counts.items() if level != "unscored"]
    st.bar_chart(chart_rows, x="level", y="count", horizontal=True)
    st.caption(f"Unscored findings shown separately: {counts['unscored']}")


def _render_technical_contextual_comparison(findings) -> None:
    st.header("Technical severity versus contextual business risk")
    st.caption("These columns answer different questions and can legitimately have different levels.")
    columns = [
        "asset_name",
        "vulnerability",
        "technical_severity",
        "cvss",
        "contextual_risk_score",
        "contextual_risk_level",
    ]
    st.dataframe([{key: row[key] for key in columns} for row in findings], width="stretch")


def _render_prioritized_findings(findings) -> None:
    st.header("Prioritized findings")
    columns = [
        "asset_name", "ip_address", "asset_type", "business_criticality", "exposure",
        "vulnerability", "vulnerability_title", "cvss", "technical_severity",
        "contextual_risk_score", "contextual_risk_level", "workflow_status", "scan_date",
    ]
    st.dataframe([{key: row[key] for key in columns} for row in findings], width="stretch")


def _render_top_assets(findings) -> None:
    st.header("Top risky assets")
    st.dataframe(get_top_risky_assets(findings), width="stretch")


def _render_alerts(alerts) -> None:
    st.header("Alerts")
    st.dataframe(alerts, width="stretch")


def _render_treatments(treatments) -> None:
    st.header("Remediation treatments")
    st.dataframe(treatments, width="stretch")


def _render_scan_history(history) -> None:
    st.header("Scan history")
    st.dataframe(history, width="stretch")
    if len(history) >= 2:
        st.subheader("Average contextual-risk trend")
        st.line_chart(history, x="scan_date", y="average_risk")


if __name__ == "__main__":
    main()
