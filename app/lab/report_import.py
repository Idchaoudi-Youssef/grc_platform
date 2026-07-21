"""Safe dry-run and explicitly confirmed import of an OpenVAS XML report."""

from __future__ import annotations

import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from app.database import configure_sqlite_foreign_keys
from app.services.grc_pipeline import PipelineResult, run_grc_pipeline
from dashboard.data import DashboardDatabaseError, create_read_only_engine


PipelineRunner = Callable[..., PipelineResult]


@dataclass(frozen=True)
class LabImportResult:
    mode: str
    database_path: Path
    pipeline_result: PipelineResult


class LabImportError(RuntimeError):
    """Raised before import when files or the database schema are unsafe."""


EXPECTED_COLUMNS = {
    "assets": {"id", "ip_address", "business_criticality", "exposure"},
    "scans": {"id", "scan_date", "source", "total_vulnerabilities"},
    "vulnerabilities": {"id", "cve_id", "technical_id", "cvss_score", "severity"},
    "asset_vulnerabilities": {"id", "asset_id", "vulnerability_id", "scan_id", "risk_score"},
    "alerts": {"id", "asset_vulnerability_id", "rule_key"},
    "risk_treatments": {"id", "asset_vulnerability_id", "rule_key"},
}


def import_report_safely(
    xml_path: str | Path,
    database_path: str | Path,
    *,
    confirm_import: bool = False,
    scan_date: datetime | None = None,
    pipeline_runner: PipelineRunner = run_grc_pipeline,
) -> LabImportResult:
    report = Path(xml_path).expanduser().resolve()
    database = Path(database_path).expanduser().resolve()
    if not report.is_file():
        raise LabImportError(f"XML report does not exist: {report}")
    _validate_existing_database(database)

    if confirm_import:
        result = _run_pipeline(report, database, scan_date, pipeline_runner)
        return LabImportResult("CONFIRMED IMPORT", database, result)

    with tempfile.TemporaryDirectory(prefix="grc_openvas_dry_run_") as temporary:
        copy_path = Path(temporary) / "dry_run.db"
        _copy_sqlite_database(database, copy_path)
        result = _run_pipeline(report, copy_path, scan_date, pipeline_runner)
    return LabImportResult("DRY RUN", database, result)


def _validate_existing_database(path: Path) -> None:
    try:
        engine = create_read_only_engine(path)
    except DashboardDatabaseError as exc:
        raise LabImportError(str(exc)) from exc
    try:
        schema = inspect(engine)
        for table, expected in EXPECTED_COLUMNS.items():
            available = {column["name"] for column in schema.get_columns(table)}
            missing = expected - available
            if missing:
                raise LabImportError(
                    f"Database table '{table}' is missing columns: "
                    + ", ".join(sorted(missing))
                )
    finally:
        engine.dispose()


def _copy_sqlite_database(source: Path, destination: Path) -> None:
    """Create a consistent copy while keeping the source connection read-only."""
    source_uri = f"file:{source.as_posix()}?mode=ro"
    with sqlite3.connect(source_uri, uri=True) as source_connection:
        with sqlite3.connect(destination) as destination_connection:
            source_connection.backup(destination_connection)


def _run_pipeline(
    report: Path,
    database: Path,
    scan_date: datetime | None,
    runner: PipelineRunner,
) -> PipelineResult:
    engine = create_engine(
        f"sqlite:///{database}", connect_args={"check_same_thread": False}
    )
    configure_sqlite_foreign_keys(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    db: Session = factory()
    try:
        return runner(report, db, scan_date=scan_date)
    finally:
        db.close()
        engine.dispose()
