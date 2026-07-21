"""M10A tests use mocks and temporary files: no Docker or network is required."""

from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

import app.lab.greenbone_preflight as preflight
from app.database import Base, configure_sqlite_foreign_keys
from app.lab.greenbone_preflight import CheckLevel, run_preflight, validate_target_ip
from app.lab.report_import import LabImportError, import_report_safely
from app.lab.report_validation import summarize_openvas_report
from app.models import Asset, AssetType, Exposure, Scan
from app.parsers.openvas import parse_openvas
from app.services.grc_pipeline import ParserResultSummary, PipelineResult
from scripts import import_openvas_report, validate_openvas_report

FIXTURES = Path(__file__).parent / "fixtures" / "openvas"


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_preflight_classifies_pass_warning_and_has_nonblocking_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(preflight.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: type("Disk", (), {"free": 5 * 1024**3})())
    summary = run_preflight(command_runner=lambda _command: completed(stdout="27.0"), disk_path=tmp_path)
    levels = {item.level for item in summary.checks}
    assert CheckLevel.PASS in levels
    assert CheckLevel.WARNING in levels
    assert summary.exit_code == 0


def test_missing_docker_is_blocking(monkeypatch, tmp_path):
    monkeypatch.setattr(preflight.shutil, "which", lambda _name: None)
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: type("Disk", (), {"free": 30 * 1024**3})())
    summary = run_preflight(disk_path=tmp_path)
    assert summary.checks[0].level is CheckLevel.FAIL
    assert summary.exit_code == 1


def test_invalid_compose_file_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: type("Disk", (), {"free": 30 * 1024**3})())
    responses = iter([completed(stdout="27.0"), completed(stdout="2.35")])
    summary = run_preflight(
        compose_file=tmp_path / "missing.yaml",
        docker_path="docker",
        command_runner=lambda _command: next(responses),
        disk_path=tmp_path,
    )
    assert any(item.name == "Compose file" and item.level is CheckLevel.FAIL for item in summary.checks)


def test_invalid_compose_configuration_is_rejected(monkeypatch, tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text("not: valid: compose", encoding="utf-8")
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: type("Disk", (), {"free": 30 * 1024**3})())
    responses = iter([
        completed(stdout="27.0"),
        completed(stdout="2.35"),
        completed(returncode=1, stderr="compose validation failed"),
    ])
    summary = run_preflight(
        compose_file=compose,
        docker_path="docker",
        command_runner=lambda _command: next(responses),
        disk_path=tmp_path,
    )
    assert any(item.name == "Compose file" and item.level is CheckLevel.FAIL for item in summary.checks)


def test_preflight_uses_only_read_only_docker_commands(monkeypatch, tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: type("Disk", (), {"free": 30 * 1024**3})())
    commands = []

    def runner(command):
        commands.append(list(command))
        if "config" in command or "ps" in command:
            return completed(stdout="\n".join(sorted(preflight.CORE_SERVICES)))
        return completed(stdout="27.0")

    summary = run_preflight(compose_file=compose, docker_path="docker", command_runner=runner, disk_path=tmp_path)
    assert summary.exit_code == 0
    assert commands == [
        ["docker", "version", "--format", "{{.Server.Version}}"],
        ["docker", "compose", "version", "--short"],
        ["docker", "compose", "-f", str(compose.resolve()), "config", "--services"],
        ["docker", "compose", "-f", str(compose.resolve()), "ps", "--services", "--filter", "status=running"],
    ]
    assert not any({"up", "down", "start", "stop", "run", "exec", "scan"} & set(command) for command in commands)


@pytest.mark.parametrize("value, expected", [("192.0.2.10", "192.0.2.10"), ("2001:0db8::10", "2001:db8::10")])
def test_target_ip_validation(value, expected):
    check, normalized = validate_target_ip(value)
    assert check.level is CheckLevel.PASS
    assert normalized == expected


def test_invalid_target_ip_is_rejected():
    check, normalized = validate_target_ip("not-an-ip")
    assert check.level is CheckLevel.FAIL
    assert normalized is None


def test_https_verifies_certificates_by_default(monkeypatch):
    seen = {}

    def fake_urlopen(_url, *, context, timeout):
        seen["verify_mode"] = context.verify_mode
        seen["timeout"] = timeout
        raise urllib.error.URLError("untrusted lab certificate")

    monkeypatch.setattr(preflight.urllib.request, "urlopen", fake_urlopen)
    result = preflight._check_https("https://127.0.0.1", False)
    assert seen["verify_mode"] == preflight.ssl.CERT_REQUIRED
    assert result.level is CheckLevel.FAIL


def test_self_signed_https_requires_explicit_opt_in(monkeypatch):
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def read(self, _size): return b"<"

    seen = {}
    def fake_urlopen(_url, *, context, timeout):
        seen["verify_mode"] = context.verify_mode
        return Response()

    monkeypatch.setattr(preflight.urllib.request, "urlopen", fake_urlopen)
    result = preflight._check_https("https://127.0.0.1", True)
    assert seen["verify_mode"] == preflight.ssl.CERT_NONE
    assert result.level is CheckLevel.WARNING


def test_validator_reports_expected_counts():
    parsed = parse_openvas(FIXTURES / "imperfect_report.xml")
    summary = summarize_openvas_report(parsed, include_examples=True)
    assert summary.findings_count == 3
    assert summary.findings_without_cves == 2
    assert summary.unique_cves == ["CVE-2023-1111", "CVE-2023-22222"]
    assert summary.cvss_distribution["high"] == 1
    assert len(summary.short_findings) == 3


def test_validator_cli_accepts_valid_and_rejects_malformed(capsys):
    assert validate_openvas_report.main([str(FIXTURES / "valid_report.xml")]) == 0
    assert "Usable findings: 1" in capsys.readouterr().out
    assert validate_openvas_report.main([str(FIXTURES / "malformed_report.xml")]) == 1
    assert "ERROR:" in capsys.readouterr().out


def test_dry_run_leaves_selected_database_unchanged(tmp_path):
    database = _create_database(tmp_path / "grc.db", include_matching_asset=True)
    before = _sha256(database)
    outcome = import_report_safely(FIXTURES / "valid_report.xml", database)
    assert outcome.mode == "DRY RUN"
    assert outcome.pipeline_result.success is True
    assert outcome.pipeline_result.scan_id == 1
    assert _sha256(database) == before
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_confirmed_import_uses_existing_pipeline_contract(tmp_path):
    database = _create_database(tmp_path / "grc.db")
    calls = []

    def fake_pipeline(xml_source, db, *, scan_date=None):
        calls.append((Path(xml_source), db, scan_date))
        return PipelineResult(parser_summary=ParserResultSummary(findings_count=1), scan_id=7, success=True)

    scan_date = datetime(2026, 7, 21, tzinfo=timezone.utc)
    outcome = import_report_safely(
        FIXTURES / "valid_report.xml",
        database,
        confirm_import=True,
        scan_date=scan_date,
        pipeline_runner=fake_pipeline,
    )
    assert outcome.mode == "CONFIRMED IMPORT"
    assert len(calls) == 1
    assert calls[0][2] == scan_date


def test_missing_confirmation_prevents_writes_even_with_pipeline(tmp_path):
    database = _create_database(tmp_path / "grc.db")
    original_hash = _sha256(database)

    def writing_pipeline(_xml, db, *, scan_date=None):
        db.add(Scan(scan_date=scan_date or datetime.now(timezone.utc), source="test", total_vulnerabilities=0))
        db.commit()
        return PipelineResult(parser_summary=ParserResultSummary(), scan_id=1, success=True)

    import_report_safely(FIXTURES / "valid_report.xml", database, pipeline_runner=writing_pipeline)
    assert _sha256(database) == original_hash


@pytest.mark.parametrize("create_file", [False, True])
def test_missing_or_unknown_database_schema_is_rejected(tmp_path, create_file):
    database = tmp_path / "unknown.db"
    if create_file:
        sqlite3.connect(database).close()
    with pytest.raises(LabImportError):
        import_report_safely(FIXTURES / "valid_report.xml", database)


def test_database_with_expected_table_names_but_wrong_columns_is_rejected(tmp_path):
    database = tmp_path / "lookalike.db"
    with sqlite3.connect(database) as connection:
        for table in ("assets", "scans", "vulnerabilities", "asset_vulnerabilities", "alerts", "risk_treatments"):
            connection.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
    with pytest.raises(LabImportError, match="missing columns"):
        import_report_safely(FIXTURES / "valid_report.xml", database)


def test_cli_default_is_dry_run(tmp_path, capsys):
    database = _create_database(tmp_path / "grc.db", include_matching_asset=True)
    before = _sha256(database)
    code = import_openvas_report.main([str(FIXTURES / "valid_report.xml"), "--database", str(database)])
    assert code == 0
    assert "DRY RUN" in capsys.readouterr().out
    assert _sha256(database) == before


def test_report_tools_do_not_execute_docker_or_network_commands(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("external command or network access attempted")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(preflight.socket, "create_connection", forbidden)
    parsed = parse_openvas(FIXTURES / "valid_report.xml")
    assert summarize_openvas_report(parsed).findings_count == 1


def _create_database(path: Path, *, include_matching_asset: bool = False) -> Path:
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    configure_sqlite_foreign_keys(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        if include_matching_asset:
            db.add(Asset(name="Authorized lab TLS host", ip_address="2001:db8::10", asset_type=AssetType.SERVER, owner="Lab Team", business_criticality=5, exposure=Exposure.EXTERNAL))
            db.commit()
        assert db.scalar(select(func.count(Scan.id))) == 0
    engine.dispose()
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
