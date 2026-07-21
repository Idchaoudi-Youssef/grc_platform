"""Run the complete GRC pipeline against a dedicated disposable demo database."""

from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import joinedload, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import Base, configure_sqlite_foreign_keys  # noqa: E402
from app.models import (  # noqa: E402
    Asset,
    AssetType,
    AssetVulnerability,
    Exposure,
)
from app.services.grc_pipeline import run_grc_pipeline  # noqa: E402
from app.services.risk_scoring import classify_risk_level  # noqa: E402

DEMO_DATABASE = Path(__file__).resolve().with_name("grc_pipeline_demo.db")
DEMO_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "openvas" / "end_to_end_report.xml"


def reset_demo_database() -> None:
    """Delete only the dedicated M7 demo database, never the normal grc.db."""
    expected = Path(__file__).resolve().parent / "grc_pipeline_demo.db"
    if DEMO_DATABASE != expected:
        raise RuntimeError(f"Unexpected demo database path: {DEMO_DATABASE}")
    if DEMO_DATABASE.exists():
        DEMO_DATABASE.unlink()


def create_demo_assets(db) -> None:
    db.add_all(
        [
            Asset(
                name="DEMO - Public customer portal",
                ip_address="192.0.2.70",
                asset_type=AssetType.SERVER,
                owner="Demo Web Operations Team",
                business_criticality=5,
                exposure=Exposure.EXTERNAL,
                description="Demonstration data only",
            ),
            Asset(
                name="DEMO - Internal analyst workstation",
                ip_address="192.0.2.71",
                asset_type=AssetType.WORKSTATION,
                owner="Demo Endpoint Team",
                business_criticality=2,
                exposure=Exposure.INTERNAL,
                description="Demonstration data only",
            ),
        ]
    )
    db.commit()


def main() -> int:
    reset_demo_database()
    demo_engine = create_engine(
        f"sqlite:///{DEMO_DATABASE}",
        connect_args={"check_same_thread": False},
    )
    configure_sqlite_foreign_keys(demo_engine)
    Base.metadata.create_all(bind=demo_engine)
    DemoSession = sessionmaker(autocommit=False, autoflush=False, bind=demo_engine)
    db = DemoSession()

    try:
        create_demo_assets(db)
        result = run_grc_pipeline(
            DEMO_FIXTURE,
            db,
            scan_date=datetime(2026, 4, 1, 10, 0, tzinfo=timezone.utc),
            evaluation_date=date(2026, 4, 1),
        )

        print("=== GRC PIPELINE DEMONSTRATION ===")
        print(f"Dedicated demo database: {DEMO_DATABASE}")
        print("Data label: DEMONSTRATION DATA ONLY")
        print(f"Pipeline success: {result.success}")
        print(f"Scan ID: {result.scan_id}")
        print(f"Parsed findings: {result.parser_summary.findings_count}")
        print(
            "Findings imported: "
            f"{result.import_result.imported_relationships_count if result.import_result else 0}"
        )
        print(
            "Vulnerabilities scored: "
            f"{result.scoring_result.scored_count if result.scoring_result else 0}"
        )
        print(
            "Alerts created: "
            f"{result.detection_remediation_result.alerts_created_count if result.detection_remediation_result else 0}"
        )
        print(
            "Treatments created: "
            f"{result.detection_remediation_result.treatments_created_count if result.detection_remediation_result else 0}"
        )

        print("Warnings:")
        if result.warnings:
            for warning in result.warnings:
                print(f"  - {warning}")
        else:
            print("  - None")

        findings = list(
            db.scalars(
                select(AssetVulnerability)
                .where(AssetVulnerability.scan_id == result.scan_id)
                .options(
                    joinedload(AssetVulnerability.asset),
                    joinedload(AssetVulnerability.vulnerability),
                )
                .order_by(AssetVulnerability.risk_score.desc())
            ).all()
        )
        print("Prioritized findings:")
        for position, finding in enumerate(findings, start=1):
            identity = (
                finding.vulnerability.cve_id
                or finding.vulnerability.technical_id
                or "unknown"
            )
            level = classify_risk_level(finding.risk_score).value
            print(
                f"  {position}. {finding.asset.name} | {identity} | "
                f"risk={finding.risk_score:.2f} ({level})"
            )

        if result.errors:
            print("Errors:")
            for error in result.errors:
                print(f"  - {error}")
        return 0 if result.success else 1
    finally:
        db.close()
        demo_engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
