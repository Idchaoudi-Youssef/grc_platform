"""Contextual GRC risk calculation and transactional scoring services."""

from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from app.models import AssetVulnerability, Exposure

THEORETICAL_MAXIMUM = Decimal("75")
HUNDRED = Decimal("100")


class RiskScoringError(ValueError):
    """Raised when required scoring data is missing or invalid."""


class RiskLevel(str, Enum):
    """Contextual business-risk level derived from the normalized score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskCalculationDetails(BaseModel):
    """Inputs and constants used to make a risk score explainable."""

    cvss_score: float
    business_criticality: int
    exposure: Exposure
    exposure_factor: float
    theoretical_maximum: float = 75.0
    formula: str = "(cvss_score × business_criticality × exposure_factor / 75) × 100"


class RiskCalculation(BaseModel):
    """Complete result of one pure contextual risk calculation."""

    raw_score: float
    normalized_risk_score: float
    risk_level: RiskLevel
    calculation_details: RiskCalculationDetails


class BulkScoringResult(BaseModel):
    """Summary of one transactional bulk-scoring operation."""

    scan_id: int | None = None
    force_recalculation: bool = False
    examined_count: int = 0
    scored_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    database_failure: bool = False


def calculate_risk(
    cvss_score: float,
    business_criticality: int,
    exposure: Exposure | str,
) -> RiskCalculation:
    """Calculate contextual risk without reading or writing the database."""
    cvss = _validated_cvss(cvss_score)
    criticality = _validated_criticality(business_criticality)
    normalized_exposure = _validated_exposure(exposure)
    exposure_factor = (
        Decimal("1.5")
        if normalized_exposure is Exposure.EXTERNAL
        else Decimal("1.0")
    )

    raw_score = cvss * Decimal(criticality) * exposure_factor
    normalized = (raw_score / THEORETICAL_MAXIMUM) * HUNDRED
    clamped = _clamp_decimal(normalized)
    rounded = clamped.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    stored_score = float(rounded)

    return RiskCalculation(
        raw_score=float(raw_score),
        normalized_risk_score=stored_score,
        risk_level=classify_risk_level(stored_score),
        calculation_details=RiskCalculationDetails(
            cvss_score=float(cvss),
            business_criticality=criticality,
            exposure=normalized_exposure,
            exposure_factor=float(exposure_factor),
        ),
    )


def classify_risk_level(risk_score: float) -> RiskLevel:
    """Classify a normalized score using the documented M5 thresholds."""
    score = _to_finite_decimal(risk_score, "Risk score")
    if not Decimal("0") <= score <= HUNDRED:
        raise RiskScoringError("Risk score must be between 0 and 100.")
    if score < Decimal("25"):
        return RiskLevel.LOW
    if score < Decimal("50"):
        return RiskLevel.MEDIUM
    if score < Decimal("75"):
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def clamp_risk_score(risk_score: float) -> float:
    """Clamp a finite numeric value to the database's 0-100 score range."""
    score = _to_finite_decimal(risk_score, "Risk score")
    return float(_clamp_decimal(score))


def score_asset_vulnerability(
    finding: AssetVulnerability,
    *,
    force: bool = False,
) -> RiskCalculation | None:
    """Calculate and assign one finding's score without committing a session."""
    if finding.risk_score is not None and not force:
        return None
    if finding.asset is None:
        raise RiskScoringError("Finding has no related asset.")
    if finding.vulnerability is None:
        raise RiskScoringError("Finding has no related vulnerability.")

    calculation = calculate_risk(
        finding.vulnerability.cvss_score,
        finding.asset.business_criticality,
        finding.asset.exposure,
    )
    finding.risk_score = calculation.normalized_risk_score
    return calculation


def score_asset_vulnerabilities(
    db: Session,
    *,
    scan_id: int | None = None,
    force: bool = False,
    commit: bool = True,
) -> BulkScoringResult:
    """Score one scan or all findings and commit the changes atomically."""
    result = BulkScoringResult(scan_id=scan_id, force_recalculation=force)
    query = (
        select(AssetVulnerability)
        .options(
            joinedload(AssetVulnerability.asset),
            joinedload(AssetVulnerability.vulnerability),
        )
        .order_by(AssetVulnerability.id)
    )
    if scan_id is not None:
        query = query.where(AssetVulnerability.scan_id == scan_id)

    try:
        findings = list(db.scalars(query).all())
        for finding in findings:
            result.examined_count += 1
            if finding.risk_score is not None and not force:
                result.skipped_count += 1
                result.warnings.append(
                    f"Finding {finding.id} skipped because it already has a risk score."
                )
                continue
            try:
                score_asset_vulnerability(finding, force=force)
                result.scored_count += 1
            except RiskScoringError as exc:
                result.failed_count += 1
                result.errors.append(f"Finding {finding.id} could not be scored: {exc}")

        if commit:
            db.commit()
        else:
            db.flush()
        return result
    except SQLAlchemyError as exc:
        db.rollback()
        result.database_failure = True
        result.failed_count = result.examined_count - result.skipped_count
        result.scored_count = 0
        result.errors.append(f"Database scoring failed and was rolled back: {exc}")
        return result


def _validated_cvss(value: float) -> Decimal:
    cvss = _to_finite_decimal(value, "CVSS score")
    if not Decimal("0") <= cvss <= Decimal("10"):
        raise RiskScoringError("CVSS score must be between 0 and 10.")
    return cvss


def _validated_criticality(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise RiskScoringError("Business criticality must be an integer between 1 and 5.")
    return value


def _validated_exposure(value: Exposure | str) -> Exposure:
    if isinstance(value, Exposure):
        return value
    if isinstance(value, str):
        try:
            return Exposure(value.strip().lower())
        except ValueError:
            pass
    raise RiskScoringError("Exposure must be 'internal' or 'external'.")


def _to_finite_decimal(value: float, label: str) -> Decimal:
    if value is None or isinstance(value, bool):
        raise RiskScoringError(f"{label} must be a finite number.")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise RiskScoringError(f"{label} must be a finite number.") from None
    if not math.isfinite(float(decimal_value)):
        raise RiskScoringError(f"{label} must be a finite number.")
    return decimal_value


def _clamp_decimal(value: Decimal) -> Decimal:
    return min(max(value, Decimal("0")), HUNDRED)
