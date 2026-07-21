"""Rule-based detection and automatic GRC task creation."""

from __future__ import annotations

import math
from datetime import date, timedelta

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from app.models import (
    Alert,
    AlertLevel,
    AssetVulnerability,
    FindingStatus,
    RiskTreatment,
    TreatmentStatus,
)

CRITICAL_CONTEXTUAL_RISK_RULE = "critical_contextual_risk_v1"
CRITICAL_RISK_THRESHOLD = 75.0
CRITICAL_ASSET_THRESHOLD = 4
CRITICAL_REMEDIATION_DAYS = 7
GENERIC_REMEDIATION = (
    "Review the affected service, apply the vendor patch or mitigation, "
    "validate the correction, and perform a new vulnerability scan."
)


class DetectionRemediationError(ValueError):
    """Raised when a finding cannot be evaluated safely."""


class RuleEvaluation(BaseModel):
    """Explainable result of the pure critical-risk rule."""

    matched: bool
    rule_key: str = CRITICAL_CONTEXTUAL_RISK_RULE
    reason: str
    alert_level: AlertLevel | None = None
    recommended_deadline: date | None = None


class FindingAutomationResult(BaseModel):
    """Records created or reused while processing one finding."""

    asset_vulnerability_id: int | None = None
    matched: bool = False
    alert_created: bool = False
    alert_reused: bool = False
    treatment_created: bool = False
    treatment_reused: bool = False
    skipped: bool = False
    failed: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class BulkAutomationResult(BaseModel):
    """Summary of one transactional detection/remediation run."""

    scan_id: int | None = None
    examined_count: int = 0
    matched_count: int = 0
    alerts_created_count: int = 0
    alerts_reused_count: int = 0
    treatments_created_count: int = 0
    treatments_reused_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def evaluate_critical_contextual_risk(
    risk_score: float | None,
    business_criticality: int,
    finding_status: FindingStatus | str,
    *,
    evaluation_date: date | None = None,
) -> RuleEvaluation:
    """Evaluate the pure M6 critical contextual-risk rule."""
    if risk_score is None:
        return RuleEvaluation(
            matched=False,
            reason="Finding has no contextual risk score.",
        )

    status = _validated_status(finding_status)
    if status is FindingStatus.FIXED:
        return RuleEvaluation(
            matched=False,
            reason="Finding is already fixed.",
        )

    score = _validated_risk_score(risk_score)
    criticality = _validated_criticality(business_criticality)
    if score < CRITICAL_RISK_THRESHOLD:
        return RuleEvaluation(
            matched=False,
            reason=f"Risk score {score:.2f} is below 75.00.",
        )
    if criticality < CRITICAL_ASSET_THRESHOLD:
        return RuleEvaluation(
            matched=False,
            reason=f"Asset criticality {criticality} is below 4.",
        )

    evaluated_on = evaluation_date or date.today()
    return RuleEvaluation(
        matched=True,
        reason="Critical contextual risk detected on a major asset.",
        alert_level=AlertLevel.CRITICAL,
        recommended_deadline=evaluated_on
        + timedelta(days=CRITICAL_REMEDIATION_DAYS),
    )


def process_asset_vulnerability(
    db: Session,
    finding: AssetVulnerability,
    *,
    evaluation_date: date | None = None,
) -> FindingAutomationResult:
    """Evaluate one finding and create missing automatic records without commit."""
    finding_id = getattr(finding, "id", None)
    result = FindingAutomationResult(asset_vulnerability_id=finding_id)
    if finding.asset is None:
        raise DetectionRemediationError("Finding has no related asset.")
    if finding.vulnerability is None:
        raise DetectionRemediationError("Finding has no related vulnerability.")

    evaluation = evaluate_critical_contextual_risk(
        finding.risk_score,
        finding.asset.business_criticality,
        finding.status,
        evaluation_date=evaluation_date,
    )
    result.matched = evaluation.matched
    if not evaluation.matched:
        result.skipped = True
        result.warnings.append(evaluation.reason)
        return result

    alert = db.scalar(
        select(Alert).where(
            Alert.asset_vulnerability_id == finding.id,
            Alert.rule_key == evaluation.rule_key,
        )
    )
    if alert is None:
        db.add(
            Alert(
                asset_vulnerability=finding,
                rule_key=evaluation.rule_key,
                level=evaluation.alert_level,
                message=_build_alert_message(finding),
                acknowledged=False,
            )
        )
        result.alert_created = True
    else:
        result.alert_reused = True

    treatment = db.scalar(
        select(RiskTreatment).where(
            RiskTreatment.asset_vulnerability_id == finding.id,
            RiskTreatment.rule_key == evaluation.rule_key,
        )
    )
    if treatment is not None:
        result.treatment_reused = True
    else:
        owner = (finding.asset.owner or "").strip()
        if not owner:
            result.failed = True
            result.errors.append(
                "Automatic treatment was not created because the asset owner is blank."
            )
        else:
            solution = (finding.vulnerability.solution or "").strip()
            db.add(
                RiskTreatment(
                    asset_vulnerability=finding,
                    rule_key=evaluation.rule_key,
                    action=solution or GENERIC_REMEDIATION,
                    owner=owner,
                    due_date=evaluation.recommended_deadline,
                    status=TreatmentStatus.PENDING,
                    resolved_at=None,
                    evidence=None,
                    auto_created=True,
                )
            )
            result.treatment_created = True

    if result.alert_created or result.treatment_created:
        db.flush()
    return result


def run_detection_remediation(
    db: Session,
    *,
    scan_id: int | None = None,
    evaluation_date: date | None = None,
    include_processed: bool = True,
) -> BulkAutomationResult:
    """Process scored findings for one scan or all scans in one transaction."""
    result = BulkAutomationResult(scan_id=scan_id)
    query = (
        select(AssetVulnerability)
        .where(AssetVulnerability.risk_score.is_not(None))
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
            if not include_processed and _is_fully_processed(db, finding.id):
                result.skipped_count += 1
                result.warnings.append(
                    f"Finding {finding.id} skipped because the rule was already processed."
                )
                continue
            try:
                outcome = process_asset_vulnerability(
                    db, finding, evaluation_date=evaluation_date
                )
                _merge_finding_result(result, outcome)
            except DetectionRemediationError as exc:
                result.failed_count += 1
                result.errors.append(f"Finding {finding.id} could not be processed: {exc}")

        db.commit()
        return result
    except SQLAlchemyError as exc:
        db.rollback()
        result.alerts_created_count = 0
        result.treatments_created_count = 0
        result.failed_count = result.examined_count - result.skipped_count
        result.errors.append(
            f"Database automation failed and was rolled back: {exc}"
        )
        return result


def _merge_finding_result(
    bulk: BulkAutomationResult, outcome: FindingAutomationResult
) -> None:
    if outcome.matched:
        bulk.matched_count += 1
    if outcome.alert_created:
        bulk.alerts_created_count += 1
    if outcome.alert_reused:
        bulk.alerts_reused_count += 1
    if outcome.treatment_created:
        bulk.treatments_created_count += 1
    if outcome.treatment_reused:
        bulk.treatments_reused_count += 1
    if outcome.skipped:
        bulk.skipped_count += 1
    if outcome.failed:
        bulk.failed_count += 1
    bulk.warnings.extend(outcome.warnings)
    bulk.errors.extend(outcome.errors)


def _is_fully_processed(db: Session, finding_id: int) -> bool:
    alert_exists = db.scalar(
        select(Alert.id).where(
            Alert.asset_vulnerability_id == finding_id,
            Alert.rule_key == CRITICAL_CONTEXTUAL_RISK_RULE,
        )
    )
    treatment_exists = db.scalar(
        select(RiskTreatment.id).where(
            RiskTreatment.asset_vulnerability_id == finding_id,
            RiskTreatment.rule_key == CRITICAL_CONTEXTUAL_RISK_RULE,
        )
    )
    return alert_exists is not None and treatment_exists is not None


def _build_alert_message(finding: AssetVulnerability) -> str:
    identity = (
        finding.vulnerability.cve_id
        or finding.vulnerability.technical_id
        or "unknown identity"
    )
    return (
        f"Critical contextual risk on asset '{finding.asset.name}' "
        f"({finding.asset.ip_address}): '{finding.vulnerability.title}' "
        f"[{identity}] has risk score {finding.risk_score:.2f}."
    )


def _validated_risk_score(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DetectionRemediationError("Risk score must be a number from 0 to 100.")
    score = float(value)
    if not math.isfinite(score) or not 0 <= score <= 100:
        raise DetectionRemediationError("Risk score must be a number from 0 to 100.")
    return score


def _validated_criticality(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        raise DetectionRemediationError(
            "Business criticality must be an integer from 1 to 5."
        )
    return value


def _validated_status(value: FindingStatus | str) -> FindingStatus:
    if isinstance(value, FindingStatus):
        return value
    if isinstance(value, str):
        try:
            return FindingStatus(value)
        except ValueError:
            pass
    raise DetectionRemediationError("Finding status is invalid.")
