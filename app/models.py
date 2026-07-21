"""SQLAlchemy database models."""

from datetime import date, datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum as SqlEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Exposure(str, Enum):
    """Whether an asset is reachable only internally or from outside."""

    INTERNAL = "internal"
    EXTERNAL = "external"


class AssetType(str, Enum):
    """Supported categories used to group assets consistently."""

    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    DATABASE = "database"
    OTHER = "other"


class Severity(str, Enum):
    """Technical severity reported for a vulnerability."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    """Current workflow state of a vulnerability on an asset."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED = "accepted"


class TreatmentStatus(str, Enum):
    """Current workflow state of a remediation action."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ACCEPTED = "accepted"


class AlertLevel(str, Enum):
    """Priority level assigned to a generated alert."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def enum_values(enum_class: type[Enum]) -> list[str]:
    """Store readable enum values such as 'in_progress' in SQLite."""
    return [str(item.value) for item in enum_class]


class Asset(Base):
    """A system, device, or service tracked by the GRC program."""

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "business_criticality BETWEEN 1 AND 5",
            name="ck_asset_business_criticality",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(
        SqlEnum(
            AssetType,
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [item.value for item in enum_class],
        ),
        nullable=False,
    )
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    business_criticality: Mapped[int] = mapped_column(Integer, nullable=False)
    exposure: Mapped[Exposure] = mapped_column(
        SqlEnum(
            Exposure,
            native_enum=False,
            create_constraint=True,
            values_callable=lambda enum_class: [item.value for item in enum_class],
        ),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    asset_vulnerabilities: Mapped[list["AssetVulnerability"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Scan(Base):
    """One imported vulnerability scan and its summary information."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "total_vulnerabilities >= 0",
            name="ck_scan_total_vulnerabilities_nonnegative",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    asset_vulnerabilities: Mapped[list["AssetVulnerability"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Vulnerability(Base):
    """A technical vulnerability reported by a scan source."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            "cvss_score BETWEEN 0 AND 10",
            name="ck_vulnerability_cvss_score",
        ),
        CheckConstraint(
            "cve_id IS NOT NULL OR technical_id IS NOT NULL",
            name="ck_vulnerability_has_stable_identity",
        ),
        UniqueConstraint(
            "source", "cve_id", name="uq_vulnerability_source_cve"
        ),
        UniqueConstraint(
            "source", "technical_id", name="uq_vulnerability_source_technical_id"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    technical_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        SqlEnum(
            Severity,
            native_enum=False,
            create_constraint=True,
            values_callable=enum_values,
        ),
        nullable=False,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    source: Mapped[str] = mapped_column(
        String(50), default="openvas", nullable=False
    )
    asset_vulnerabilities: Mapped[list["AssetVulnerability"]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AssetVulnerability(Base):
    """A vulnerability observed on one asset during one scan."""

    __tablename__ = "asset_vulnerabilities"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "vulnerability_id",
            "scan_id",
            name="uq_asset_vulnerability_scan",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[FindingStatus] = mapped_column(
        SqlEnum(
            FindingStatus,
            native_enum=False,
            create_constraint=True,
            values_callable=enum_values,
        ),
        default=FindingStatus.OPEN,
        nullable=False,
    )
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    asset: Mapped[Asset] = relationship(back_populates="asset_vulnerabilities")
    vulnerability: Mapped[Vulnerability] = relationship(
        back_populates="asset_vulnerabilities"
    )
    scan: Mapped[Scan] = relationship(back_populates="asset_vulnerabilities")
    treatments: Mapped[list["RiskTreatment"]] = relationship(
        back_populates="asset_vulnerability",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="asset_vulnerability",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class RiskTreatment(Base):
    """A remediation action used to manage one asset finding."""

    __tablename__ = "risk_treatments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[TreatmentStatus] = mapped_column(
        SqlEnum(
            TreatmentStatus,
            native_enum=False,
            create_constraint=True,
            values_callable=enum_values,
        ),
        default=TreatmentStatus.PENDING,
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    auto_created: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    asset_vulnerability: Mapped[AssetVulnerability] = relationship(
        back_populates="treatments"
    )


class Alert(Base):
    """A notification attached to a noteworthy asset finding."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    level: Mapped[AlertLevel] = mapped_column(
        SqlEnum(
            AlertLevel,
            native_enum=False,
            create_constraint=True,
            values_callable=enum_values,
        ),
        nullable=False,
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    acknowledged: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    asset_vulnerability: Mapped[AssetVulnerability] = relationship(
        back_populates="alerts"
    )
