"""SQLAlchemy database models."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

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
