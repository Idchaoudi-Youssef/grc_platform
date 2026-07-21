"""Pydantic schemas validate API input and shape API output."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

from app.models import AssetType, Exposure


class AssetCreate(BaseModel):
    """Fields accepted when a new asset is created."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)
    ip_address: IPvAnyAddress
    asset_type: AssetType
    owner: str = Field(min_length=1, max_length=100)
    business_criticality: int = Field(ge=1, le=5)
    exposure: Exposure
    description: str | None = None


class AssetUpdate(BaseModel):
    """Fields accepted when an asset is partially updated."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=100)
    ip_address: IPvAnyAddress | None = None
    asset_type: AssetType | None = None
    owner: str | None = Field(default=None, min_length=1, max_length=100)
    business_criticality: int | None = Field(default=None, ge=1, le=5)
    exposure: Exposure | None = None
    description: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_null_required_fields(cls, data):
        """Allow fields to be omitted, but not explicitly cleared to null."""
        if isinstance(data, dict):
            required_fields = {
                "name",
                "ip_address",
                "asset_type",
                "owner",
                "business_criticality",
                "exposure",
            }
            null_fields = required_fields.intersection(data)
            if any(data[field] is None for field in null_fields):
                raise ValueError("Required asset fields cannot be null.")
        return data


class AssetRead(BaseModel):
    """Fields returned to an API client."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    ip_address: IPvAnyAddress
    asset_type: AssetType
    owner: str
    business_criticality: int
    exposure: Exposure
    description: str | None
    created_at: datetime
    updated_at: datetime
