"""Database operations for assets."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models, schemas


def list_assets(db: Session) -> list[models.Asset]:
    return list(db.scalars(select(models.Asset).order_by(models.Asset.id)).all())


def get_asset(db: Session, asset_id: int) -> models.Asset | None:
    return db.get(models.Asset, asset_id)


def create_asset(db: Session, asset_in: schemas.AssetCreate) -> models.Asset:
    data = asset_in.model_dump()
    data["ip_address"] = str(data["ip_address"])
    asset = models.Asset(**data)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def update_asset(
    db: Session, asset: models.Asset, asset_in: schemas.AssetUpdate
) -> models.Asset:
    changes = asset_in.model_dump(exclude_unset=True)
    if changes.get("ip_address") is not None:
        changes["ip_address"] = str(changes["ip_address"])
    for field, value in changes.items():
        setattr(asset, field, value)
    db.commit()
    db.refresh(asset)
    return asset


def delete_asset(db: Session, asset: models.Asset) -> None:
    db.delete(asset)
    db.commit()

