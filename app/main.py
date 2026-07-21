"""FastAPI application and asset API endpoints."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import crud, models, schemas
from app.database import Base, engine, get_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create database tables when the application starts."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="GRC Vulnerability Management API",
    description="Milestone 1: a simple API for managing assets.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/assets",
    response_model=schemas.AssetRead,
    status_code=status.HTTP_201_CREATED,
)
def create_asset(
    asset_in: schemas.AssetCreate, db: Session = Depends(get_db)
) -> models.Asset:
    try:
        return crud.create_asset(db, asset_in)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An asset with this IP address already exists.",
        ) from None


@app.get("/assets", response_model=list[schemas.AssetRead])
def list_assets(db: Session = Depends(get_db)) -> list[models.Asset]:
    return crud.list_assets(db)


@app.get("/assets/{asset_id}", response_model=schemas.AssetRead)
def read_asset(asset_id: int, db: Session = Depends(get_db)) -> models.Asset:
    asset = crud.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return asset


@app.patch("/assets/{asset_id}", response_model=schemas.AssetRead)
def update_asset(
    asset_id: int,
    asset_in: schemas.AssetUpdate,
    db: Session = Depends(get_db),
) -> models.Asset:
    asset = crud.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    try:
        return crud.update_asset(db, asset, asset_in)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An asset with this IP address already exists.",
        ) from None


@app.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, db: Session = Depends(get_db)) -> Response:
    asset = crud.get_asset(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    crud.delete_asset(db, asset)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

