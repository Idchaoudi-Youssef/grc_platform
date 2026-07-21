"""Shared test setup using an isolated temporary SQLite database."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, configure_sqlite_foreign_keys, get_db
from app.main import app


@pytest.fixture()
def test_engine(tmp_path):
    database_path = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )
    configure_sqlite_foreign_keys(engine)
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(test_engine):
    testing_session = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )
    db = testing_session()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@pytest.fixture()
def client(test_engine):
    testing_session = sessionmaker(
        autocommit=False, autoflush=False, bind=test_engine
    )

    def override_get_db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
