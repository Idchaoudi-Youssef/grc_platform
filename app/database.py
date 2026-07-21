"""Database connection and session configuration."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./grc.db"

# SQLite normally allows a connection to be used by only one thread. FastAPI
# handles requests in multiple threads, so this SQLite-specific option is needed.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class inherited by all database models."""


def get_db():
    """Provide one database session per API request and close it afterward."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

