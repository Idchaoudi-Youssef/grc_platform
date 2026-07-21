"""Database connection and session configuration."""

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///./grc.db"

# SQLite normally allows a connection to be used by only one thread. FastAPI
# handles requests in multiple threads, so this SQLite-specific option is needed.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
    """Enable SQLite foreign-key checks for each new database connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def configure_sqlite_foreign_keys(target_engine: Engine) -> None:
    """Attach SQLite foreign-key enforcement to an SQLAlchemy engine."""
    event.listen(target_engine, "connect", _enable_foreign_keys)


configure_sqlite_foreign_keys(engine)
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
