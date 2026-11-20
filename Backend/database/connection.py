"""
ShipSafe Database Connection Module
Configures SQLAlchemy 2.0 with PostgreSQL as primary database,
and automatic fallback to SQLite for local development or testing.
"""

import os
import socket
import urllib.parse
import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

logger = logging.getLogger("shipsafe.database")

from pathlib import Path

_DB_PATH = Path(__file__).resolve().parent.parent / "shipsafe_dev.db"

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@localhost:5432/shipsafe"
)
DEV_SQLITE_FALLBACK = os.environ.get(
    "DEV_SQLITE_FALLBACK",
    f"sqlite:///{_DB_PATH.as_posix()}"
)

Base = declarative_base()


def check_port_reachable(host: str, port: int, timeout: float = 0.2) -> bool:
    """Fast probe to determine if database port is open before engine creation."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def create_db_engine():
    """Attempts to connect to PostgreSQL; falls back to SQLite for local development."""
    target_url = os.environ.get("DATABASE_URL", DATABASE_URL)
    try:
        if target_url.startswith("postgresql"):
            parsed = urllib.parse.urlsplit(target_url)
            host = parsed.hostname or "localhost"
            port = parsed.port or 5432

            if not check_port_reachable(host, port, timeout=0.2):
                logger.warning(
                    f"PostgreSQL port ({host}:{port}) is not reachable. "
                    f"Using SQLite development database: {DEV_SQLITE_FALLBACK}"
                )
                return create_engine(DEV_SQLITE_FALLBACK, connect_args={"check_same_thread": False})

            eng = create_engine(
                target_url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
                connect_args={"connect_timeout": 1}
            )
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Successfully connected to PostgreSQL database.")
            return eng
        else:
            return create_engine(target_url, connect_args={"check_same_thread": False})
    except Exception as e:
        logger.warning(
            f"Could not connect to PostgreSQL ({e}). "
            f"Falling back to local development SQLite database: {DEV_SQLITE_FALLBACK}"
        )
        return create_engine(
            DEV_SQLITE_FALLBACK,
            connect_args={"check_same_thread": False}
        )



engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initializes schema if tables do not exist."""
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
