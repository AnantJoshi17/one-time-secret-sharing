"""
SQLAlchemy setup: the engine, the session factory, and the FastAPI dependency
that hands a session to a request.

This is the module most worth reading slowly if SQLAlchemy is new to you.
There are three objects and they are easy to mix up:

  Engine   -- the connection pool. Created ONCE for the whole application.
              It knows the database URL and holds open TCP connections.
              It does not talk to your Python objects at all.

  Session  -- your unit of work for one request. You add objects to it, query
              through it, and at the end you commit (write everything) or
              roll back (throw everything away). Created and destroyed per
              request, never shared between requests or threads.

  Base     -- the parent class every ORM model inherits from. SQLAlchemy
              collects the table definitions on `Base.metadata`, which is what
              Alembic later compares against the real database.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


def _engine_kwargs(url: str) -> dict:
    """
    Driver-specific engine options.

    PostgreSQL is the real target. SQLite only shows up when running the test
    suite without a local Postgres, and it needs one extra flag because its
    driver refuses to be used from a thread other than the one that created
    the connection -- which TestClient does.
    """
    if url.startswith("sqlite"):
        return {
            "connect_args": {
                "check_same_thread": False,
                # SQLite locks the whole database file for a write. Wait up to
                # 30s for another writer instead of failing instantly, which
                # keeps the concurrency test from flaking.
                "timeout": 30,
            }
        }

    return {
        # Recycle connections after 30 minutes. Managed Postgres providers
        # (including Render) silently drop idle connections, and a recycled
        # pool avoids "server closed the connection unexpectedly" errors.
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }


# The engine is module-level: created once when the app imports this file.
engine = create_engine(settings.database_url, **_engine_kwargs(settings.database_url))

# A factory that produces new Session objects bound to our engine.
#
# expire_on_commit=False is worth explaining: by default, after you call
# commit(), SQLAlchemy marks every object you loaded as "stale" and re-queries
# the database the next time you touch an attribute. That is safe but it means
# a `return user` after a commit can fire another SELECT -- or blow up if the
# session is already closed. Since we finish with our objects right after
# committing, turning it off keeps the code simple and predictable.
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Parent class for every model. See app/models.py."""


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides one Session per request.

    The `yield` is the important part. FastAPI runs everything before the
    yield, hands the session to your endpoint, and then -- whether the endpoint
    returned normally OR raised -- runs the `finally` block. So the connection
    always goes back to the pool and never leaks.

    Note that this dependency does NOT commit for you. Each endpoint commits
    explicitly, so that reading the endpoint tells you exactly when the write
    becomes permanent.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
