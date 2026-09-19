"""
Tests for settings normalisation.

Small file, but it guards a failure that only shows up in production: Render
and Heroku hand out `postgres://` URLs, which SQLAlchemy 2.0 refuses to load.
Getting this wrong means the app crashes on boot after a deploy, which is
exactly when it is most annoying to debug.
"""

import pytest

from app.config import Settings


@pytest.mark.parametrize(
    "given, expected",
    [
        # What Render's `fromDatabase: connectionString` actually gives you.
        (
            "postgres://user:pw@host:5432/db",
            "postgresql+psycopg2://user:pw@host:5432/db",
        ),
        # Valid for SQLAlchemy, but leaves the driver to chance.
        (
            "postgresql://user:pw@host:5432/db",
            "postgresql+psycopg2://user:pw@host:5432/db",
        ),
        # Already explicit -- must be left exactly as it is.
        (
            "postgresql+psycopg2://user:pw@host:5432/db",
            "postgresql+psycopg2://user:pw@host:5432/db",
        ),
        # The SQLite fallback used by the test suite must not be touched.
        ("sqlite:///./test.db", "sqlite:///./test.db"),
    ],
)
def test_database_url_is_normalised(given: str, expected: str):
    settings = Settings(database_url=given, secret_encryption_key="x")

    assert settings.database_url == expected


def test_a_normalised_url_is_one_sqlalchemy_can_actually_load():
    """
    The real point of the normalisation: create_engine must not raise.

    create_engine does not connect, so this is safe to run without a database.
    """
    from sqlalchemy import create_engine

    settings = Settings(
        database_url="postgres://user:pw@host:5432/db", secret_encryption_key="x"
    )

    engine = create_engine(settings.database_url)

    assert engine.dialect.name == "postgresql"
    assert engine.dialect.driver == "psycopg2"
