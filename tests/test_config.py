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


@pytest.mark.parametrize(
    "given, expected",
    [
        # The exact bug hit on the first Render deploy: the dashboard renders
        # env var values as a text box, so pasting a URL captures a newline.
        ("https://app.onrender.com\n", "https://app.onrender.com"),
        ("  https://app.onrender.com  ", "https://app.onrender.com"),
        # A trailing slash must not produce a double slash in share links.
        ("https://app.onrender.com/", "https://app.onrender.com"),
        ("https://app.onrender.com/\n", "https://app.onrender.com"),
        ("https://app.onrender.com", "https://app.onrender.com"),
    ],
)
def test_public_base_url_is_normalised(given: str, expected: str):
    settings = Settings(public_base_url=given, secret_encryption_key="x")

    assert settings.public_base_url == expected


def test_share_links_are_well_formed_after_normalisation():
    """The end the bug actually showed up at: the generated link."""
    settings = Settings(
        public_base_url="https://app.onrender.com\n", secret_encryption_key="x"
    )

    link = f"{settings.public_base_url}/s/abc123"

    assert link == "https://app.onrender.com/s/abc123"
    assert "\n" not in link
    assert "//s/" not in link


def test_a_pasted_cleanup_token_still_matches():
    """
    A trailing newline on CLEANUP_TOKEN would make every cleanup call 401,
    with no clue as to why.
    """
    settings = Settings(cleanup_token="secret-token\n", secret_encryption_key="x")

    assert settings.cleanup_token == "secret-token"
