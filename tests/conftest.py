"""
Shared pytest fixtures.

READ THE TOP OF THIS FILE FIRST -- the import order is load-bearing.

app/config.py builds its `settings` object the moment it is imported, reading
the environment as it stands at that instant. So the environment variables
below MUST be set before anything from `app` is imported, or the tests would
run against whatever DATABASE_URL your real .env points at -- and the first
`drop_all` would delete your development data.

WHICH DATABASE DO THE TESTS USE?

PostgreSQL is what this project targets and what you should run the suite
against before an interview:

    createdb secretshare_test
    TEST_DATABASE_URL="postgresql+psycopg2://localhost/secretshare_test" pytest

If TEST_DATABASE_URL is not set, the suite falls back to a local SQLite file
so that `pytest` works out of the box before you have installed PostgreSQL.
The fallback is genuinely useful here because the behaviour under test --
UPDATE ... WHERE viewed = false RETURNING ... -- is supported by SQLite 3.35+
too, so the same code path runs either way. Row-level locking differs between
the two, which is exactly why the concurrency test is worth re-running against
PostgreSQL.
"""

import os
import pathlib

# --------------------------------------------------------------------------
# Environment setup -- must come before any `from app...` import.
# --------------------------------------------------------------------------
_TEST_DB_FILE = pathlib.Path(__file__).parent / "test_secretshare.db"

os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", f"sqlite:///{_TEST_DB_FILE}"
)

# A throwaway Fernet key, generated fresh for each test run.
from cryptography.fernet import Fernet  # noqa: E402

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-not-used-anywhere-real"
os.environ["CLEANUP_TOKEN"] = "test-cleanup-token"
os.environ["PUBLIC_BASE_URL"] = "http://testserver"

# Set the rate limit high enough that ordinary tests never trip it. The
# rate-limiting test lowers it deliberately with monkeypatch.
os.environ["RATE_LIMIT_MAX_REQUESTS"] = "1000"

# --------------------------------------------------------------------------
# Now it is safe to import the application.
# --------------------------------------------------------------------------
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Secret  # noqa: E402
from app.rate_limit import reset_rate_limits  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_database():
    """
    Give every test an empty database.

    autouse=True means this runs for every test without being asked for.
    Dropping and recreating is slower than wrapping each test in a rolled-back
    transaction, but it is much easier to reason about -- and crucially, the
    concurrency test uses real separate connections that would not see each
    other's uncommitted data inside a shared transaction.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def clear_rate_limits():
    """
    Reset the in-memory rate limiter between tests.

    The limiter is a module-level dict, so without this a test that made a lot
    of requests would leak its counters into the next test and cause a
    baffling 429 somewhere unrelated.
    """
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture
def client() -> TestClient:
    """An HTTP client that talks to the app in-process, with no network."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db() -> Session:
    """
    A database session for tests that need to check or tamper with rows
    directly -- for example, to force a secret into the past so it expires.
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# --------------------------------------------------------------------------
# Helpers. These are plain functions rather than fixtures because they take
# arguments, and a test often needs two or three users.
# --------------------------------------------------------------------------
def register_user(client: TestClient, email: str, password: str = "hunter2pass") -> dict:
    """Register an account and return the created user's JSON."""
    response = client.post(
        "/auth/register", json={"email": email, "password": password}
    )
    assert response.status_code == 201, response.text
    return response.json()


def login(client: TestClient, email: str, password: str = "hunter2pass") -> str:
    """Log in and return the raw access token."""
    response = client.post(
        "/auth/login",
        # A FORM body, not JSON, and the email goes in `username`. See the
        # docstring on the login endpoint for why.
        data={"username": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    """Build the Authorization header every protected endpoint expects."""
    return {"Authorization": f"Bearer {token}"}


def make_user(client: TestClient, email: str, password: str = "hunter2pass") -> dict:
    """
    Register + log in in one step.

    Returns a dict with the user's id, email and ready-made auth headers,
    which is what most tests actually want.
    """
    user = register_user(client, email, password)
    token = login(client, email, password)
    return {
        "id": user["id"],
        "email": user["email"],
        "token": token,
        "headers": auth_headers(token),
    }


def create_secret(
    client: TestClient,
    headers: dict[str, str],
    plaintext: str = "correct horse battery staple",
    **kwargs,
) -> dict:
    """Create a secret and return the response JSON (token, share_url, ...)."""
    body = {"plaintext": plaintext, **kwargs}
    response = client.post("/secrets", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def force_expire(db: Session, token: str, seconds_ago: int = 60) -> None:
    """
    Backdate a secret's expiry so it is already expired.

    This is how the expiry tests avoid sleeping. Moving the row's clock is
    both instant and completely deterministic, whereas time.sleep() makes the
    suite slow and flaky.
    """
    from app.timeutil import utc_now
    from datetime import timedelta

    secret = db.query(Secret).filter(Secret.token == token).one()
    secret.expires_at = utc_now() - timedelta(seconds=seconds_ago)
    db.commit()
