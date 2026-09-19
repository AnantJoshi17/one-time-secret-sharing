"""
Tests for registration, login and the get_current_user dependency.
"""

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, make_user, register_user


def test_register_creates_a_user(client: TestClient):
    response = client.post(
        "/auth/register", json={"email": "alice@example.com", "password": "hunter2pass"}
    )

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["id"] > 0
    assert body["team_id"] is None

    # The most important assertion in this file: the password hash must never
    # appear in an API response. This is guaranteed by UserRead not having the
    # field, but it is worth pinning down so a future edit cannot undo it.
    assert "hashed_password" not in body
    assert "password" not in body


def test_register_stores_a_hash_not_the_password(client: TestClient, db):
    from app.models import User

    register_user(client, "bob@example.com", "hunter2pass")

    user = db.query(User).filter(User.email == "bob@example.com").one()
    assert user.hashed_password != "hunter2pass"
    # bcrypt hashes always start with $2b$ (the algorithm identifier).
    assert user.hashed_password.startswith("$2b$")


def test_register_rejects_a_duplicate_email(client: TestClient):
    register_user(client, "carol@example.com")

    response = client.post(
        "/auth/register", json={"email": "carol@example.com", "password": "hunter2pass"}
    )

    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_register_normalises_email_case(client: TestClient):
    """Alice@ and alice@ are the same account, so the second one is a conflict."""
    register_user(client, "dave@example.com")

    response = client.post(
        "/auth/register", json={"email": "DAVE@example.com", "password": "hunter2pass"}
    )

    assert response.status_code == 409


def test_register_rejects_a_short_password(client: TestClient):
    response = client.post(
        "/auth/register", json={"email": "eve@example.com", "password": "short"}
    )

    # 422 is FastAPI's "your body did not match the schema" -- Pydantic
    # rejected it before our endpoint ever ran.
    assert response.status_code == 422


def test_register_rejects_an_invalid_email(client: TestClient):
    response = client.post(
        "/auth/register", json={"email": "not-an-email", "password": "hunter2pass"}
    )

    assert response.status_code == 422


def test_login_returns_a_usable_token(client: TestClient):
    register_user(client, "frank@example.com")

    response = client.post(
        "/auth/login",
        data={"username": "frank@example.com", "password": "hunter2pass"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    # A JWT is three dot-separated base64 segments: header.payload.signature.
    assert body["access_token"].count(".") == 2


def test_login_with_the_wrong_password_is_rejected(client: TestClient):
    register_user(client, "grace@example.com")

    response = client.post(
        "/auth/login",
        data={"username": "grace@example.com", "password": "wrong-password"},
    )

    assert response.status_code == 401


def test_login_does_not_reveal_whether_an_account_exists(client: TestClient):
    """
    The error for an unknown email and the error for a wrong password must be
    byte-for-byte identical. Otherwise this endpoint becomes a tool for
    discovering who has an account here (user enumeration).
    """
    register_user(client, "heidi@example.com")

    unknown_email = client.post(
        "/auth/login", data={"username": "nobody@example.com", "password": "hunter2pass"}
    )
    wrong_password = client.post(
        "/auth/login", data={"username": "heidi@example.com", "password": "wrong-password"}
    )

    assert unknown_email.status_code == wrong_password.status_code == 401
    assert unknown_email.json() == wrong_password.json()


def test_me_returns_the_logged_in_user(client: TestClient):
    user = make_user(client, "ivan@example.com")

    response = client.get("/auth/me", headers=user["headers"])

    assert response.status_code == 200
    assert response.json()["email"] == "ivan@example.com"


def test_me_requires_a_token(client: TestClient):
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_me_rejects_a_garbage_token(client: TestClient):
    response = client.get("/auth/me", headers=auth_headers("not.a.jwt"))

    assert response.status_code == 401


def test_me_rejects_a_token_signed_with_the_wrong_key(client: TestClient):
    """
    A forged token must not be accepted.

    This is the check that the JWT signature is actually being verified. If
    someone ever changed decode_access_token to skip verification, every other
    auth test would still pass and only this one would catch it.
    """
    import jwt

    register_user(client, "judy@example.com")
    forged = jwt.encode({"sub": "1"}, "the-wrong-signing-key", algorithm="HS256")

    response = client.get("/auth/me", headers=auth_headers(forged))

    assert response.status_code == 401


def test_me_rejects_an_expired_token(client: TestClient):
    from app.security import create_access_token

    user = make_user(client, "ken@example.com")

    # A token that expired an hour ago.
    expired = create_access_token(user["id"], expires_minutes=-60)

    response = client.get("/auth/me", headers=auth_headers(expired))

    assert response.status_code == 401


def test_deactivated_user_cannot_authenticate(client: TestClient, db):
    """
    Proves get_current_user re-reads the database rather than trusting the
    token alone: the token is still validly signed and unexpired, but the
    account was disabled after it was issued.
    """
    from app.models import User

    user = make_user(client, "leo@example.com")

    db.query(User).filter(User.id == user["id"]).update({"is_active": False})
    db.commit()

    response = client.get("/auth/me", headers=user["headers"])

    assert response.status_code == 403


def test_failed_login_is_recorded_in_the_audit_log(client: TestClient, db):
    from app.models import AuditLog

    register_user(client, "mallory@example.com")
    client.post(
        "/auth/login", data={"username": "mallory@example.com", "password": "nope"}
    )

    entries = db.query(AuditLog).filter(AuditLog.action == "user.login_failed").all()
    assert len(entries) == 1
