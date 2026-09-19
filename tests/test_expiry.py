"""
Tests for TTL expiry: lazy expiry on read, and the cleanup sweeper.

None of these tests call time.sleep(). Instead they backdate the row's
expires_at (see force_expire in conftest.py), which is instant and completely
deterministic. A suite that sleeps is slow, and a suite that sleeps for one
second to test a one-second TTL is also flaky.
"""

from datetime import timedelta

from fastapi.testclient import TestClient

from tests.conftest import create_secret, force_expire, make_user

PLAINTEXT = "expiring-secret-value"
CLEANUP_HEADERS = {"X-Cleanup-Token": "test-cleanup-token"}


def test_secret_has_an_expiry_in_the_future(client: TestClient):
    user = make_user(client, "alice@example.com")

    body = create_secret(client, user["headers"], PLAINTEXT, ttl_minutes=30)

    assert body["expires_at"] is not None


def test_default_ttl_is_applied_when_none_is_given(client: TestClient, db):
    from app.config import settings
    from app.models import Secret
    from app.timeutil import ensure_utc, utc_now

    user = make_user(client, "bob@example.com")
    body = create_secret(client, user["headers"], PLAINTEXT)  # no ttl_minutes

    row = db.query(Secret).filter(Secret.token == body["token"]).one()
    expected = utc_now() + timedelta(minutes=settings.default_ttl_minutes)

    # Allow a minute of slack for the time the test itself takes.
    assert abs((ensure_utc(row.expires_at) - expected).total_seconds()) < 60


def test_ttl_above_the_maximum_is_rejected(client: TestClient):
    from app.config import settings

    user = make_user(client, "carol@example.com")

    response = client.post(
        "/secrets",
        json={"plaintext": PLAINTEXT, "ttl_minutes": settings.max_ttl_minutes + 1},
        headers=user["headers"],
    )

    assert response.status_code == 422


def test_zero_or_negative_ttl_is_rejected(client: TestClient):
    user = make_user(client, "dave@example.com")

    for bad_ttl in (0, -5):
        response = client.post(
            "/secrets",
            json={"plaintext": PLAINTEXT, "ttl_minutes": bad_ttl},
            headers=user["headers"],
        )
        assert response.status_code == 422


def test_expired_secret_cannot_be_revealed(client: TestClient, db):
    """
    Lazy expiry. Nothing ran in the background -- the secret simply fails the
    `expires_at > now` condition inside the atomic UPDATE, so it matches no
    rows and the caller gets 410.
    """
    user = make_user(client, "erin@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT, ttl_minutes=5)

    force_expire(db, secret["token"])

    response = client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])

    assert response.status_code == 410
    assert "expired" in response.json()["detail"].lower()
    assert PLAINTEXT not in response.text


def test_expired_secret_is_still_unreadable_even_though_the_row_remains(
    client: TestClient, db
):
    """
    Expiry does not delete the row by itself, and it does not need to -- the
    guarantee comes from the read path refusing to match it.
    """
    from app.models import Secret

    user = make_user(client, "frank@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)
    force_expire(db, secret["token"])

    db.expire_all()
    row = db.query(Secret).filter(Secret.token == secret["token"]).one()

    assert row.viewed is False        # never read
    assert row.ciphertext is not None # not yet swept
    # ...and yet:
    response = client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])
    assert response.status_code == 410


def test_metadata_reports_an_expired_secret_as_unavailable(client: TestClient, db):
    user = make_user(client, "grace@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)
    force_expire(db, secret["token"])

    meta = client.get(f"/secrets/{secret['token']}", headers=user["headers"])

    assert meta.status_code == 200
    assert meta.json()["is_expired"] is True
    assert meta.json()["is_available"] is False


def test_cleanup_wipes_the_ciphertext_of_expired_secrets(client: TestClient, db):
    """
    The sweeper's real job: make the bytes actually go away, not merely become
    unreachable through the API.
    """
    from app.models import Secret

    user = make_user(client, "heidi@example.com")
    expired = create_secret(client, user["headers"], PLAINTEXT)
    still_valid = create_secret(client, user["headers"], "keep-me", ttl_minutes=60)

    force_expire(db, expired["token"])

    response = client.post("/maintenance/cleanup", headers=CLEANUP_HEADERS)

    assert response.status_code == 200
    assert response.json()["expired_secrets_wiped"] == 1

    db.expire_all()
    expired_row = db.query(Secret).filter(Secret.token == expired["token"]).one()
    valid_row = db.query(Secret).filter(Secret.token == still_valid["token"]).one()

    assert expired_row.ciphertext is None     # wiped
    assert valid_row.ciphertext is not None   # untouched


def test_cleanup_is_idempotent(client: TestClient, db):
    """Running it twice must be harmless -- the second pass finds nothing."""
    user = make_user(client, "ivan@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)
    force_expire(db, secret["token"])

    first = client.post("/maintenance/cleanup", headers=CLEANUP_HEADERS)
    second = client.post("/maintenance/cleanup", headers=CLEANUP_HEADERS)

    assert first.json()["expired_secrets_wiped"] == 1
    assert second.json()["expired_secrets_wiped"] == 0


def test_cleanup_purges_long_expired_rows(client: TestClient, db):
    """Stage two: rows that expired ages ago are deleted entirely."""
    from app.models import Secret

    user = make_user(client, "judy@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    # 40 days past its expiry, well beyond the default 30-day purge window.
    force_expire(db, secret["token"], seconds_ago=40 * 24 * 3600)

    response = client.post("/maintenance/cleanup", headers=CLEANUP_HEADERS)

    assert response.status_code == 200
    assert response.json()["old_rows_purged"] == 1
    assert db.query(Secret).filter(Secret.token == secret["token"]).count() == 0


def test_cleanup_keeps_the_audit_trail_after_purging_a_secret(client: TestClient, db):
    """
    The audit log must outlive the secret. This is why audit_logs.secret_token
    is a plain string rather than a foreign key -- a FK with ON DELETE CASCADE
    would have deleted the evidence along with the row.
    """
    from app.models import AuditLog

    user = make_user(client, "ken@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)
    force_expire(db, secret["token"], seconds_ago=40 * 24 * 3600)

    client.post("/maintenance/cleanup", headers=CLEANUP_HEADERS)

    surviving = (
        db.query(AuditLog).filter(AuditLog.secret_token == secret["token"]).all()
    )
    assert len(surviving) >= 1
    assert any(entry.action == "secret.create" for entry in surviving)


def test_cleanup_requires_the_right_token(client: TestClient):
    no_header = client.post("/maintenance/cleanup")
    wrong_header = client.post(
        "/maintenance/cleanup", headers={"X-Cleanup-Token": "wrong-token"}
    )

    assert no_header.status_code == 401
    assert wrong_header.status_code == 401


def test_health_endpoint_is_public(client: TestClient):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["detail"] == "ok"
