"""
Tests for the core promise: a secret can be read EXACTLY once.

This is the file to open first in an interview. The last two tests are the
interesting ones -- they attack the atomic UPDATE from two directions, once
deterministically and once with real concurrent requests.
"""

import threading

from fastapi.testclient import TestClient

from tests.conftest import create_secret, make_user

PLAINTEXT = "correct horse battery staple"


def response_text(body: dict) -> str:
    """Flatten a response body to a string so we can assert on its contents."""
    import json

    return json.dumps(body)


def test_create_returns_a_link_but_not_the_secret(client: TestClient):
    user = make_user(client, "alice@example.com")

    body = create_secret(client, user["headers"], PLAINTEXT, label="prod db password")

    assert len(body["token"]) > 20  # 32 random bytes, url-safe encoded
    assert body["token"] in body["share_url"]
    assert body["label"] == "prod db password"
    # The creation response must NOT echo the secret back.
    assert PLAINTEXT not in response_text(body)


def test_first_reveal_returns_the_plaintext(client: TestClient):
    user = make_user(client, "bob@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    response = client.post(
        f"/secrets/{secret['token']}/reveal", headers=user["headers"]
    )

    assert response.status_code == 200
    assert response.json()["plaintext"] == PLAINTEXT


def test_second_reveal_is_410_gone(client: TestClient):
    """The headline behaviour: the link works once and then it does not."""
    user = make_user(client, "carol@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    first = client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])
    second = client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])

    assert first.status_code == 200
    assert second.status_code == 410
    assert "already been viewed" in second.json()["detail"]
    # And the plaintext must not leak in the failure response.
    assert PLAINTEXT not in second.text


def test_third_and_later_reveals_stay_410(client: TestClient):
    user = make_user(client, "dave@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])

    for _ in range(3):
        response = client.post(
            f"/secrets/{secret['token']}/reveal", headers=user["headers"]
        )
        assert response.status_code == 410


def test_ciphertext_is_wiped_from_the_database_after_reading(client: TestClient, db):
    """
    "Destroyed" has to mean destroyed, not just flagged.

    After a reveal the row survives (so we can answer 410), but the column
    holding the encrypted payload must be NULL.
    """
    from app.models import Secret

    user = make_user(client, "erin@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    row_before = db.query(Secret).filter(Secret.token == secret["token"]).one()
    assert row_before.ciphertext is not None

    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])

    db.expire_all()  # throw away cached values so we re-read from the database
    row_after = db.query(Secret).filter(Secret.token == secret["token"]).one()
    assert row_after.ciphertext is None
    assert row_after.viewed is True
    assert row_after.viewed_at is not None
    assert row_after.viewed_by_id == user["id"]


def test_plaintext_is_never_stored_in_the_database(client: TestClient, db):
    """
    Encryption at rest. Someone who dumps the secrets table must find nothing
    usable -- so the plaintext must not appear in ANY column of the row.
    """
    from app.models import Secret

    user = make_user(client, "frank@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    row = db.query(Secret).filter(Secret.token == secret["token"]).one()
    all_columns = " ".join(str(getattr(row, c.name)) for c in row.__table__.columns)

    assert PLAINTEXT not in all_columns
    assert row.ciphertext is not None


def test_metadata_endpoint_does_not_consume_the_secret(client: TestClient):
    """
    GET must be safe. Checking a link ten times must not burn it -- otherwise
    a Slack link preview would destroy the secret before anyone read it.
    """
    user = make_user(client, "grace@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    for _ in range(10):
        meta = client.get(f"/secrets/{secret['token']}", headers=user["headers"])
        assert meta.status_code == 200
        assert meta.json()["is_available"] is True
        assert "plaintext" not in meta.json()

    # It still works afterwards.
    reveal = client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])
    assert reveal.status_code == 200
    assert reveal.json()["plaintext"] == PLAINTEXT


def test_metadata_reports_viewed_after_a_reveal(client: TestClient):
    user = make_user(client, "heidi@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])
    meta = client.get(f"/secrets/{secret['token']}", headers=user["headers"])

    assert meta.status_code == 200
    assert meta.json()["viewed"] is True
    assert meta.json()["is_available"] is False


def test_unknown_token_is_404(client: TestClient):
    user = make_user(client, "ivan@example.com")

    response = client.post("/secrets/does-not-exist/reveal", headers=user["headers"])

    assert response.status_code == 404


def test_reveal_requires_authentication(client: TestClient):
    user = make_user(client, "judy@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    response = client.post(f"/secrets/{secret['token']}/reveal")  # no headers

    assert response.status_code == 401


# ==========================================================================
# The two race-condition tests.
# ==========================================================================
def test_atomic_update_lets_only_one_of_two_stale_readers_win(client: TestClient):
    """
    DETERMINISTIC proof that the conditional UPDATE is what protects us.

    This reproduces the exact interleaving that breaks the naive
    read-check-write implementation:

        session A reads the row   (viewed = False)
        session B reads the row   (viewed = False)   <-- both hold a stale view
        session A claims it       -> succeeds
        session B claims it       -> must fail

    Both sessions run the SAME statement the endpoint runs. Because the
    `WHERE viewed = false` check lives inside the UPDATE, B's statement
    matches zero rows and returns nothing -- even though B decided to try
    while the row still looked unread.

    Had the check been a separate `if secret.viewed:` in Python, B would have
    passed it and both sessions would have returned the plaintext.
    """
    from sqlalchemy import select, update

    from app.database import SessionLocal
    from app.models import Secret
    from app.timeutil import utc_now

    user = make_user(client, "ken@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)
    token = secret["token"]

    session_a = SessionLocal()
    session_b = SessionLocal()
    try:
        now = utc_now()

        # Both sessions read the row first and both see viewed = False.
        row_a = session_a.scalar(select(Secret).where(Secret.token == token))
        row_b = session_b.scalar(select(Secret).where(Secret.token == token))
        assert row_a.viewed is False
        assert row_b.viewed is False

        def claim(session):
            """The exact statement from reveal_secret()."""
            statement = (
                update(Secret)
                .where(
                    Secret.token == token,
                    Secret.viewed.is_(False),
                    Secret.expires_at > now,
                )
                .values(viewed=True, viewed_at=now, viewed_by_id=user["id"])
                .returning(Secret.ciphertext)
                .execution_options(synchronize_session=False)
            )
            result = session.execute(statement).first()
            session.commit()
            return result

        result_a = claim(session_a)
        result_b = claim(session_b)

        # A claimed the row and got the ciphertext back.
        assert result_a is not None
        assert result_a[0] is not None

        # B, working from an equally stale view, got nothing at all.
        assert result_b is None
    finally:
        session_a.close()
        session_b.close()


def test_concurrent_reveals_return_exactly_one_success(client: TestClient):
    """
    The same guarantee, tested through real concurrent HTTP requests.

    Eight threads fire POST /reveal at the same token simultaneously. Exactly
    one must get 200 with the plaintext; every other one must get 410.

    A threaded test can pass by luck, so treat it as a smoke test that backs
    up the deterministic one above rather than as the primary proof. It is
    most valuable when re-run against PostgreSQL, where it exercises real
    row-level locking:

        TEST_DATABASE_URL="postgresql+psycopg2://localhost/secretshare_test" pytest
    """
    user = make_user(client, "laura@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)
    token = secret["token"]

    thread_count = 8
    responses: list = []
    responses_lock = threading.Lock()

    # A barrier makes all threads wait until every one of them is ready, then
    # releases them together. Without it the first thread would usually finish
    # before the last one started, and nothing would actually be concurrent.
    start_together = threading.Barrier(thread_count)

    def attempt_reveal():
        start_together.wait()
        response = client.post(f"/secrets/{token}/reveal", headers=user["headers"])
        with responses_lock:
            responses.append((response.status_code, response.text))

    threads = [threading.Thread(target=attempt_reveal) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert len(responses) == thread_count

    successes = [r for r in responses if r[0] == 200]
    gone = [r for r in responses if r[0] == 410]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}"
    assert len(gone) == thread_count - 1
    assert PLAINTEXT in successes[0][1]

    # And no loser saw the plaintext.
    for _, text in gone:
        assert PLAINTEXT not in text
