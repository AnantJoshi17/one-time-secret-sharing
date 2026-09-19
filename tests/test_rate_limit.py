"""
Tests for the per-IP rate limit on secret creation.

Two levels:
  * the pure function check_rate_limit(), tested directly -- fast and precise;
  * the endpoint, tested through HTTP -- proves the dependency is wired up.
"""

from fastapi.testclient import TestClient

from app.config import settings
from app.rate_limit import check_rate_limit, reset_rate_limits
from tests.conftest import make_user


def test_requests_under_the_limit_are_allowed():
    reset_rate_limits()

    for _ in range(5):
        allowed, retry_after = check_rate_limit("10.0.0.1", max_requests=5, window_seconds=60)
        assert allowed is True
        assert retry_after == 0


def test_the_request_over_the_limit_is_blocked():
    reset_rate_limits()

    for _ in range(3):
        check_rate_limit("10.0.0.2", max_requests=3, window_seconds=60)

    allowed, retry_after = check_rate_limit("10.0.0.2", max_requests=3, window_seconds=60)

    assert allowed is False
    assert retry_after > 0  # tells the caller how long to wait


def test_the_limit_is_tracked_per_ip():
    """One noisy client must not lock everybody else out."""
    reset_rate_limits()

    for _ in range(3):
        check_rate_limit("10.0.0.3", max_requests=3, window_seconds=60)

    blocked, _ = check_rate_limit("10.0.0.3", max_requests=3, window_seconds=60)
    other_client, _ = check_rate_limit("10.0.0.4", max_requests=3, window_seconds=60)

    assert blocked is False
    assert other_client is True


def test_old_requests_fall_out_of_the_window():
    """
    The window SLIDES: a request from longer ago than window_seconds no longer
    counts against you.

    Tested with a zero-second window rather than by sleeping, so it is instant.
    """
    reset_rate_limits()

    for _ in range(3):
        check_rate_limit("10.0.0.5", max_requests=3, window_seconds=60)

    assert check_rate_limit("10.0.0.5", max_requests=3, window_seconds=60)[0] is False

    # With a zero-length window every earlier timestamp is already expired.
    assert check_rate_limit("10.0.0.5", max_requests=3, window_seconds=0)[0] is True


def test_creating_too_many_secrets_returns_429(client: TestClient, monkeypatch):
    """The limiter is actually attached to POST /secrets."""
    monkeypatch.setattr(settings, "rate_limit_max_requests", 3)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)

    user = make_user(client, "alice@example.com")

    statuses = []
    for index in range(5):
        response = client.post(
            "/secrets", json={"plaintext": f"secret-{index}"}, headers=user["headers"]
        )
        statuses.append(response.status_code)

    assert statuses[:3] == [201, 201, 201]
    assert statuses[3:] == [429, 429]


def test_the_429_response_includes_a_retry_after_header(client: TestClient, monkeypatch):
    """A well-behaved client reads Retry-After instead of hammering us."""
    monkeypatch.setattr(settings, "rate_limit_max_requests", 1)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)

    user = make_user(client, "bob@example.com")

    client.post("/secrets", json={"plaintext": "first"}, headers=user["headers"])
    blocked = client.post("/secrets", json={"plaintext": "second"}, headers=user["headers"])

    assert blocked.status_code == 429
    assert "retry-after" in {k.lower() for k in blocked.headers}
    assert int(blocked.headers["retry-after"]) > 0


def test_reading_a_secret_is_not_rate_limited(client: TestClient, monkeypatch):
    """
    Only creation is limited. Reads are cheap, self-limiting (each token works
    once), and rate limiting them would let an attacker deny service to a
    legitimate reader just by burning the quota from the same IP.
    """
    monkeypatch.setattr(settings, "rate_limit_max_requests", 1)

    user = make_user(client, "carol@example.com")
    created = client.post(
        "/secrets", json={"plaintext": "readable"}, headers=user["headers"]
    ).json()

    # Many reads, well past the creation limit of 1.
    for _ in range(10):
        response = client.get(f"/secrets/{created['token']}", headers=user["headers"])
        assert response.status_code == 200


def test_the_x_forwarded_for_header_identifies_the_client(client: TestClient, monkeypatch):
    """
    Behind a proxy the client IP comes from X-Forwarded-For. Without this,
    every request on Render would look like it came from one address and the
    first busy user would rate limit everyone.
    """
    monkeypatch.setattr(settings, "rate_limit_max_requests", 2)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)

    user = make_user(client, "dave@example.com")

    def create_as(ip: str):
        return client.post(
            "/secrets",
            json={"plaintext": "x"},
            headers={**user["headers"], "X-Forwarded-For": ip},
        ).status_code

    assert create_as("203.0.113.1") == 201
    assert create_as("203.0.113.1") == 201
    assert create_as("203.0.113.1") == 429   # this IP is out of quota

    # A different client IP is unaffected.
    assert create_as("203.0.113.2") == 201
