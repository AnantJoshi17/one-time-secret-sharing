"""
Tests for the browser frontend served by FastAPI.

The important one is test_loading_the_reveal_page_does_not_consume_the_secret.
The whole GET/POST split exists so that opening a share link is harmless, and
that property is easy to break by accident later.
"""

from fastapi.testclient import TestClient

from tests.conftest import create_secret, make_user

PLAINTEXT = "frontend-secret-value"


def test_home_page_is_served(client: TestClient):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "One-Time Secret Sharing" in response.text


def test_static_assets_are_served(client: TestClient):
    stylesheet = client.get("/static/style.css")
    script = client.get("/static/api.js")

    assert stylesheet.status_code == 200
    assert "text/css" in stylesheet.headers["content-type"]

    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]


def test_share_url_points_at_the_landing_page(client: TestClient):
    """
    The link handed to a human must be the browser page, not the API path.

    Pasting the raw API path into a browser would send an unauthenticated GET
    and return a 401 JSON body, which is useless to the person you sent it to.
    """
    user = make_user(client, "alice@example.com")

    created = create_secret(client, user["headers"], PLAINTEXT)

    assert created["share_url"].endswith(f"/s/{created['token']}")
    assert "/secrets/" not in created["share_url"]


def test_reveal_page_is_served_for_any_token(client: TestClient):
    """
    The page is the same HTML whatever the token, and serving it never touches
    the database -- so an unknown token still returns 200. The page discovers
    that the link is invalid by calling the API from the browser.
    """
    response = client.get("/s/some-token-that-does-not-exist")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Someone shared a secret with you" in response.text


def test_loading_the_reveal_page_does_not_consume_the_secret(client: TestClient):
    """
    The guarantee the GET/POST split exists to provide.

    A browser prefetch, a Slack unfurl or a mail scanner following the share
    link must not burn the secret. Loading the page ten times, unauthenticated,
    must leave it perfectly readable.
    """
    user = make_user(client, "bob@example.com")
    created = create_secret(client, user["headers"], PLAINTEXT)

    for _ in range(10):
        page = client.get(f"/s/{created['token']}")
        assert page.status_code == 200
        # The page must not contain the secret either -- it is fetched by the
        # browser afterwards, not baked into the HTML.
        assert PLAINTEXT not in page.text

    # Still readable.
    revealed = client.post(
        f"/secrets/{created['token']}/reveal", headers=user["headers"]
    )
    assert revealed.status_code == 200
    assert revealed.json()["plaintext"] == PLAINTEXT


def test_the_pages_are_not_in_the_api_schema(client: TestClient):
    """
    The HTML pages are for humans, so they are excluded from the OpenAPI
    schema and do not clutter /docs.
    """
    schema = client.get("/openapi.json").json()

    assert "/" not in schema["paths"]
    assert "/s/{token}" not in schema["paths"]
    # The real API endpoints are still documented.
    assert "/secrets/{token}/reveal" in schema["paths"]


def test_docs_page_still_works(client: TestClient):
    response = client.get("/docs")

    assert response.status_code == 200
    assert "swagger" in response.text.lower()
