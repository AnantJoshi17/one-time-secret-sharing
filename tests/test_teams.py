"""
Tests for teams and the access checks built on them.

The access rule under test, in one sentence: you may read a secret if you
created it, or if it was created inside the team you are currently in.
"""

from fastapi.testclient import TestClient

from tests.conftest import create_secret, make_user

PLAINTEXT = "shared-team-credential"


def make_team(client: TestClient, headers: dict, name: str = "Backend") -> dict:
    response = client.post("/teams", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def join_team(client: TestClient, headers: dict, invite_code: str) -> dict:
    response = client.post(
        "/teams/join", json={"invite_code": invite_code}, headers=headers
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_create_team_makes_you_a_member(client: TestClient):
    user = make_user(client, "alice@example.com")

    team = make_team(client, user["headers"])

    assert team["name"] == "Backend"
    assert team["invite_code"]
    assert [m["email"] for m in team["members"]] == ["alice@example.com"]

    me = client.get("/auth/me", headers=user["headers"]).json()
    assert me["team_id"] == team["id"]


def test_join_team_with_an_invite_code(client: TestClient):
    owner = make_user(client, "bob@example.com")
    joiner = make_user(client, "carol@example.com")

    team = make_team(client, owner["headers"])
    join_team(client, joiner["headers"], team["invite_code"])

    members = client.get("/teams/me", headers=joiner["headers"]).json()["members"]
    assert {m["email"] for m in members} == {"bob@example.com", "carol@example.com"}


def test_join_with_a_bad_invite_code_is_404(client: TestClient):
    user = make_user(client, "dave@example.com")

    response = client.post(
        "/teams/join", json={"invite_code": "not-a-real-code"}, headers=user["headers"]
    )

    assert response.status_code == 404


def test_cannot_join_two_teams(client: TestClient):
    owner = make_user(client, "erin@example.com")
    other_owner = make_user(client, "frank@example.com")
    joiner = make_user(client, "grace@example.com")

    team_one = make_team(client, owner["headers"], "Team One")
    team_two = make_team(client, other_owner["headers"], "Team Two")

    join_team(client, joiner["headers"], team_one["invite_code"])
    response = client.post(
        "/teams/join",
        json={"invite_code": team_two["invite_code"]},
        headers=joiner["headers"],
    )

    assert response.status_code == 409


def test_teammate_can_reveal_a_team_secret(client: TestClient):
    """The whole point of teams."""
    owner = make_user(client, "heidi@example.com")
    teammate = make_user(client, "ivan@example.com")

    team = make_team(client, owner["headers"])
    join_team(client, teammate["headers"], team["invite_code"])

    secret = create_secret(client, owner["headers"], PLAINTEXT)
    response = client.post(
        f"/secrets/{secret['token']}/reveal", headers=teammate["headers"]
    )

    assert response.status_code == 200
    assert response.json()["plaintext"] == PLAINTEXT


def test_outsider_cannot_reveal_a_team_secret(client: TestClient):
    owner = make_user(client, "judy@example.com")
    outsider = make_user(client, "ken@example.com")

    make_team(client, owner["headers"])
    secret = create_secret(client, owner["headers"], PLAINTEXT)

    response = client.post(
        f"/secrets/{secret['token']}/reveal", headers=outsider["headers"]
    )

    # 404, not 403: we must not confirm to a stranger that this token is real.
    assert response.status_code == 404
    assert PLAINTEXT not in response.text


def test_a_denied_read_does_not_burn_the_secret(client: TestClient):
    """
    Important: a failed access check must not consume the secret, or anyone
    who guessed a token could destroy other people's secrets without ever
    reading them -- a denial-of-service on the product's core feature.

    This is why the access check happens BEFORE the atomic claim in
    reveal_secret(), not after.
    """
    owner = make_user(client, "laura@example.com")
    outsider = make_user(client, "mallory@example.com")

    secret = create_secret(client, owner["headers"], PLAINTEXT)

    denied = client.post(
        f"/secrets/{secret['token']}/reveal", headers=outsider["headers"]
    )
    assert denied.status_code == 404

    # The rightful owner can still read it.
    allowed = client.post(
        f"/secrets/{secret['token']}/reveal", headers=owner["headers"]
    )
    assert allowed.status_code == 200
    assert allowed.json()["plaintext"] == PLAINTEXT


def test_teamless_users_do_not_share_secrets_with_each_other(client: TestClient):
    """
    Guards the `secret.team_id is not None` check in _user_can_access.

    Both users have team_id = None. Without that explicit None check, the
    comparison None == None would be true and every teamless user would be
    able to read every other teamless user's secrets.
    """
    alice = make_user(client, "nancy@example.com")
    bob = make_user(client, "oscar@example.com")

    assert client.get("/auth/me", headers=alice["headers"]).json()["team_id"] is None
    assert client.get("/auth/me", headers=bob["headers"]).json()["team_id"] is None

    secret = create_secret(client, alice["headers"], PLAINTEXT)
    response = client.post(f"/secrets/{secret['token']}/reveal", headers=bob["headers"])

    assert response.status_code == 404


def test_listing_shows_your_own_and_your_teams_secrets_only(client: TestClient):
    """
    Pins the SQL filter in list_secrets to the Python rule in
    _user_can_access. The two express the same policy in different languages,
    so they can drift apart; this test is what stops that.
    """
    owner = make_user(client, "peggy@example.com")
    teammate = make_user(client, "quinn@example.com")
    outsider = make_user(client, "rupert@example.com")

    team = make_team(client, owner["headers"])
    join_team(client, teammate["headers"], team["invite_code"])

    team_secret = create_secret(client, owner["headers"], "team-secret")
    outsider_secret = create_secret(client, outsider["headers"], "outsider-secret")

    teammate_view = client.get("/secrets", headers=teammate["headers"]).json()
    outsider_view = client.get("/secrets", headers=outsider["headers"]).json()

    teammate_tokens = {s["token"] for s in teammate_view}
    outsider_tokens = {s["token"] for s in outsider_view}

    assert team_secret["token"] in teammate_tokens
    assert outsider_secret["token"] not in teammate_tokens

    assert outsider_secret["token"] in outsider_tokens
    assert team_secret["token"] not in outsider_tokens


def test_listing_never_includes_secret_material(client: TestClient):
    user = make_user(client, "sybil@example.com")
    create_secret(client, user["headers"], PLAINTEXT, label="prod key")

    response = client.get("/secrets", headers=user["headers"])

    assert response.status_code == 200
    assert PLAINTEXT not in response.text
    assert "ciphertext" not in response.text
    # The non-sensitive label is fine to show.
    assert "prod key" in response.text


def test_secret_team_is_frozen_at_creation_time(client: TestClient):
    """
    A secret's team is decided when it is created, not when it is read.

    Otherwise someone switching teams would retroactively hand their old
    secrets to their new colleagues.
    """
    owner = make_user(client, "trent@example.com")
    new_colleague = make_user(client, "ursula@example.com")

    # Owner creates a secret while in NO team.
    solo_secret = create_secret(client, owner["headers"], "made-while-solo")

    # Owner then joins a team with someone else.
    team = make_team(client, new_colleague["headers"], "New Team")
    join_team(client, owner["headers"], team["invite_code"])

    # The new colleague must NOT gain access to the earlier secret.
    response = client.post(
        f"/secrets/{solo_secret['token']}/reveal", headers=new_colleague["headers"]
    )
    assert response.status_code == 404


def test_leaving_a_team_revokes_access(client: TestClient):
    owner = make_user(client, "victor@example.com")
    leaver = make_user(client, "wendy@example.com")

    team = make_team(client, owner["headers"])
    join_team(client, leaver["headers"], team["invite_code"])

    secret = create_secret(client, owner["headers"], PLAINTEXT)

    # Can read it while a member...
    meta = client.get(f"/secrets/{secret['token']}", headers=leaver["headers"])
    assert meta.status_code == 200

    client.post("/teams/leave", headers=leaver["headers"])

    # ...and cannot once they have left.
    after = client.get(f"/secrets/{secret['token']}", headers=leaver["headers"])
    assert after.status_code == 404


def test_teams_me_is_404_when_you_have_no_team(client: TestClient):
    user = make_user(client, "xavier@example.com")

    assert client.get("/teams/me", headers=user["headers"]).status_code == 404
