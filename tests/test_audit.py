"""
Tests for the audit log.

Two things matter here: that the right events get recorded, and that the log
never becomes a side channel for reading secrets or other people's activity.
"""

from fastapi.testclient import TestClient

from tests.conftest import create_secret, make_user

PLAINTEXT = "audited-secret-value"


def test_creating_a_secret_is_recorded(client: TestClient):
    user = make_user(client, "alice@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    entries = client.get(
        "/audit", params={"action": "secret.create"}, headers=user["headers"]
    ).json()

    assert len(entries) == 1
    assert entries[0]["secret_token"] == secret["token"]
    assert entries[0]["user_id"] == user["id"]


def test_revealing_a_secret_records_who_read_it(client: TestClient):
    owner = make_user(client, "bob@example.com")
    teammate = make_user(client, "carol@example.com")

    team = client.post("/teams", json={"name": "Backend"}, headers=owner["headers"]).json()
    client.post(
        "/teams/join", json={"invite_code": team["invite_code"]}, headers=teammate["headers"]
    )

    secret = create_secret(client, owner["headers"], PLAINTEXT)
    client.post(f"/secrets/{secret['token']}/reveal", headers=teammate["headers"])

    entries = client.get(
        "/audit", params={"action": "secret.reveal"}, headers=owner["headers"]
    ).json()

    # The owner can see that their teammate read it -- which is the whole
    # reason to keep an audit log.
    assert len(entries) == 1
    assert entries[0]["user_id"] == teammate["id"]
    assert entries[0]["secret_token"] == secret["token"]


def test_a_failed_second_read_is_recorded(client: TestClient):
    user = make_user(client, "dave@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])
    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])  # 410

    entries = client.get(
        "/audit", params={"action": "secret.reveal_missed"}, headers=user["headers"]
    ).json()

    assert len(entries) == 1
    assert entries[0]["detail"] == "already viewed"


def test_a_denied_read_is_recorded(client: TestClient):
    owner = make_user(client, "erin@example.com")
    outsider = make_user(client, "frank@example.com")

    secret = create_secret(client, owner["headers"], PLAINTEXT)
    client.post(f"/secrets/{secret['token']}/reveal", headers=outsider["headers"])

    # The outsider's own log shows the denial.
    entries = client.get(
        "/audit", params={"action": "secret.reveal_denied"}, headers=outsider["headers"]
    ).json()

    assert len(entries) == 1
    assert entries[0]["secret_token"] == secret["token"]


def test_the_audit_log_never_contains_the_plaintext(client: TestClient, db):
    """
    An audit log that records the secret would defeat the entire product: the
    secret would be destroyed from the secrets table and then sit forever in
    audit_logs. This checks every column of every row.
    """
    from app.models import AuditLog

    user = make_user(client, "grace@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT, label="prod key")
    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])

    all_rows = db.query(AuditLog).all()
    assert len(all_rows) > 0

    for row in all_rows:
        flattened = " ".join(
            str(getattr(row, column.name)) for column in row.__table__.columns
        )
        assert PLAINTEXT not in flattened


def test_you_cannot_see_another_users_audit_entries(client: TestClient):
    alice = make_user(client, "heidi@example.com")
    bob = make_user(client, "ivan@example.com")

    create_secret(client, alice["headers"], "alice-secret")

    bobs_view = client.get("/audit", headers=bob["headers"]).json()

    assert all(entry["user_id"] != alice["id"] for entry in bobs_view)


def test_audit_can_be_filtered_by_secret_token(client: TestClient):
    user = make_user(client, "judy@example.com")
    first = create_secret(client, user["headers"], "one")
    create_secret(client, user["headers"], "two")

    entries = client.get(
        "/audit", params={"secret_token": first["token"]}, headers=user["headers"]
    ).json()

    assert len(entries) >= 1
    assert all(entry["secret_token"] == first["token"] for entry in entries)


def test_audit_requires_authentication(client: TestClient):
    assert client.get("/audit").status_code == 401


def test_the_full_lifecycle_of_a_secret_is_traceable(client: TestClient):
    """End to end: create, read, and the failed second read, all in order."""
    user = make_user(client, "ken@example.com")
    secret = create_secret(client, user["headers"], PLAINTEXT)

    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])
    client.post(f"/secrets/{secret['token']}/reveal", headers=user["headers"])

    entries = client.get(
        "/audit", params={"secret_token": secret["token"]}, headers=user["headers"]
    ).json()

    actions = {entry["action"] for entry in entries}
    assert actions == {"secret.create", "secret.reveal", "secret.reveal_missed"}
