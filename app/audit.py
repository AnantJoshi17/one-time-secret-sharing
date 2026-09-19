"""
Writing the audit log.

One helper, used from every endpoint that does something worth remembering.
Centralising it means the columns are filled in consistently and there is a
single place to check that we never log a secret's contents.
"""

from sqlalchemy.orm import Session

from app.models import AuditLog, User

# The full vocabulary of actions, as constants rather than loose strings so a
# typo is an AttributeError at import time instead of a row nobody can query.
ACTION_USER_REGISTER = "user.register"
ACTION_USER_LOGIN = "user.login"
ACTION_USER_LOGIN_FAILED = "user.login_failed"
ACTION_TEAM_CREATE = "team.create"
ACTION_TEAM_JOIN = "team.join"
ACTION_SECRET_CREATE = "secret.create"
ACTION_SECRET_REVEAL = "secret.reveal"
ACTION_SECRET_REVEAL_DENIED = "secret.reveal_denied"
ACTION_SECRET_REVEAL_MISSED = "secret.reveal_missed"
ACTION_CLEANUP = "maintenance.cleanup"


def record_audit(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    user_id: int | None = None,
    team_id: int | None = None,
    secret_token: str | None = None,
    ip_address: str | None = None,
    detail: str | None = None,
) -> AuditLog:
    """
    Add one audit row to the session.

    Note: this only ADDS to the session -- it does not commit. The caller
    commits, which means the audit entry lands in the same transaction as the
    thing it describes. Either both are written or neither is, so you can
    never end up with a "secret revealed" log line for a reveal that was
    rolled back.

    Keyword-only arguments (that is what the bare `*` does) because a call
    like record_audit(db, "secret.reveal", user, None, None, ip) is unreadable
    and easy to get wrong.
    """
    if user is not None:
        # Convenience: pass the User object and we pull the ids off it.
        user_id = user.id
        if team_id is None:
            team_id = user.team_id

    entry = AuditLog(
        action=action,
        user_id=user_id,
        team_id=team_id,
        secret_token=secret_token,
        ip_address=ip_address,
        detail=detail,
    )
    db.add(entry)
    return entry
