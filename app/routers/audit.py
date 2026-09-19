"""
Reading the audit log.

    GET /audit   the events you are allowed to see

Who can see what:
    * You always see your own events.
    * If you are in a team, you also see your team's events -- otherwise
      "someone on my team read that secret, who?" would be unanswerable,
      which is the main reason to have an audit log at all.

The log is append-only: there is no endpoint here to edit or delete an entry,
and that is the point. An audit trail you can quietly rewrite is not evidence.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import AuditLog, User
from app.schemas import AuditLogRead

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_entries(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    action: str | None = Query(
        default=None, description="Filter to one action, e.g. secret.reveal"
    ),
    secret_token: str | None = Query(
        default=None, description="Filter to the history of one secret"
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditLog]:
    """Most recent events first."""
    visibility = [AuditLog.user_id == current_user.id]
    if current_user.team_id is not None:
        visibility.append(AuditLog.team_id == current_user.team_id)

    stmt = select(AuditLog).where(or_(*visibility))

    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if secret_token is not None:
        stmt = stmt.where(AuditLog.secret_token == secret_token)

    stmt = stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    stmt = stmt.limit(limit).offset(offset)

    return list(db.scalars(stmt).all())
