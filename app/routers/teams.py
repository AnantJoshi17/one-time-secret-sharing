"""
Teams.

    POST /teams        create a team (you become its first member)
    POST /teams/join   join an existing team using its invite code
    GET  /teams/me     show your team and its members
    POST /teams/leave  leave your team

The point of a team is access: a secret created by a team member can be read
by any other member of that team. See _user_can_access in routers/secrets.py.

Joining is by INVITE CODE rather than "an admin adds you by user id". That
choice means you cannot be pulled into a team without someone deliberately
handing you the code, and it keeps the model to one table and one column.
"""

import secrets as secrets_module

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import ACTION_TEAM_CREATE, ACTION_TEAM_JOIN, record_audit
from app.database import get_db
from app.dependencies import get_client_ip, get_current_user
from app.models import Team, User
from app.schemas import MessageResponse, TeamCreate, TeamJoin, TeamRead

router = APIRouter(prefix="/teams", tags=["teams"])


def _team_response(team: Team, include_invite_code: bool) -> TeamRead:
    """
    Serialise a team.

    The invite code is a credential -- anyone holding it can join and then
    read the team's secrets -- so it is only included for actual members.
    """
    return TeamRead(
        id=team.id,
        name=team.name,
        created_at=team.created_at,
        members=[{"id": m.id, "email": m.email} for m in team.members],
        invite_code=team.invite_code if include_invite_code else None,
    )


@router.post("", response_model=TeamRead, status_code=status.HTTP_201_CREATED)
def create_team(
    payload: TeamCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    client_ip: str = Depends(get_client_ip),
) -> TeamRead:
    """Create a team and join it."""
    # A user belongs to at most one team (users.team_id is a single column),
    # so creating a second one would silently move them. Refuse instead.
    if current_user.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are already in a team. Leave it before creating another.",
        )

    team = Team(
        name=payload.name.strip(),
        invite_code=secrets_module.token_urlsafe(12),
    )
    db.add(team)

    # flush() sends the INSERT so the database assigns team.id, but does NOT
    # commit. We need the id right now to point the user at it, and both
    # writes still land in the same transaction.
    db.flush()

    current_user.team_id = team.id

    record_audit(
        db,
        action=ACTION_TEAM_CREATE,
        user=current_user,
        team_id=team.id,
        ip_address=client_ip,
        detail=f"name={team.name}",
    )
    db.commit()
    db.refresh(team)

    return _team_response(team, include_invite_code=True)


@router.post("/join", response_model=TeamRead)
def join_team(
    payload: TeamJoin,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    client_ip: str = Depends(get_client_ip),
) -> TeamRead:
    """Join a team using the invite code one of its members gave you."""
    if current_user.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are already in a team. Leave it before joining another.",
        )

    team = db.scalar(
        select(Team).where(Team.invite_code == payload.invite_code.strip())
    )
    if team is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid invite code"
        )

    current_user.team_id = team.id

    record_audit(
        db,
        action=ACTION_TEAM_JOIN,
        user=current_user,
        team_id=team.id,
        ip_address=client_ip,
    )
    db.commit()
    db.refresh(team)

    return _team_response(team, include_invite_code=True)


@router.get("/me", response_model=TeamRead)
def read_my_team(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TeamRead:
    """Show the team you are in, with its members."""
    if current_user.team_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="You are not in a team"
        )

    team = db.get(Team, current_user.team_id)
    if team is None:
        # Only reachable if the team row was deleted directly in the database;
        # the FK is ON DELETE SET NULL so this should self-heal.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="You are not in a team"
        )

    return _team_response(team, include_invite_code=True)


@router.post("/leave", response_model=MessageResponse)
def leave_team(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    """
    Leave your team.

    Note what this does NOT do: it does not revoke your access to secrets you
    already created, because those keep their own creator_id. It does stop you
    reading your ex-colleagues' secrets from this moment on, and it does not
    retroactively hide the secrets you made while you were a member -- those
    still carry the old team_id, which is the frozen-at-creation behaviour
    explained in models.py.
    """
    if current_user.team_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="You are not in a team"
        )

    current_user.team_id = None
    db.commit()

    return MessageResponse(detail="You have left the team")
