"""
The database tables, described as Python classes (this is what an ORM is).

Each class below becomes one table. Each `mapped_column(...)` becomes one
column. SQLAlchemy reads these classes to build `Base.metadata`, and Alembic
reads `Base.metadata` to generate migrations.

Four tables:

    teams        -- a group of users
    users        -- people who can log in; each belongs to 0 or 1 team
    secrets      -- the encrypted payloads, one row per shareable link
    audit_logs   -- an append-only record of who did what, and when

Relationship cheat-sheet for the `relationship()` lines:
    ForeignKey   = the actual column + constraint in the database.
    relationship = the convenience attribute in Python. It creates no column;
                   it just tells SQLAlchemy how to follow the foreign key for
                   you, so you can write `user.team` instead of a manual query.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Team(Base):
    """A group of users who are allowed to read each other's secrets."""

    __tablename__ = "teams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # A random string that an existing member shares with someone so they can
    # join. Using a code (instead of "anyone can add anyone by user id") means
    # you cannot pull a stranger into your team without their cooperation.
    invite_code: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # server_default=func.now() means PostgreSQL fills this in, so the value is
    # correct even for rows inserted by a migration or by hand in psql.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    members: Mapped[list["User"]] = relationship(back_populates="team")

    def __repr__(self) -> str:  # helps when debugging in a REPL
        return f"<Team id={self.id} name={self.name!r}>"


class User(Base):
    """Someone who can log in and create secrets."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # unique=True creates a UNIQUE constraint in the database itself. That is
    # the only reliable way to stop two simultaneous registrations from
    # creating the same account -- checking "does this email exist?" in Python
    # first is a race condition, because another request can insert between
    # your check and your insert.
    email: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )

    # The bcrypt hash, NEVER the password. See app/security.py.
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )

    # Nullable: a user does not have to be in a team.
    team_id: Mapped[int | None] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    team: Mapped["Team | None"] = relationship(back_populates="members")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"


class Secret(Base):
    """
    One encrypted payload, readable exactly once.

    The lifecycle of a row is:
        created   -> viewed=False, ciphertext is set
        revealed  -> viewed=True,  ciphertext is wiped to NULL
        expired   -> ciphertext wiped to NULL by the read path or by cleanup

    Note that the row itself survives being read. We keep it so that a second
    reader gets an honest "this link was already used" (410 Gone) instead of a
    misleading "no such link" (404), and so the audit trail still has something
    to point at. The sensitive part -- the ciphertext -- is what gets destroyed.
    """

    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # This is the unguessable part of the shareable link, NOT the primary key.
    #
    # Using the integer id in the URL would be a disaster: /secrets/41 tells
    # you that /secrets/42 probably exists. This token comes from
    # secrets.token_urlsafe(32), which is 256 bits of cryptographic randomness.
    token: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # The Fernet ciphertext. Nullable because destroying a secret means setting
    # this to NULL -- at that point the plaintext is unrecoverable, which is
    # exactly the guarantee the product makes.
    ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)

    # A short, non-sensitive label so a list of secrets is readable. This is
    # stored in plaintext, so the API forbids putting the secret itself here.
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)

    creator_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Copied from the creator's team AT CREATION TIME, on purpose.
    #
    # If we instead looked up `secret.creator.team_id` at read time, then a
    # user changing teams would retroactively hand their old secrets to their
    # new colleagues. Freezing it here means access is decided by the state of
    # the world when the secret was made.
    team_id: Mapped[int | None] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # The single-read flag. This column is the whole ballgame -- see the
    # atomic UPDATE in app/routers/secrets.py.
    viewed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false", index=True
    )
    viewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    viewed_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # foreign_keys= is required here because this table has TWO foreign keys
    # pointing at users (creator_id and viewed_by_id), so SQLAlchemy cannot
    # work out which one each relationship should follow on its own.
    creator: Mapped["User"] = relationship(foreign_keys=[creator_id])
    viewed_by: Mapped["User | None"] = relationship(foreign_keys=[viewed_by_id])

    def __repr__(self) -> str:
        return f"<Secret id={self.id} token={self.token[:8]}... viewed={self.viewed}>"


class AuditLog(Base):
    """
    Append-only history. Rows are written, never updated or deleted.

    Deliberately NOT foreign-keyed to secrets.id: the audit trail has to
    outlive the thing it describes, and a FK with ON DELETE CASCADE would
    quietly erase the evidence when a secret row is purged. We store the
    token as a plain string instead.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # A short machine-readable verb, e.g. "secret.reveal" or "user.login".
    # The full list lives in app/audit.py.
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    # Nullable because some events (a failed login, an anonymous read attempt)
    # genuinely have no authenticated user attached.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    team_id: Mapped[int | None] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"), nullable=True, index=True
    )

    secret_token: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Free-text context, e.g. "already viewed". Must never contain the secret.
    detail: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    user: Mapped["User | None"] = relationship()

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action!r}>"
