"""Initial schema: teams, users, secrets, audit_logs.

Revision ID: 0001
Revises:
Create Date: 2026-09-19

This is the first migration, so `down_revision` is None -- it is the root of
the chain. Every later migration will point back at this one by its revision
id, forming a linked list that Alembic walks.

Reading a migration: `upgrade()` applies the change, `downgrade()` undoes it.
Alembic will not write a correct downgrade for you in every case, so always
read it before trusting it. Here it simply drops the four tables in reverse
dependency order (a table cannot be dropped while another still has a foreign
key pointing at it).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- teams --------------------------------------------------------------
    # Created first because users.team_id and secrets.team_id both reference
    # it. A foreign key cannot point at a table that does not exist yet.
    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("invite_code", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            # sa.func.now() is portable: SQLAlchemy renders it as now() on
            # PostgreSQL and CURRENT_TIMESTAMP on SQLite. Hard-coding either
            # one would tie this migration to a single database.
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    # unique=True here creates a UNIQUE INDEX, which does double duty: it
    # enforces that no two teams share an invite code, and it makes the
    # lookup in POST /teams/join an index scan rather than a full table scan.
    op.create_index("ix_teams_invite_code", "teams", ["invite_code"], unique=True)

    # -- users --------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column("team_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # ondelete="SET NULL": if a team is deleted, its members survive and
        # simply become teamless. The alternative, CASCADE, would delete the
        # users along with the team -- catastrophic and almost never what you
        # want. Always think about which way a cascade points.
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_team_id", "users", ["team_id"], unique=False)

    # -- secrets ------------------------------------------------------------
    op.create_table(
        "secrets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        # Nullable because destroying a secret means setting this to NULL.
        sa.Column("ciphertext", sa.Text(), nullable=True),
        sa.Column("label", sa.String(length=120), nullable=True),
        sa.Column("creator_id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "viewed", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("viewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("viewed_by_id", sa.Integer(), nullable=True),
        # Deleting a user removes the secrets they created...
        sa.ForeignKeyConstraint(["creator_id"], ["users.id"], ondelete="CASCADE"),
        # ...but does NOT delete secrets they merely read; that column just
        # becomes NULL.
        sa.ForeignKeyConstraint(["viewed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    # The single most important index in the schema: every reveal looks a
    # secret up by this token, and it must be unique because the token IS the
    # identity of the shareable link.
    op.create_index("ix_secrets_token", "secrets", ["token"], unique=True)
    op.create_index("ix_secrets_creator_id", "secrets", ["creator_id"], unique=False)
    op.create_index("ix_secrets_team_id", "secrets", ["team_id"], unique=False)
    # Supports the cleanup endpoint's "WHERE expires_at <= now()" sweep.
    op.create_index("ix_secrets_expires_at", "secrets", ["expires_at"], unique=False)
    op.create_index("ix_secrets_viewed", "secrets", ["viewed"], unique=False)

    # -- audit_logs ---------------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("team_id", sa.Integer(), nullable=True),
        # Note: a plain string column, NOT a foreign key to secrets.id. The
        # audit trail has to outlive the secret it describes.
        sa.Column("secret_token", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"], unique=False)
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)
    op.create_index("ix_audit_logs_team_id", "audit_logs", ["team_id"], unique=False)
    op.create_index(
        "ix_audit_logs_secret_token", "audit_logs", ["secret_token"], unique=False
    )
    op.create_index(
        "ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False
    )


def downgrade() -> None:
    # Reverse order: drop the tables that point at others before the ones
    # being pointed at, or the foreign keys will block the DROP.
    op.drop_table("audit_logs")
    op.drop_table("secrets")
    op.drop_table("users")
    op.drop_table("teams")
    # The indexes are dropped automatically with their tables, so there is no
    # need to drop them one by one here.
