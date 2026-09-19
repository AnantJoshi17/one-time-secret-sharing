"""
Pydantic schemas: the shapes of what goes in and what comes out of the API.

Keeping these separate from the SQLAlchemy models in app/models.py is not
ceremony -- it is the single most important habit in a FastAPI codebase.
The model is what the DATABASE stores; the schema is what the OUTSIDE WORLD
is allowed to send and see. If you return ORM objects directly, then the day
you add a `hashed_password` column you have leaked every password hash.

Naming convention used here:
    XCreate  -- what the client sends to create an X
    XRead    -- what we send back about an X
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.config import settings

# `from_attributes=True` lets Pydantic build a schema straight from an ORM
# object by reading its attributes (user.email) rather than expecting a dict
# (user["email"]). Without it, `UserRead.model_validate(user_row)` fails.
ORM_CONFIG = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Users and auth
# ---------------------------------------------------------------------------
class UserCreate(BaseModel):
    # EmailStr does real validation, not a regex guess -- "bob@" is rejected.
    email: EmailStr

    # min_length is a genuine security control, and max_length exists because
    # bcrypt only looks at the first 72 bytes (see app/security.py).
    password: str = Field(min_length=8, max_length=72)


class UserRead(BaseModel):
    model_config = ORM_CONFIG

    id: int
    email: EmailStr
    team_id: int | None
    created_at: datetime
    # Note what is absent: hashed_password. It is not in this schema, so it
    # physically cannot be serialised into a response.


class LoginResponse(BaseModel):
    """
    The response shape for POST /auth/login.

    The field names `access_token` and `token_type` are dictated by the OAuth2
    spec, which is what Swagger UI's Authorize button expects. Renaming them
    to something prettier would break that integration.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


# ---------------------------------------------------------------------------
# Teams
# ---------------------------------------------------------------------------
class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class TeamJoin(BaseModel):
    invite_code: str = Field(min_length=1, max_length=64)


class TeamMember(BaseModel):
    model_config = ORM_CONFIG

    id: int
    email: EmailStr


class TeamRead(BaseModel):
    model_config = ORM_CONFIG

    id: int
    name: str
    created_at: datetime
    members: list[TeamMember] = []

    # The invite code is only included when you are already a member -- the
    # endpoint decides. It is a credential, so it is Optional here rather than
    # always present.
    invite_code: str | None = None


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
class SecretCreate(BaseModel):
    # The actual sensitive value. This is the only place it ever appears in a
    # request body, and it is never echoed back in any response schema.
    #
    # The maximum comes from settings, so MAX_SECRET_LENGTH in .env is real
    # rather than decorative. It is read once, when this class is defined.
    plaintext: str = Field(min_length=1, max_length=settings.max_secret_length)

    # Optional human-readable name, stored UNENCRYPTED so lists are useful.
    # The description shows up in the generated API docs.
    label: str | None = Field(
        default=None,
        max_length=120,
        description="Non-sensitive label, stored unencrypted. Never put the secret here.",
    )

    # None means "use DEFAULT_TTL_MINUTES from the settings".
    ttl_minutes: int | None = Field(
        default=None,
        ge=1,
        description="Minutes until the link expires. Defaults to DEFAULT_TTL_MINUTES.",
    )


class SecretCreated(BaseModel):
    """Returned once, at creation. This is the only time the link is shown."""

    token: str
    share_url: str
    label: str | None
    expires_at: datetime
    team_id: int | None


class SecretMetadata(BaseModel):
    """
    Everything about a secret EXCEPT the secret.

    Used for listing and for the non-destructive GET, so a client can show
    "this link is still valid, it expires in 20 minutes" without burning it.
    """

    model_config = ORM_CONFIG

    token: str
    label: str | None
    creator_id: int
    team_id: int | None
    created_at: datetime
    expires_at: datetime
    viewed: bool
    viewed_at: datetime | None
    viewed_by_id: int | None
    is_expired: bool
    is_available: bool  # not viewed AND not expired -- i.e. reading it would work


class SecretRevealed(BaseModel):
    """
    The one and only response that ever contains the plaintext.

    By the time this is serialised, the database row has already been marked
    viewed and its ciphertext wiped. If the network drops this response, the
    secret is gone -- which is the correct, if harsh, behaviour for a
    one-time secret, and it is called out in the README.
    """

    token: str
    plaintext: str
    label: str | None
    revealed_at: datetime


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
class AuditLogRead(BaseModel):
    model_config = ORM_CONFIG

    id: int
    action: str
    user_id: int | None
    team_id: int | None
    secret_token: str | None
    ip_address: str | None
    detail: str | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------
class CleanupResult(BaseModel):
    expired_secrets_wiped: int
    old_rows_purged: int
    ran_at: datetime


class MessageResponse(BaseModel):
    """A plain {"detail": "..."} body, for endpoints with nothing to return."""

    detail: str
