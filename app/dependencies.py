"""
Shared FastAPI dependencies.

A "dependency" is just a function that FastAPI calls for you before your
endpoint runs. Whatever it returns gets passed in as an argument. If it
raises an HTTPException, your endpoint never runs at all.

That last property is what makes `get_current_user` useful: an endpoint
declaring `current_user: User = Depends(get_current_user)` cannot be reached
without a valid token. The authentication check is impossible to forget,
because it is part of the function signature.
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security import InvalidTokenError, decode_access_token

# This does two things:
#   1. It pulls the token out of the "Authorization: Bearer <token>" header.
#   2. tokenUrl tells Swagger UI where the login form lives, which is what
#      makes the "Authorize" button at /docs actually work.
# It does NOT validate the token -- that is our job below.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Per the spec, a 401 should say how to authenticate, hence the WWW-Authenticate
# header. Built once here so every auth failure looks identical.
def _credentials_error(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Turn an "Authorization: Bearer ..." header into a User row.

    Note the chain: this dependency itself depends on two others. FastAPI
    resolves the whole tree for you, and caches each one per request, so
    asking for `get_db` here and in the endpoint gives you the SAME session.

    Why re-query the database when the user id is already in the token?
    Because the token is a snapshot from up to an hour ago. The account may
    have been deactivated, or moved to a different team, since it was issued.
    The database is the source of truth; the token only says who is asking.
    """
    try:
        user_id = decode_access_token(token)
    except InvalidTokenError:
        # Deliberately vague: we do not tell the caller whether the token was
        # expired, forged, or just gibberish.
        raise _credentials_error()

    user = db.get(User, user_id)  # db.get() is a primary-key lookup
    if user is None:
        # The token is validly signed but the user is gone (deleted account).
        raise _credentials_error()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is deactivated",
        )

    return user


def get_client_ip(request: Request) -> str:
    """
    Best-effort client IP, used for rate limiting and the audit log.

    On Render (and behind any reverse proxy) request.client.host is the
    PROXY's address, not the user's -- every request would look like it came
    from one IP. The real address is in the X-Forwarded-For header, as a
    comma-separated chain where the first entry is the original client.

    Security caveat, and this matters: X-Forwarded-For is set by the client
    and can be forged. Trusting it means a determined attacker can rotate the
    header to dodge the rate limit. It is safe to trust only because Render
    overwrites the header at its edge. If you ever run this without a proxy in
    front, drop this branch and use request.client.host alone.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first_hop = forwarded_for.split(",")[0].strip()
        if first_hop:
            return first_hop

    if request.client is not None:
        return request.client.host

    return "unknown"
