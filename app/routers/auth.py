"""
Registration and login.

Three endpoints:
    POST /auth/register  -- create an account
    POST /auth/login     -- exchange email + password for a JWT
    GET  /auth/me        -- who am I? (proves the token works)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import (
    ACTION_USER_LOGIN,
    ACTION_USER_LOGIN_FAILED,
    ACTION_USER_REGISTER,
    record_audit,
)
from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_user
from app.models import User
from app.schemas import LoginResponse, UserCreate, UserRead
from app.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserCreate,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
) -> User:
    """
    Create a new account.

    Emails are normalised to lowercase so Bob@x.com and bob@x.com are the same
    account. Without this, the UNIQUE constraint treats them as different and
    you get two accounts for one person.
    """
    email = payload.email.lower().strip()

    user = User(
        email=email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    record_audit(db, action=ACTION_USER_REGISTER, user_id=None, ip_address=client_ip,
                 detail=f"email={email}")

    try:
        db.commit()
    except IntegrityError:
        # The UNIQUE constraint on users.email rejected this insert, meaning
        # the address is already registered.
        #
        # We rely on the database to tell us this rather than doing a SELECT
        # first, because between a "does it exist?" SELECT and our INSERT
        # another request can register the same address. The constraint is the
        # only check that cannot be raced.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    db.refresh(user)  # reload so server-generated columns (id, created_at) are populated
    return user


@router.post("/login", response_model=LoginResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
) -> LoginResponse:
    """
    Exchange credentials for an access token.

    This takes a FORM body, not JSON, and the email goes in a field called
    `username`. That is the OAuth2 password-flow spec, and following it is
    what makes the Authorize button in /docs work. Call it with:

        curl -X POST localhost:8000/auth/login \
             -d "username=bob@example.com&password=hunter2"
    """
    email = form_data.username.lower().strip()

    user = db.scalar(select(User).where(User.email == email))

    # Check the user exists AND the password matches in one branch, and return
    # the same message either way.
    #
    # If we said "no such account" for a bad email and "wrong password" for a
    # bad password, anyone could use this endpoint to discover which email
    # addresses have accounts here. That is called user enumeration.
    if user is None or not verify_password(form_data.password, user.hashed_password):
        record_audit(
            db,
            action=ACTION_USER_LOGIN_FAILED,
            user_id=user.id if user else None,
            ip_address=client_ip,
            detail=f"email={email}",
        )
        db.commit()  # the failed attempt is itself worth recording
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is deactivated",
        )

    record_audit(db, action=ACTION_USER_LOGIN, user=user, ip_address=client_ip)
    db.commit()

    return LoginResponse(
        access_token=create_access_token(user.id),
        token_type="bearer",
        expires_in_minutes=settings.access_token_expire_minutes,
    )


@router.get("/me", response_model=UserRead)
def read_current_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Return the logged-in user.

    The entire auth check is the `Depends(get_current_user)` in the signature.
    There is no `if token is None` anywhere in this function, because the
    request cannot reach the body without a valid token.
    """
    return current_user
