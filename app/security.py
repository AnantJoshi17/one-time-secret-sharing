"""
Passwords and JWTs.

Two separate jobs live here, and it is worth being clear that they are
different, because they are easy to conflate when you are new to auth:

  1. PASSWORD HASHING (passlib + bcrypt)
     One-way. We turn "hunter2" into a hash and store the hash. There is no
     "un-hash" function. To check a login we hash the attempt and compare.

  2. TOKENS (PyJWT)
     Two-way but SIGNED, not encrypted. A JWT's contents are only base64 --
     anyone can read them. What the signature guarantees is that nobody
     *changed* them without our key. So never put anything private in a JWT.

--------------------------------------------------------------------------
THE JWT FLOW, END TO END
--------------------------------------------------------------------------
    1. POST /auth/login with email + password.
    2. We look the user up and call verify_password(). If it fails, 401.
    3. We call create_access_token(user.id) -> a long "aaa.bbb.ccc" string.
         aaa = header    (which algorithm)         base64
         bbb = payload   (sub = user id, exp)      base64
         ccc = signature (HMAC-SHA256 of aaa.bbb using our secret key)
    4. The client stores that string and sends it on every later request as
         Authorization: Bearer aaa.bbb.ccc
    5. get_current_user (app/dependencies.py) calls decode_access_token().
       PyJWT recomputes the signature with our key. If it does not match the
       one in the token, the token was forged or tampered with -> 401. It
       also checks `exp`, so expired tokens are rejected -> 401.
    6. We load that user id from the database and hand the User to the
       endpoint.

The important consequence: the server stores NO session state. Anyone holding
a valid token is authenticated, which is why tokens are short-lived and why
they must only ever travel over HTTPS.
"""

from datetime import timedelta

import jwt
from passlib.context import CryptContext

from app.config import settings
from app.timeutil import utc_now

# bcrypt is deliberately slow. That is the point: it makes brute-forcing a
# stolen password database expensive. passlib handles generating a random
# per-password salt and storing it inside the hash string for us, so two users
# with the same password still get different hashes.
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# bcrypt silently truncates anything past 72 BYTES. Rejecting long passwords
# up front is clearer than accepting them and only checking the first 72.
BCRYPT_MAX_BYTES = 72


def hash_password(plain_password: str) -> str:
    """Turn a plaintext password into a bcrypt hash safe to store."""
    return password_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Check a login attempt against a stored hash.

    passlib does the comparison in constant time, so an attacker cannot learn
    how much of the hash they got right by measuring how long we took.
    """
    try:
        return password_context.verify(plain_password, hashed_password)
    except ValueError:
        # Raised if the stored value is not a valid bcrypt hash at all (for
        # example a row hand-edited in psql). Treat it as a failed login
        # rather than letting a 500 leak that the row is malformed.
        return False


def create_access_token(user_id: int, expires_minutes: int | None = None) -> str:
    """
    Build a signed JWT identifying `user_id`.

    The registered claim names are not ours to choose -- they are from the JWT
    spec, and libraries treat them specially:
        sub ("subject")   who the token is about. Must be a string.
        exp ("expires")   a UNIX timestamp; PyJWT rejects the token past it.
        iat ("issued at") when we made it, useful for debugging.
    """
    if expires_minutes is None:
        expires_minutes = settings.access_token_expire_minutes

    issued_at = utc_now()
    payload = {
        "sub": str(user_id),  # the spec says `sub` is a string, so cast it
        "iat": issued_at,
        "exp": issued_at + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


class InvalidTokenError(Exception):
    """Raised when a token is missing, malformed, expired or badly signed."""


def decode_access_token(token: str) -> int:
    """
    Verify a JWT and return the user id inside it.

    Raises InvalidTokenError for every failure mode, so the caller has exactly
    one thing to catch. We deliberately do not tell the client *which* check
    failed -- "expired" vs "bad signature" is useful information to an attacker.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            # algorithms= is a whitelist, and it is a real security control,
            # not boilerplate. Without it, an attacker can hand us a token
            # whose header says alg="none" and PyJWT would skip verification.
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    subject = payload.get("sub")
    if subject is None:
        raise InvalidTokenError("token has no subject claim")

    try:
        return int(subject)
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError("token subject is not a user id") from exc
