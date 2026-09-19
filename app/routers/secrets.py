"""
Creating, inspecting and revealing secrets.

    POST /secrets                  create a secret, get a shareable link
    GET  /secrets                  list secrets you can see (metadata only)
    GET  /secrets/{token}          is this link still good? (does NOT consume it)
    POST /secrets/{token}/reveal   consume the link -- returns the plaintext once

WHY IS REVEALING A POST AND NOT A GET?

Because GET must be safe: fetching a URL is not allowed to change anything.
That is not pedantry, it is a real bug waiting to happen. Browsers, chat apps
(Slack and WhatsApp unfurl links you paste), antivirus scanners and mail
gateways all follow GET links automatically. If GET /secrets/{token} consumed
the secret, pasting your link into Slack would destroy it before the intended
reader ever clicked.

So the two are split: GET tells you whether the link is still valid, and an
explicit POST -- which no link-preview bot will ever send -- consumes it.
"""

import secrets as secrets_module  # stdlib `secrets`; aliased so it does not
                                  # shadow this module's own name
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.audit import (
    ACTION_SECRET_CREATE,
    ACTION_SECRET_REVEAL,
    ACTION_SECRET_REVEAL_DENIED,
    ACTION_SECRET_REVEAL_MISSED,
    record_audit,
)
from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_user
from app.encryption import DecryptionError, decrypt, encrypt
from app.models import Secret, User
from app.rate_limit import rate_limit_secret_creation
from app.schemas import SecretCreate, SecretCreated, SecretMetadata, SecretRevealed
from app.timeutil import ensure_utc, utc_now

router = APIRouter(prefix="/secrets", tags=["secrets"])

# 32 bytes -> a 43-character url-safe string. Guessing one is not feasible.
TOKEN_BYTES = 32


def _new_token() -> str:
    """
    Generate the unguessable part of the share link.

    `secrets.token_urlsafe` uses the operating system's cryptographic random
    source. Do NOT use `random` here -- it is a deterministic PRNG, and
    someone who sees a few of its outputs can predict the rest.
    """
    return secrets_module.token_urlsafe(TOKEN_BYTES)


def _user_can_access(user: User, secret: Secret) -> bool:
    """
    The whole access policy, in one place.

    A user may touch a secret if they created it, or if the secret was created
    inside the team they are currently in.

    `secret.team_id is not None` matters: without it, a user with no team
    (team_id = None) would match every secret created by another teamless
    user, because None == None.
    """
    if secret.creator_id == user.id:
        return True

    if secret.team_id is not None and secret.team_id == user.team_id:
        return True

    return False


def _to_metadata(secret: Secret) -> SecretMetadata:
    """Build the public metadata view, adding the two computed fields."""
    expires_at = ensure_utc(secret.expires_at)
    is_expired = expires_at <= utc_now()

    return SecretMetadata(
        token=secret.token,
        label=secret.label,
        creator_id=secret.creator_id,
        team_id=secret.team_id,
        created_at=ensure_utc(secret.created_at),
        expires_at=expires_at,
        viewed=secret.viewed,
        viewed_at=ensure_utc(secret.viewed_at),
        viewed_by_id=secret.viewed_by_id,
        is_expired=is_expired,
        # "Would a reveal right now succeed?" -- the same condition the atomic
        # UPDATE below enforces, which is why it is computed from the same two
        # facts rather than tracked as its own column.
        is_available=(not secret.viewed) and (not is_expired),
    )


@router.post(
    "",
    response_model=SecretCreated,
    status_code=status.HTTP_201_CREATED,
    # This dependency is the rate limiter. It returns nothing; it is here to
    # raise 429 before the endpoint body runs. Creation is the expensive,
    # abusable operation (it writes rows), so it is the one we limit.
    dependencies=[Depends(rate_limit_secret_creation)],
)
def create_secret(
    payload: SecretCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    client_ip: str = Depends(get_client_ip),
) -> SecretCreated:
    """Encrypt a value and return a one-time link for it."""
    # Validate the TTL against the configured ceiling. Pydantic already
    # guaranteed it is >= 1 if present; the maximum depends on settings, which
    # Pydantic cannot see, so it is checked here.
    ttl_minutes = payload.ttl_minutes or settings.default_ttl_minutes
    if ttl_minutes > settings.max_ttl_minutes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"ttl_minutes must be at most {settings.max_ttl_minutes}",
        )

    now = utc_now()

    secret = Secret(
        token=_new_token(),
        # The plaintext is encrypted HERE, before the object is ever handed to
        # the session. It never exists in a column, a log line or a query.
        ciphertext=encrypt(payload.plaintext),
        label=payload.label,
        creator_id=current_user.id,
        # Frozen at creation -- see the comment on Secret.team_id in models.py.
        team_id=current_user.team_id,
        created_at=now,
        expires_at=now + timedelta(minutes=ttl_minutes),
        viewed=False,
    )
    db.add(secret)

    record_audit(
        db,
        action=ACTION_SECRET_CREATE,
        user=current_user,
        secret_token=secret.token,
        ip_address=client_ip,
        detail=f"ttl_minutes={ttl_minutes}",
    )

    # One commit writes the secret and its audit row together.
    db.commit()
    db.refresh(secret)

    return SecretCreated(
        token=secret.token,
        # Points at the browser landing page (/s/<token>), not at the API
        # path. Opening it runs a safe GET that only shows metadata; the
        # secret is consumed only when the reader presses the button there.
        #
        # public_base_url is already stripped of whitespace and any trailing
        # slash by the Settings validators, so this is a plain join.
        share_url=f"{settings.public_base_url}/s/{secret.token}",
        label=secret.label,
        expires_at=ensure_utc(secret.expires_at),
        team_id=secret.team_id,
    )


@router.get("", response_model=list[SecretMetadata])
def list_secrets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[SecretMetadata]:
    """
    List the secrets you are allowed to see: your own, plus your team's.

    Metadata only -- no ciphertext and certainly no plaintext. Listing a
    secret must never be a way to read it; reading only happens at /reveal.

    This is the SQL equivalent of _user_can_access(), which is a real
    duplication: the rule now lives in two places and they must be kept in
    step. The alternative -- fetching every row and filtering in Python --
    does not scale, so the duplication is the lesser evil. The two are pinned
    together by a test (test_teams.py).
    """
    conditions = [Secret.creator_id == current_user.id]
    if current_user.team_id is not None:
        conditions.append(Secret.team_id == current_user.team_id)

    stmt = (
        select(Secret)
        .where(or_(*conditions))
        .order_by(Secret.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    return [_to_metadata(row) for row in db.scalars(stmt).all()]


@router.get("/{token}", response_model=SecretMetadata)
def get_secret_metadata(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SecretMetadata:
    """
    Check whether a link is still usable. This does NOT consume it.

    Safe to call as many times as you like -- see the module docstring for why
    that matters.
    """
    secret = db.scalar(select(Secret).where(Secret.token == token))

    # Unknown token and forbidden token both return 404, on purpose.
    #
    # A 403 would confirm "this token exists, you just cannot have it", which
    # tells an attacker their guess was correct. Since the token is the only
    # thing protecting the secret, never confirm that one is real.
    if secret is None or not _user_can_access(current_user, secret):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found"
        )

    return _to_metadata(secret)


@router.post("/{token}/reveal", response_model=SecretRevealed)
def reveal_secret(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    client_ip: str = Depends(get_client_ip),
) -> SecretRevealed:
    """
    Consume the link: return the plaintext exactly once, then destroy it.

    ======================================================================
    THE ATOMIC UPDATE -- the heart of this project. Read this bit carefully.
    ======================================================================

    The obvious implementation is wrong:

        secret = db.query(Secret).filter_by(token=token).first()   # (1) read
        if secret.viewed:                                          # (2) check
            raise HTTPException(410)
        secret.viewed = True                                       # (3) write
        db.commit()
        return decrypt(secret.ciphertext)

    That is a check-then-act race, also called TOCTOU (time of check to time
    of use). Two requests can interleave like this:

        request A: (1) reads viewed=False
        request B: (1) reads viewed=False        <-- B read before A wrote
        request A: (2) passes the check
        request B: (2) passes the check          <-- still sees the stale False
        request A: (3) sets viewed=True, commits
        request B: (3) sets viewed=True, commits
        --> BOTH callers receive the plaintext.

    The window between (1) and (3) is small, but "small" is not "zero", and
    the entire product promise is that it is zero. It is also exactly the
    window an attacker widens on purpose by firing simultaneous requests.

    The fix is to make the check and the write THE SAME STATEMENT, so the
    database -- not our Python -- decides the winner:

        UPDATE secrets
           SET viewed = true, viewed_at = ..., viewed_by_id = ...
         WHERE token = :token
           AND viewed = false          <-- the check, now inside the write
           AND expires_at > :now
        RETURNING ciphertext, label;

    A single UPDATE statement holds a row lock for its whole duration, so the
    two requests can no longer interleave. In PostgreSQL's default READ
    COMMITTED isolation:

        - A and B both aim at the same row.
        - A takes the row lock and updates it.
        - B BLOCKS on the lock -- it cannot proceed.
        - A commits, releasing the lock.
        - B wakes up and RE-EVALUATES its WHERE clause against the row as it
          is NOW (this is Postgres's EvalPlanQual behaviour). It sees
          viewed = true, so `AND viewed = false` no longer matches.
        - B's UPDATE affects 0 rows and RETURNING gives back nothing.

    So whoever loses gets an empty result and we answer 410 Gone. There is no
    window, at any load, on any number of workers, because the guarantee comes
    from the database rather than from our process.

    RETURNING is the other half of the trick. Without it we would have to
    SELECT the ciphertext in a second statement -- and then we would be back
    to two statements, needing a transaction to tie them together. RETURNING
    hands us the row we just claimed, in the same round trip.
    ======================================================================
    """
    now = utc_now()

    # ------------------------------------------------------------------
    # Step 1: the ACCESS check (who is allowed to ask).
    #
    # This is separate from the atomic claim below, and the order matters: a
    # user who is not allowed to read this secret must not be able to burn it
    # for the person who is. So we check permission first and only then claim.
    # ------------------------------------------------------------------
    secret = db.scalar(select(Secret).where(Secret.token == token))

    if secret is None:
        record_audit(
            db,
            action=ACTION_SECRET_REVEAL_MISSED,
            user=current_user,
            secret_token=token,
            ip_address=client_ip,
            detail="no such token",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found"
        )

    if not _user_can_access(current_user, secret):
        record_audit(
            db,
            action=ACTION_SECRET_REVEAL_DENIED,
            user=current_user,
            secret_token=token,
            ip_address=client_ip,
            detail="not creator and not in owning team",
        )
        db.commit()
        # 404 rather than 403, for the reason given in get_secret_metadata.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found"
        )

    # ------------------------------------------------------------------
    # Step 2: the atomic claim. Everything above is about permission; this
    # single statement is what makes the read happen exactly once.
    # ------------------------------------------------------------------
    claim = (
        update(Secret)
        .where(
            Secret.token == token,
            # The single-read guard.
            Secret.viewed.is_(False),
            # Lazy expiry: an expired secret simply fails to match, so it can
            # never be revealed even though its row is still sitting there.
            # Expiry is enforced on the read path, not by a background job.
            Secret.expires_at > now,
        )
        .values(viewed=True, viewed_at=now, viewed_by_id=current_user.id)
        # RETURNING gives back the values AFTER the update. We are not
        # touching `ciphertext` in this statement, so what comes back is the
        # real ciphertext -- which is precisely why the wipe is a separate
        # statement further down rather than being merged into this one.
        .returning(Secret.ciphertext, Secret.label)
        # synchronize_session=False tells the ORM not to try to work out which
        # in-memory objects this bulk UPDATE invalidated. We handle that
        # ourselves with db.expire() below, and it avoids an extra query.
        .execution_options(synchronize_session=False)
    )

    claimed_row = db.execute(claim).first()

    # ------------------------------------------------------------------
    # Step 3a: we lost (or it was already used / expired). Work out which, so
    # the caller gets a useful message.
    # ------------------------------------------------------------------
    if claimed_row is None:
        # The in-memory `secret` object is stale -- another transaction may
        # have flipped `viewed` since we loaded it. expire() throws away the
        # cached column values so the next attribute access re-reads the row.
        db.expire(secret)

        if ensure_utc(secret.expires_at) <= now:
            detail = "This secret has expired"
            audit_detail = "expired"
        else:
            detail = "This secret has already been viewed and no longer exists"
            audit_detail = "already viewed"

        record_audit(
            db,
            action=ACTION_SECRET_REVEAL_MISSED,
            user=current_user,
            secret_token=token,
            ip_address=client_ip,
            detail=audit_detail,
        )
        db.commit()

        # 410 Gone, not 404: the resource genuinely existed and is now
        # permanently unavailable. The caller is allowed to know that, because
        # they already proved they had access to it.
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=detail)

    # ------------------------------------------------------------------
    # Step 3b: we won. We now hold the only copy of this ciphertext.
    # ------------------------------------------------------------------
    ciphertext, label = claimed_row

    if ciphertext is None:
        # Should not happen -- a claimable row always has ciphertext -- but if
        # it ever did we would rather return a clear error than crash on None.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This secret has already been destroyed",
        )

    # Decrypt BEFORE wiping and committing, deliberately.
    #
    # If the encryption key has changed, decryption fails. Rolling back here
    # means the row keeps viewed=False and its ciphertext, so the secret is
    # not lost to a configuration mistake -- fix the key and it works again.
    # Wiping first and then failing would destroy it for nothing.
    try:
        plaintext = decrypt(ciphertext)
    except DecryptionError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    # Now destroy the ciphertext. This is the "and then it is gone" half of the
    # promise: after this commit, the plaintext exists only in the HTTP
    # response we are about to send.
    db.execute(
        update(Secret)
        .where(Secret.token == token)
        .values(ciphertext=None)
        .execution_options(synchronize_session=False)
    )

    record_audit(
        db,
        action=ACTION_SECRET_REVEAL,
        user=current_user,
        secret_token=token,
        ip_address=client_ip,
        detail=f"created_by={secret.creator_id}",
    )

    # One commit makes the claim, the wipe and the audit entry permanent
    # together. If the process died before this line, the transaction would
    # roll back and the secret would still be readable -- which is the safe
    # failure direction.
    db.commit()

    return SecretRevealed(
        token=token,
        plaintext=plaintext,
        label=label,
        revealed_at=now,
    )
