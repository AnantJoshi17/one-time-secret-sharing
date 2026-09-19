"""
Housekeeping.

    GET  /health               liveness check (used by Render)
    POST /maintenance/cleanup  wipe expired secrets

WHY IS THERE A CLEANUP ENDPOINT IF EXPIRY IS ALREADY ENFORCED ON READ?

Because the two do different jobs, and you want both.

  Lazy expiry (the `expires_at > now` clause in the atomic UPDATE) guarantees
  CORRECTNESS: an expired secret can never be revealed, whatever else happens.
  It is the guarantee that matters, and it needs no background process.

  But lazy expiry alone never *deletes* anything. A secret that expires and is
  simply never visited again keeps its ciphertext in the table forever. That
  is a data-retention problem: "we destroy your secret after an hour" should
  mean the bytes are gone, not merely unreachable through the API.

So cleanup is the sweeper. It is a plain HTTP endpoint rather than a Celery
beat task or a cron container, because the brief rules out background workers
and because this way any free uptime pinger can drive it:

    curl -X POST https://your-app.onrender.com/maintenance/cleanup \
         -H "X-Cleanup-Token: ..."

It is safe to call at any frequency, including never -- calling it twice in a
row simply finds nothing to do the second time (it is idempotent).
"""

import hmac
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.audit import ACTION_CLEANUP, record_audit
from app.config import settings
from app.database import get_db
from app.models import Secret
from app.schemas import CleanupResult, MessageResponse
from app.timeutil import utc_now

router = APIRouter(tags=["maintenance"])


def verify_cleanup_token(
    x_cleanup_token: str | None = Header(default=None),
) -> None:
    """
    Guard the cleanup endpoint with a shared token instead of a JWT.

    A JWT would be wrong here: the caller is a cron job or an uptime pinger,
    not a person, and it has no account. A fixed header token is the right
    shape for machine-to-machine calls like this.
    """
    expected = settings.cleanup_token

    # hmac.compare_digest instead of `==` so the comparison takes the same
    # time whatever the input. A plain == returns early on the first wrong
    # character, and that timing difference is enough to guess the token one
    # character at a time.
    if not x_cleanup_token or not hmac.compare_digest(x_cleanup_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Cleanup-Token header",
        )


@router.get("/health", response_model=MessageResponse, tags=["health"])
def health() -> MessageResponse:
    """
    Liveness check.

    Deliberately does NOT touch the database. Render pings this to decide
    whether the process is alive; if it ran a query, a slow database would get
    the whole service restarted, turning a small problem into an outage.
    """
    return MessageResponse(detail="ok")


@router.post(
    "/maintenance/cleanup",
    response_model=CleanupResult,
    dependencies=[Depends(verify_cleanup_token)],
)
def cleanup_expired_secrets(
    db: Session = Depends(get_db),
    purge_after_days: int = Query(
        default=30,
        ge=1,
        description="Delete rows whose expiry is older than this many days.",
    ),
) -> CleanupResult:
    """
    Two-stage cleanup.

    Stage 1 -- WIPE (immediately at expiry): set ciphertext to NULL on every
      expired secret that still has one. This is the part that matters, and it
      happens as soon as the secret expires. The row survives, so a reader
      arriving late still gets an honest "this expired" rather than "no such
      link", and the audit trail still has a row to point at.

    Stage 2 -- PURGE (much later): delete rows that expired more than
      `purge_after_days` ago. By then nobody is still clicking that link, and
      keeping metadata forever would grow the table without limit. The
      audit_logs rows survive this, because they store the token as a plain
      string rather than a foreign key -- see models.py.
    """
    now = utc_now()

    # -- Stage 1: wipe the ciphertext of expired secrets --------------------
    wipe = (
        update(Secret)
        .where(
            Secret.expires_at <= now,
            # Only rows that still hold data. Without this the statement would
            # rewrite every expired row on every run, for no reason.
            Secret.ciphertext.is_not(None),
        )
        .values(ciphertext=None)
        .execution_options(synchronize_session=False)
    )
    wiped_count = db.execute(wipe).rowcount

    # -- Stage 2: purge long-expired rows -----------------------------------
    purge_before = now - timedelta(days=purge_after_days)
    purge = (
        delete(Secret)
        .where(Secret.expires_at <= purge_before)
        .execution_options(synchronize_session=False)
    )
    purged_count = db.execute(purge).rowcount

    record_audit(
        db,
        action=ACTION_CLEANUP,
        detail=f"wiped={wiped_count} purged={purged_count}",
    )
    db.commit()

    return CleanupResult(
        expired_secrets_wiped=wiped_count,
        old_rows_purged=purged_count,
        ran_at=now,
    )
