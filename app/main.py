"""
The FastAPI application: wires the routers together and starts up.

Run it locally with:
    uvicorn app.main:app --reload

Then open http://localhost:8000/docs for interactive API documentation that
FastAPI generates from the type hints and Pydantic schemas -- you can register,
log in with the Authorize button, and create a secret without writing a line
of client code.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.encryption import EncryptionKeyMissingError, get_cipher
from app.routers import audit, auth, maintenance, secrets, teams

# The browser frontend: three static files (index.html, reveal.html, api.js,
# style.css) served by this same application. Resolved relative to THIS file
# rather than the working directory, so the app runs correctly whatever
# directory uvicorn was started from.
STATIC_DIR = Path(__file__).parent / "static"

logger = logging.getLogger("secretshare")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown hooks.

    Everything before `yield` runs once when the process starts; everything
    after runs once as it stops.

    We build the Fernet cipher here on purpose. It is a FAIL-FAST check: if
    SECRET_ENCRYPTION_KEY is missing or malformed, the app refuses to start,
    with a message telling you how to generate one. The alternative -- finding
    out on the first POST /secrets in production -- is much worse, because by
    then the service is live and taking traffic it cannot serve.
    """
    try:
        get_cipher()
    except EncryptionKeyMissingError as exc:
        # Re-raise as RuntimeError so uvicorn prints it and exits non-zero.
        raise RuntimeError(f"Cannot start: {exc}") from exc

    if settings.jwt_secret_key == "change-me-in-production":
        logger.warning(
            "JWT_SECRET_KEY is still the default value. Anyone who reads this "
            "source can forge login tokens. Set a real one before deploying."
        )

    logger.info("%s started", settings.app_name)
    yield
    logger.info("%s shutting down", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "Share a secret through a link that works exactly once.\n\n"
        "Secrets are encrypted at rest with Fernet, destroyed on first read "
        "via an atomic conditional UPDATE, and expire after a TTL.\n\n"
        "**Getting started:** register, then log in with the *Authorize* "
        "button above, then try `POST /secrets`."
    ),
)

# Order here is only cosmetic -- it sets the order of the sections in /docs.
app.include_router(auth.router)
app.include_router(teams.router)
app.include_router(secrets.router)
app.include_router(audit.router)
app.include_router(maintenance.router)


# Serve /static/style.css, /static/api.js and so on. Mounted rather than
# routed, because StaticFiles handles content types, caching headers and 404s
# for a whole directory in one line.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --------------------------------------------------------------------------
# The two HTML pages.
#
# include_in_schema=False keeps them out of /docs and out of openapi.json --
# they are pages for humans, not API endpoints, and listing them would clutter
# the generated API documentation.
# --------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def home_page() -> FileResponse:
    """The web UI: sign in, create a secret, manage your team."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/s/{token}", include_in_schema=False)
def reveal_page(token: str) -> FileResponse:
    """
    The landing page a share link points at.

    Note that this returns the SAME html for every token and never looks at
    the value -- the page reads the token out of the URL in the browser and
    calls the API itself.

    That is deliberate. Serving this page must not touch the secret at all, so
    that a browser prefetch, a Slack link preview or a mail scanner opening the
    URL cannot consume it. The only thing that consumes a secret is the POST
    to /secrets/{token}/reveal, which happens when a person clicks the button.
    """
    return FileResponse(STATIC_DIR / "reveal.html")
