"""
Application settings.

Everything configurable lives here in one place, and every value comes from an
environment variable (or from the .env file, which pydantic-settings reads
automatically). Nothing in the rest of the code calls os.environ directly --
it all goes through the single `settings` object at the bottom of this file.

Why a class instead of plain os.environ calls?
  * Pydantic validates and converts the types for us (a port becomes an int,
    a comma-free string stays a string), and it fails loudly at startup if a
    required variable is missing -- which is much better than failing at 3am
    on the first request that happens to need it.
"""

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # `env_file=".env"` means: if a file called .env sits next to the project
    # root, load the variables from it. Real environment variables (the ones
    # Render sets for you in production) always win over the file.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Database ----------------------------------------------------------
    # A SQLAlchemy connection URL, e.g.
    #   postgresql+psycopg2://secretshare:secretshare@localhost:5432/secretshare
    # The "+psycopg2" part tells SQLAlchemy which driver to use.
    database_url: str = (
        "postgresql+psycopg2://secretshare:secretshare@localhost:5432/secretshare"
    )

    # -- JWT ---------------------------------------------------------------
    # The key used to SIGN the login tokens. If this leaks, anyone can mint a
    # token for any user, so it must be long and random in production.
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # -- Fernet encryption -------------------------------------------------
    # The key used to ENCRYPT the secret payloads before they are written to
    # the database. This is a different key from jwt_secret_key on purpose:
    # they protect different things, and one leaking should not compromise the
    # other. Generate one with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    secret_encryption_key: str = ""

    # -- Secrets behaviour -------------------------------------------------
    default_ttl_minutes: int = 60          # used when the caller does not pass one
    max_ttl_minutes: int = 60 * 24 * 7     # one week -- the hard upper bound
    max_secret_length: int = 10_000        # characters of plaintext

    # -- Rate limiting (per client IP, on secret creation) -----------------
    rate_limit_max_requests: int = 10
    rate_limit_window_seconds: int = 60

    # -- Maintenance -------------------------------------------------------
    # The cleanup endpoint is called by a cron job / uptime pinger, not by a
    # logged-in user, so it is protected by this shared token instead of a JWT.
    cleanup_token: str = "change-me-too"

    # -- Misc --------------------------------------------------------------
    # Used to build the shareable link that is returned when a secret is made.
    public_base_url: str = "http://localhost:8000"
    app_name: str = "One-Time Secret Sharing Service"

    @field_validator("database_url")
    @classmethod
    def normalise_database_url(cls, url: str) -> str:
        """
        Accept the connection URL in whichever form the host hands it to us.

        This exists because of a specific, very common deployment failure.
        Render (and Heroku) give you a database URL starting with the legacy
        `postgres://` scheme:

            postgres://user:password@host:5432/dbname

        SQLAlchemy 2.0 does not recognise `postgres://` as a dialect and
        refuses to start:

            NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres

        So a blueprint that wires DATABASE_URL straight from the managed
        database would crash the app on boot. Rather than making that a manual
        step you have to remember, we normalise it here:

            postgres://...              ->  postgresql+psycopg2://...
            postgresql://...            ->  postgresql+psycopg2://...
            postgresql+psycopg2://...   ->  unchanged
            sqlite://...                ->  unchanged

        Naming the driver explicitly also stops SQLAlchemy from guessing a
        default that might differ between versions.
        """
        if url.startswith("postgres://"):
            return "postgresql+psycopg2://" + url[len("postgres://") :]

        # Already a postgresql URL, but with no driver named after the "+".
        if url.startswith("postgresql://"):
            return "postgresql+psycopg2://" + url[len("postgresql://") :]

        return url

    @field_validator(
        "public_base_url", "cleanup_token", "jwt_secret_key", "database_url"
    )
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        """
        Strip surrounding whitespace from values that get pasted by hand.

        This is not defensive programming for its own sake -- it fixes a real
        bug we hit on the first deploy. Render's dashboard renders environment
        variable values as a multi-line text box, so pasting a URL into it
        captures a trailing newline. That produced share links like:

            https://your-app.onrender.com\n/s/abc123

        which are broken, and in a way that is genuinely hard to spot because
        the newline is invisible in most output.

        The same hazard applies to CLEANUP_TOKEN (a stray newline would make
        every cleanup call 401) and to DATABASE_URL (a newline would make the
        host unresolvable). Cheaper to strip once here than to debug later.
        """
        return value.strip()

    @field_validator("public_base_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        """
        Normalise the base URL so links are built consistently.

        Both "https://x.com" and "https://x.com/" must produce
        "https://x.com/s/token", never "https://x.com//s/token".
        """
        return value.rstrip("/")


@lru_cache
def get_settings() -> Settings:
    """
    Build the Settings object once and reuse it.

    lru_cache turns this into a singleton: the .env file is read on the first
    call, and every later call gets the same object back. Tests can call
    get_settings.cache_clear() to force a reload after changing the environment.
    """
    return Settings()


# Importing this module gives you a ready-to-use settings object.
settings = get_settings()
