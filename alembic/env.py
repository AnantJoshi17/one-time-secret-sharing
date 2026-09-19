"""
Alembic's entry point. It runs this file for every `alembic` command.

What Alembic is, in one paragraph: your models change over time (you add a
column, you rename a table), but the database already has data in it and
cannot just be dropped and recreated. Alembic keeps an ordered list of
migration scripts, each describing one change and how to undo it, plus a table
called `alembic_version` in your database recording which one it is currently
at. `alembic upgrade head` runs whichever scripts are missing, in order.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Importing the settings gives us the database URL from the environment.
from app.config import settings

# Importing Base gives us the table definitions... but ONLY if the model
# classes have actually been imported, because a class registers itself on
# Base.metadata when Python executes its `class` statement. Importing
# app.models is therefore not an unused import -- without it, autogenerate
# would see an empty schema and cheerfully write a migration that drops every
# table you have.
from app.database import Base
from app.models import AuditLog, Secret, Team, User  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the URL from our settings, overriding the (absent) one in alembic.ini.
config.set_main_option("sqlalchemy.url", settings.database_url)

# This is what `--autogenerate` compares the live database against.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Generate SQL without connecting to a database ("offline" mode).

    `alembic upgrade head --sql` prints the statements instead of running
    them, which is how you hand a migration to a DBA for review.
    """
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect to the database and run the migrations against it."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # one short-lived connection; no pool needed
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # compare_type tells autogenerate to notice when a column's TYPE
            # changed (String(50) -> String(100)), not just when columns are
            # added or removed. Off by default, and surprising when it bites.
            compare_type=True,
            # SQLite cannot ALTER most things, so Alembic emulates it by
            # building a new table and copying rows. Harmless on PostgreSQL,
            # necessary if you run the test suite on SQLite.
            render_as_batch=settings.database_url.startswith("sqlite"),
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
