# One-Time Secret Sharing Service

Share a password, API key or private note through a link that works **exactly
once**. After it is read, the secret is destroyed. Links also expire on a TTL.

Built with FastAPI, PostgreSQL, SQLAlchemy, Alembic and Pydantic.

---

## Contents

- [What it does](#what-it-does)
- [The web UI](#the-web-ui)
- [Architecture](#architecture)
- [The atomic single-read](#the-atomic-single-read-the-interesting-part)
- [Setup: PostgreSQL on macOS](#setup-1-postgresql-on-macos)
- [Setup: the application](#setup-2-the-application)
- [Setup: the first Alembic migration](#setup-3-the-first-alembic-migration)
- [Running the app](#setup-4-run-the-app)
- [Running the tests](#setup-5-run-the-tests)
- [API reference](#api-reference)
- [Deploying to Render](#deploying-to-render)
- [Design decisions](#design-decisions)
- [Known limitations](#known-limitations)

---

## What it does

1. You register and log in, in the browser or over the API, and get a JWT.
2. You create a secret. It is encrypted with Fernet and stored; you get back an
   unguessable token and a share link.
3. You send that link to a teammate. Opening it shows a landing page with a
   **Reveal** button — loading the page is harmless. Pressing the button gets
   them the plaintext, and in the same transaction the ciphertext is wiped from
   the database.
4. Anyone else who tries that link gets **410 Gone**.
5. If nobody reads it before `expires_at`, it can never be read at all.
6. Every create, read, failed read and denied read is written to an audit log.

---

## The web UI

The app serves a small browser frontend from the same process — no separate
deployment, no build step, no CORS to configure.

| Page | What it is |
|------|------------|
| `/` | Sign in, create a secret, manage your team, list what you can see. |
| `/s/{token}` | The landing page a share link points at: metadata, then a **Reveal** button. |
| `/docs` | Swagger UI, generated from the type hints. Still there, still useful. |

It is four static files in [`app/static/`](app/static/) — `index.html`,
`reveal.html`, `api.js`, `style.css` — served by `StaticFiles` and two
`FileResponse` routes in [`app/main.py`](app/main.py). Plain JavaScript, no
framework, deliberately: the interesting part of this project is the backend,
and a React build step would add a toolchain without adding anything to
demonstrate.

**The reveal page is where the GET/POST split pays off.** Loading `/s/{token}`
runs a safe `GET` that only reads metadata, so a browser prefetch, a Slack
unfurl or a mail scanner following the link does nothing. The destructive
`POST` fires only when a person presses the button. Pinned by
`test_loading_the_reveal_page_does_not_consume_the_secret`.

Note that the reveal page asks the reader to sign in first. That follows from
feature 5: the team access check has to know who is asking.

---

## Architecture

```
  Browser  ────────►  /  and  /s/{token}   (app/static/*.html)
                             │  calls the API below with fetch()
                             ▼
                      ┌──────────────────────────────────────────┐
   HTTP request  ───► │  FastAPI (app/main.py)                   │
                      │                                          │
                      │  Dependencies run BEFORE the endpoint:   │
                      │    get_db            -> a Session        │
                      │    get_current_user  -> a User (or 401)  │
                      │    rate_limit_*      -> 429 if too fast  │
                      └────────────────┬─────────────────────────┘
                                       │
                      ┌────────────────▼─────────────────────────┐
                      │  Routers                                 │
                      │    auth.py         register / login      │
                      │    teams.py        create / join         │
                      │    secrets.py      create / reveal  ◄──── the core
                      │    audit.py        read the history      │
                      │    maintenance.py  health / cleanup      │
                      └────────────────┬─────────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
     ┌────────▼────────┐    ┌──────────▼─────────┐   ┌──────────▼────────┐
     │ security.py     │    │ encryption.py      │   │ models.py         │
     │ bcrypt + JWT    │    │ Fernet encrypt /   │   │ SQLAlchemy ORM    │
     │                 │    │ decrypt            │   │ 4 tables          │
     └─────────────────┘    └────────────────────┘   └──────────┬────────┘
                                                                │
                                                     ┌──────────▼────────┐
                                                     │   PostgreSQL      │
                                                     │   (schema managed │
                                                     │    by Alembic)    │
                                                     └───────────────────┘
```

### The four tables

| Table        | What it holds                                                        |
|--------------|----------------------------------------------------------------------|
| `teams`      | A group of users, plus an `invite_code` for joining.                  |
| `users`      | Email, bcrypt hash, and an optional `team_id`.                        |
| `secrets`    | The Fernet ciphertext, the URL `token`, `expires_at`, and `viewed`.   |
| `audit_logs` | Append-only history: who did what, to which token, from which IP.     |

### Request lifecycle for a reveal

```
POST /secrets/{token}/reveal
  │
  ├─ get_current_user     decode the JWT, load the User       -> 401 if bad
  ├─ access check         creator, or same team?              -> 404 if not
  ├─ ATOMIC UPDATE        claim the row (see below)           -> 410 if lost
  ├─ decrypt              Fernet, before committing anything  -> 500 if key wrong
  ├─ wipe ciphertext      set it to NULL
  ├─ write audit row
  └─ COMMIT               claim + wipe + audit, all together
```

---

## The atomic single-read (the interesting part)

**This is the design decision the whole project exists to demonstrate.**

### The bug in the obvious implementation

```python
secret = db.query(Secret).filter_by(token=token).first()   # 1. read
if secret.viewed:                                          # 2. check
    raise HTTPException(410)
secret.viewed = True                                       # 3. write
db.commit()
return decrypt(secret.ciphertext)
```

This reads correctly and is wrong. Two simultaneous requests interleave:

| time | request A                   | request B                   |
|------|-----------------------------|-----------------------------|
| t1   | reads row, `viewed = False` |                             |
| t2   |                             | reads row, `viewed = False` |
| t3   | passes the `if` check       |                             |
| t4   |                             | passes the `if` check       |
| t5   | sets `viewed = True`, commits |                           |
| t6   |                             | sets `viewed = True`, commits |
| t7   | **returns the plaintext**   | **returns the plaintext**   |

Both callers got the secret. This is a *check-then-act* race, also called
TOCTOU (time of check to time of use). The window between step 1 and step 3
is milliseconds, but the product's entire promise is that the window is
**zero** — and an attacker widens it deliberately by firing parallel requests.

Wrapping the three statements in a transaction does **not** fix it under
PostgreSQL's default READ COMMITTED isolation: each statement still sees a
fresh snapshot, so B's `SELECT` happily reads the row A has not committed
changes to yet.

### The fix: put the check inside the write

```sql
UPDATE secrets
   SET viewed = true,
       viewed_at = :now,
       viewed_by_id = :user_id
 WHERE token = :token
   AND viewed = false        -- the check, now part of the write
   AND expires_at > :now     -- expiry enforced in the same breath
RETURNING ciphertext, label;
```

A single `UPDATE` statement holds a row lock for its entire duration, so the
two requests can no longer interleave. In READ COMMITTED:

1. A and B both target the same row.
2. A takes the row lock and updates it.
3. B **blocks** on that lock.
4. A commits and releases.
5. B wakes and **re-evaluates its `WHERE` clause against the current row**
   (PostgreSQL calls this EvalPlanQual). It now sees `viewed = true`, so
   `AND viewed = false` no longer matches.
6. B's `UPDATE` affects **0 rows**, and `RETURNING` gives back nothing.

Whoever loses gets an empty result, and the endpoint answers 410. There is no
window, at any level of concurrency, across any number of workers or servers,
because the guarantee comes from the database rather than from application code.

`RETURNING` is the second half of the trick: it hands back the row we just
claimed in the same round trip. Without it we would need a separate `SELECT`
— and we would be back to two statements needing coordination.

In the code: [`app/routers/secrets.py`](app/routers/secrets.py), function
`reveal_secret`, which carries this explanation as a comment.

Proved by two tests in
[`tests/test_secrets_single_read.py`](tests/test_secrets_single_read.py):

- `test_atomic_update_lets_only_one_of_two_stale_readers_win` — deterministic.
  Two sessions both read the row, both see `viewed = False`, both then run the
  claim. Exactly one gets a row back. This reproduces the precise interleaving
  that breaks the naive version.
- `test_concurrent_reveals_return_exactly_one_success` — eight threads released
  simultaneously by a barrier. Exactly one 200, seven 410s.

---

## Setup 1: PostgreSQL on macOS

```bash
# Install and start it. `brew services` keeps it running across reboots
# (use `brew services stop postgresql@16` if you would rather it did not).
brew install postgresql@16
brew services start postgresql@16

# Homebrew does not add this to your PATH automatically.
echo 'export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Check it is alive. This should print a version number.
psql --version
psql postgres -c "SELECT version();"
```

Two things that bite on macOS:

- **Until you add that PATH line**, `psql` is not on your PATH at all. You can
  always call it by its full path instead:
  `/opt/homebrew/opt/postgresql@16/bin/psql`.
- **If you use Anaconda**, its `pg_config` shadows Homebrew's, and Homebrew
  will warn you about it during install. It does not matter here, because
  `requirements.txt` pins `psycopg2-binary`, which ships pre-compiled and never
  runs `pg_config`. It would matter if you ever switched to plain `psycopg2`,
  which builds from source.

Create the database and a user for this project:

```bash
psql postgres <<'SQL'
CREATE USER secretshare WITH PASSWORD 'secretshare';
CREATE DATABASE secretshare OWNER secretshare;
CREATE DATABASE secretshare_test OWNER secretshare;
GRANT ALL PRIVILEGES ON DATABASE secretshare TO secretshare;
GRANT ALL PRIVILEGES ON DATABASE secretshare_test TO secretshare;
SQL
```

Confirm you can connect as that user:

```bash
psql "postgresql://secretshare:secretshare@localhost:5432/secretshare" -c "\dt"
```

`\dt` lists tables; it will say "Did not find any relations" until you have run
the migration, which is correct at this point.

**Useful psql commands** (you will want these in an interview):

| Command      | What it does                      |
|--------------|-----------------------------------|
| `\l`         | list databases                    |
| `\c dbname`  | connect to a database             |
| `\dt`        | list tables                       |
| `\d tablename` | describe a table's columns and indexes |
| `\q`         | quit                              |

---

## Setup 2: the application

```bash
cd "Secret Sharing Service"

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Create your `.env`:

```bash
cp .env.example .env
```

Then generate the two keys and paste them into `.env`:

```bash
# SECRET_ENCRYPTION_KEY  (must be a valid Fernet key -- any other string fails)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# JWT_SECRET_KEY and CLEANUP_TOKEN (any long random string)
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

> **The encryption key is not recoverable.** Change it and every secret already
> in the database becomes permanently unreadable. Back it up somewhere real if
> you ever store anything you care about.

### How SQLAlchemy connects to PostgreSQL

The chain is worth understanding, because it is the same in every project:

```
.env: DATABASE_URL=postgresql+psycopg2://secretshare:secretshare@localhost:5432/secretshare
                   └─dialect──┘ └─driver─┘  └─user─┘ └password┘ └──host──┘ └port┘ └──db───┘
        │
        ▼
app/config.py    pydantic-settings reads it into settings.database_url
        │
        ▼
app/database.py  create_engine(settings.database_url)  -> a connection pool
        │
        ▼
                 SessionLocal = sessionmaker(bind=engine)
        │
        ▼
app/database.py  get_db() yields one Session per request, closes it after
```

`create_engine` does **not** connect. It builds a lazy pool; the first real
connection opens when the first query runs.

---

## Setup 3: the first Alembic migration

The migration is already written, at
[`alembic/versions/0001_initial_schema.py`](alembic/versions/0001_initial_schema.py).
You just apply it:

```bash
alembic upgrade head
```

Verify:

```bash
psql "postgresql://secretshare:secretshare@localhost:5432/secretshare" -c "\dt"
```

You should now see `teams`, `users`, `secrets`, `audit_logs` and
`alembic_version`. That last table is Alembic's bookkeeping — one row, holding
the revision id the database is currently at.

### Alembic commands you will actually use

| Command | What it does |
|---------|--------------|
| `alembic upgrade head` | apply every migration not yet applied |
| `alembic current` | which revision is this database at? |
| `alembic history` | list all migrations in order |
| `alembic downgrade -1` | undo the most recent migration |
| `alembic revision --autogenerate -m "add x"` | write a new migration by diffing the models against the live database |
| `alembic check` | does the database match the models? |

**Always read an autogenerated migration before running it.** Autogenerate
diffs your models against the database and is good at additions, but it cannot
tell a rename from a drop-plus-add — so a column rename comes out as
"drop the old one, add a new empty one", which silently deletes your data.

---

## Setup 4: run the app

```bash
uvicorn app.main:app --reload
```

- API: http://localhost:8000
- **Interactive docs: http://localhost:8000/docs**

The `/docs` page is generated from the type hints and Pydantic schemas. You can
register, click **Authorize** to paste in a token, and create and reveal a
secret without writing any client code.

### A complete session with curl

```bash
BASE=http://localhost:8000

# 1. Register
curl -X POST $BASE/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"hunter2pass"}'

# 2. Log in. Note this is a FORM body and the email goes in `username` --
#    that is the OAuth2 spec, and it is what makes /docs Authorize work.
TOKEN=$(curl -s -X POST $BASE/auth/login \
  -d "username=alice@example.com&password=hunter2pass" \
  | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# 3. Create a secret
curl -X POST $BASE/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"db-password-s3cr3t","label":"prod db","ttl_minutes":30}'

# 4. Check the link without consuming it (safe to repeat)
curl $BASE/secrets/PASTE_TOKEN_HERE -H "Authorization: Bearer $TOKEN"

# 5. Reveal it -- returns the plaintext
curl -X POST $BASE/secrets/PASTE_TOKEN_HERE/reveal -H "Authorization: Bearer $TOKEN"

# 6. Reveal it again -- 410 Gone
curl -X POST $BASE/secrets/PASTE_TOKEN_HERE/reveal -H "Authorization: Bearer $TOKEN"
```

---

## Setup 5: run the tests

```bash
pytest
```

By default the suite runs against a local SQLite file, so it works before you
have PostgreSQL set up. **Run it against PostgreSQL too** — that is the real
target, and it is where the concurrency test exercises genuine row-level
locking. All 90 tests pass on both backends (verified on PostgreSQL 16.15):

```bash
TEST_DATABASE_URL="postgresql+psycopg2://secretshare:secretshare@localhost:5432/secretshare_test" pytest
```

```bash
pytest tests/test_secrets_single_read.py -v   # the single-read guarantees
pytest -k "concurrent" -v                     # just the race-condition test
```

90 tests across eight files:

| File | Covers |
|------|--------|
| `test_auth.py` | registration, hashing, login, JWT verification, forged and expired tokens |
| `test_secrets_single_read.py` | the exactly-once guarantee, including two race tests |
| `test_expiry.py` | TTL validation, lazy expiry, the cleanup sweeper |
| `test_teams.py` | team membership and every access-control rule |
| `test_rate_limit.py` | the sliding window, and that it is wired to the endpoint |
| `test_audit.py` | what gets logged, and that the log leaks nothing |
| `test_frontend.py` | the pages are served, and loading a share link never consumes it |
| `test_config.py` | env var normalisation: the `postgres://` rewrite, and stripping whitespace from pasted values |

---

## API reference

All endpoints except `/`, `/health` and `/maintenance/cleanup` require
`Authorization: Bearer <token>`.

### Auth

| Method | Path | Body | Returns |
|--------|------|------|---------|
| `POST` | `/auth/register` | `{email, password}` JSON | 201, the user |
| `POST` | `/auth/login` | `username`, `password` **form** | 200, `{access_token, token_type, expires_in_minutes}` |
| `GET` | `/auth/me` | — | 200, the current user |

### Teams

| Method | Path | Body | Returns |
|--------|------|------|---------|
| `POST` | `/teams` | `{name}` | 201, the team + invite code |
| `POST` | `/teams/join` | `{invite_code}` | 200, the team |
| `GET` | `/teams/me` | — | 200, your team + members |
| `POST` | `/teams/leave` | — | 200 |

### Secrets

| Method | Path | Body | Returns |
|--------|------|------|---------|
| `POST` | `/secrets` | `{plaintext, label?, ttl_minutes?}` | 201, `{token, share_url, expires_at}`. `share_url` is `/s/{token}`, the browser page. |
| `GET` | `/secrets` | — | 200, metadata for your + your team's secrets |
| `GET` | `/secrets/{token}` | — | 200, metadata. **Does not consume.** |
| `POST` | `/secrets/{token}/reveal` | — | 200 with the plaintext, **once** |

### Pages (HTML, not part of the OpenAPI schema)

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/` | the web UI |
| `GET` | `/s/{token}` | the reveal landing page. Serving it **never touches the database**. |

### Audit and maintenance

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/audit` | filters: `action`, `secret_token`, `limit`, `offset` |
| `GET` | `/health` | public; does not touch the database |
| `POST` | `/maintenance/cleanup` | needs the `X-Cleanup-Token` header |

### Status codes

| Code | Meaning here |
|------|--------------|
| 401 | missing, expired, forged or invalid token |
| 403 | valid token, deactivated account |
| 404 | no such secret — **or** you are not allowed to see it (deliberately indistinguishable) |
| 409 | duplicate email, or already in a team |
| 410 | the secret existed and is gone: already read, or expired |
| 422 | the body failed validation |
| 429 | rate limit exceeded; see the `Retry-After` header |

---

## Deploying to Render

### Option A — the blueprint (recommended)

[`render.yaml`](render.yaml) describes the web service and the database.

1. Push this repository to GitHub.
2. In Render: **New → Blueprint**, pick the repo.
3. Render creates the database and the web service, wires `DATABASE_URL`
   between them, and generates `JWT_SECRET_KEY` and `CLEANUP_TOKEN`.
4. It will **prompt you for `SECRET_ENCRYPTION_KEY`**. Generate one locally and
   paste it in — Render's random-value generator cannot produce a valid Fernet
   key, so this one has to be yours:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
5. After the first deploy, set `PUBLIC_BASE_URL` to your real
   `https://<name>.onrender.com` URL so `share_url` points somewhere real.

### Option B — by hand

1. **New → PostgreSQL**, free plan. Copy the **Internal Database URL**.
2. **New → Web Service**, point it at the repo, and set:
   - Build command: `pip install -r requirements.txt && alembic upgrade head`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`
3. Add the environment variables from `.env.example`. For `DATABASE_URL`, paste
   the Internal Database URL as-is — Render gives it to you with a legacy
   `postgres://` prefix, and `app/config.py` rewrites that to
   `postgresql+psycopg2://` for you. (Without that rewrite, SQLAlchemy 2.0
   refuses to start with `Can't load plugin: sqlalchemy.dialects:postgres` —
   it is the single most common way this deploy fails.)

### Things that will bite you on the free tier

- **Bind to `0.0.0.0` and use `$PORT`.** Binding to `127.0.0.1` or hard-coding
  8000 makes the health check fail and the deploy hang.
- **Migrations run in the build command.** Render's dedicated
  `preDeployCommand` is the proper home for them but needs a paid instance.
- **The service sleeps after 15 minutes idle** and takes ~30 seconds to wake.
  The first request after a nap will look broken; it is not.
- **Free databases expire after 30 days.** Fine for a portfolio demo; note it
  if you show this to anyone.
- **The rate limiter resets on every deploy**, because it lives in memory.
- **If the first build fails on the Python version**, change `PYTHON_VERSION`
  in `render.yaml`. Render only offers specific patch releases, and nothing in
  this project needs anything newer than 3.11.

### Driving the cleanup endpoint

There is no scheduler on the free tier. Point any free uptime pinger
(cron-job.org, UptimeRobot) at:

```
POST https://your-app.onrender.com/maintenance/cleanup
Header: X-Cleanup-Token: <your CLEANUP_TOKEN>
```

Hourly is plenty. Nothing breaks if it never runs — expired secrets are still
unreadable, they just are not swept. See
[`app/routers/maintenance.py`](app/routers/maintenance.py).

---

## Design decisions

### Why the reveal is a POST, not a GET

`GET` is required to be *safe*: fetching a URL must not change anything. That
is not pedantry. Browsers prefetch, Slack and WhatsApp unfurl pasted links,
and mail gateways scan them — all with `GET`. If `GET /secrets/{token}`
consumed the secret, **pasting your own link into Slack would destroy it**
before the intended reader clicked.

So the two are split: `GET` reports whether the link is still valid and is
safe to repeat, and an explicit `POST` — which no link-preview bot sends —
consumes it. The landing page at `/s/{token}` is the human-facing half of this:
it loads over `GET` and only fires the `POST` when someone presses the button.

### Why encrypt when the secret is deleted after one read?

They defend against different attackers. Single-read protects the secret from
whoever gets the **link**. Encryption protects it from whoever gets the
**database** — a leaked backup, a misconfigured instance, anyone with read
access to the table. With Fernet, the rows are useless without
`SECRET_ENCRYPTION_KEY`, which exists only in the environment.

### Why the row survives being read

Deleting the row on read would make a second visitor get `404 Not Found`,
which is indistinguishable from "that link never existed". Keeping the row
with its ciphertext wiped lets us answer `410 Gone` — "this was real and it is
now used" — which is both honest and much easier to support. The sensitive
part, the ciphertext, is genuinely destroyed.

### Why the URL token is not the primary key

`/secrets/41` tells you that `/secrets/42` probably exists. The token is 32
bytes from `secrets.token_urlsafe`, drawn from the OS cryptographic random
source, and is the only thing standing between an attacker and the secret.

### Why 404 and not 403 for a forbidden secret

Returning `403` would confirm "this token is real, you just cannot have it",
which turns the API into an oracle for validating guessed tokens. Unknown and
forbidden look identical from outside.

### Why the access check happens before the atomic claim

If we claimed the row first and checked permission afterwards, anyone who
guessed a token could **burn other people's secrets without reading them** — a
denial of service on the core feature. Pinned by
`test_a_denied_read_does_not_burn_the_secret`.

### Why a secret's team is frozen at creation

`secrets.team_id` is copied from the creator when the secret is made, rather
than looked up through `creator.team_id` at read time. Otherwise someone
changing teams would retroactively hand their old secrets to their new
colleagues.

### Why decryption happens before the commit

If the encryption key has changed, decryption fails. Decrypting first means we
can roll back and leave the secret intact for you to fix the key. Wiping first
and then failing would destroy it for nothing.

### Why both lazy expiry and a cleanup endpoint

Lazy expiry (the `expires_at > now` clause inside the atomic UPDATE) provides
the **correctness** guarantee: an expired secret can never be revealed, with no
background process required. But it never *deletes* anything, so a secret
nobody revisits keeps its ciphertext forever. Cleanup is the sweeper that makes
"we destroy your secret" true of the bytes and not just the API.

### Why in-memory rate limiting

Redis is out of scope, so counters live in a module-level dict. The honest
cost: it is per-process (N workers means N times the configured limit) and it
resets on deploy. Acceptable because the limiter exists to stop one IP filling
the table with junk, not to enforce a billing quota. The fix when it matters is
Redis `INCR` + `EXPIRE`, not a cleverer dict.

### Why login returns the same error for a bad email and a bad password

Different messages would let anyone use the endpoint to discover which email
addresses have accounts here. That is user enumeration, and it is pinned by
`test_login_does_not_reveal_whether_an_account_exists`.

---

## Known limitations

Being upfront about these is more useful than pretending they are not there.

1. **Not end-to-end encrypted.** The server holds the key in memory to do its
   job, so a full server compromise exposes secrets in flight. Real E2E would
   encrypt in the browser and put the key in the URL *fragment* (`#key`), which
   browsers never send to the server.
2. **Reading requires an account.** Feature 5 (team access checks) means the
   reader must be authenticated, so links are shareable within a team rather
   than with the whole internet. The reveal page handles this by showing a
   login form first, but it is still a real constraint: you cannot send a link
   to someone outside your team. A public-link mode would be a separate,
   explicitly unauthenticated code path.
3. **The rate limiter is per-process and resets on deploy.** See above.
4. **A dropped response loses the secret.** Once the reveal commits, the
   plaintext exists only in that HTTP response. If the network drops it, it is
   gone. This is the correct trade for a one-time secret — the alternative is
   a window where the secret is readable twice — but it is a real failure mode.
5. **No account recovery, email verification, or password reset.** Out of
   scope for the brief.
6. **`X-Forwarded-For` is trusted.** Safe only because Render overwrites it at
   its edge. Running without a proxy in front would let anyone forge it to dodge
   the rate limit.

### If I were extending it

- End-to-end encryption with the key in the URL fragment.
- A "burn on first view" web page, so the secret is shown in a browser instead
  of a JSON body.
- Optional passphrase on top of the link, so the link alone is not enough.
- Redis-backed rate limiting once there is more than one worker.
- Webhook or email notification to the creator when their secret is read.

---

## Project layout

```
app/
  main.py            FastAPI app, router wiring, static mount, startup checks
  static/            the browser frontend -- no build step
    index.html       sign in, create a secret, manage your team
    reveal.html      the share-link landing page (GET is safe, button POSTs)
    api.js           token storage, fetch wrapper, shared auth panel
    style.css
  config.py          all settings, read from the environment
  database.py        engine, SessionLocal, get_db  -- read this one first
  models.py          the four SQLAlchemy tables
  schemas.py         Pydantic request/response shapes
  security.py        bcrypt hashing + JWT create/decode
  encryption.py      Fernet encrypt/decrypt
  dependencies.py    get_current_user, get_client_ip
  rate_limit.py      the in-memory sliding window
  audit.py           the record_audit helper
  routers/
    auth.py          register, login, me
    teams.py         create, join, leave
    secrets.py       create, list, metadata, reveal  <-- the atomic UPDATE
    audit.py         read the audit log
    maintenance.py   health, cleanup

alembic/
  env.py             reads DATABASE_URL from app.config
  versions/0001_initial_schema.py

tests/               90 tests, see the table above
NOTES.md             plain-English walkthrough of every module
```

**Start here:** `app/database.py`, then `app/models.py`, then the
`reveal_secret` function in `app/routers/secrets.py`.
