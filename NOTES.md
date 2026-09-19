# NOTES — what every module does, in plain English

Revision notes for this project. The README is the public face; this file is
for you, to read the night before an interview.

It assumes you know Python and FastAPI basics and have not used PostgreSQL,
SQLAlchemy, Alembic or JWT before.

---

## Part 1 — The four tools you had not used

### PostgreSQL

A relational database that runs as a separate server process on your machine
(or on Render). Your app talks to it over a TCP connection.

Compared to SQLite: SQLite is a file your program opens; Postgres is a server
your program connects to. That difference is why Postgres can do real
concurrency — multiple clients, row-level locks, transactions that block each
other properly — which this project depends on.

Things worth knowing by name:

- **Transaction** — a group of statements that either all take effect or none
  do. `BEGIN` ... `COMMIT`, or `ROLLBACK` to throw it away.
- **Isolation level** — how much one transaction can see of another's
  in-progress work. Postgres defaults to **READ COMMITTED**: you see other
  transactions' *committed* changes, and each statement gets a fresh view.
- **Row lock** — an `UPDATE` locks the rows it touches until the transaction
  ends. Another transaction trying to update the same row **waits**. This is
  the mechanism that makes the single-read work.
- **Index** — a lookup structure so a `WHERE` does not scan the whole table.
  Think of it as the `std::map` sitting beside your `std::vector`.
- **Foreign key** — a column that must contain a value that exists in another
  table's primary key. The database enforces it; you cannot end up with a
  secret whose `creator_id` points at a user who never existed.

### SQLAlchemy (the ORM)

An ORM maps rows to Python objects so you write `user.email` instead of
parsing a tuple from raw SQL.

The three objects, which are easy to confuse:

| Object | Lifetime | What it is |
|--------|----------|------------|
| **Engine** | one per app | the connection pool. Knows the URL, holds TCP connections. |
| **Session** | one per request | your unit of work. You add and query through it, then `commit()` or `rollback()`. |
| **Base** | one per app | the parent class of your models. Collects the table definitions on `Base.metadata`. |

The mental model that makes Sessions click: a Session is a **staging area**.
`db.add(x)` does not write anything. `db.commit()` writes everything you staged,
in one transaction. Three things move data:

- `flush()` — send the SQL now, but stay inside the transaction. Used when you
  need a database-generated id (`team.id`) before you are ready to commit.
- `commit()` — flush *and* make it permanent.
- `rollback()` — discard everything staged since the last commit.

### Alembic (migrations)

Your models change over time, but the database already has data in it and
cannot be dropped and rebuilt. Alembic keeps an ordered chain of migration
scripts, each with an `upgrade()` and a `downgrade()`, plus a table called
`alembic_version` in your database holding the revision id it is currently at.

`alembic upgrade head` runs whatever is missing, in order.

Think of it as `git log` for your schema: each migration is a commit, and
`alembic_version` is `HEAD`.

The one real trap: `--autogenerate` diffs your models against the live
database. It is good at additions, but **it cannot tell a rename from a drop
plus an add**, so renaming a column comes out as "drop the old one, create a
new empty one" — which silently deletes that column's data. Always read the
generated file before running it.

### JWT (JSON Web Tokens)

A JWT is three base64 chunks joined by dots: `header.payload.signature`.

```
eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiI0MiIsImV4cCI6MTc...} . 4pX9f-Tn...
└─ alg: HS256 ──────┘   └─ sub: "42", exp: ... ─────┘   └─ HMAC ──┘
```

**The single most important fact: a JWT is signed, not encrypted.** Anyone can
base64-decode the payload and read it. What the signature guarantees is that
nobody *changed* it without your key. So never put anything private in a token.

The flow in this project:

1. `POST /auth/login` → we check the password, then build a token whose
   payload says `sub = "7"` (the user id) and `exp = <one hour from now>`.
2. We sign it with `JWT_SECRET_KEY` and hand it over.
3. The client sends `Authorization: Bearer <token>` on every later request.
4. `get_current_user` decodes it. PyJWT recomputes the signature with our key;
   if it does not match, the token was forged → 401. It also checks `exp`.
5. We then **load the user from the database** — see below for why.

Because the signature is all that matters, the server keeps **no session
state**. That is the big win (any instance can validate any token) and the big
cost: you cannot revoke a token. It is valid until it expires. That is why the
lifetime is an hour, not a year.

---

## Part 2 — Module by module

### `app/config.py`

One `Settings` class, built from environment variables by pydantic-settings,
and one `settings` object that everything imports. Nothing else in the codebase
touches `os.environ`.

Why: Pydantic validates and converts types, and fails **at startup** if
something required is missing — much better than failing at 3am on the one
request that needed it.

`get_settings()` is wrapped in `@lru_cache`, so the `.env` file is read once.

### `app/timeutil.py`

Three tiny helpers enforcing one rule: **every datetime is timezone-aware and
in UTC**.

Why it matters: comparing a naive datetime to an aware one raises `TypeError`
in Python, and "expires at 5pm" is meaningless without a timezone when your
laptop, the test runner and the Render server are in three different ones.

`ensure_utc()` exists because SQLite has no real timezone support and hands
back naive values. Postgres returns them correctly and it is a no-op there.

### `app/database.py` — **read this one first**

Creates the three things from the table above: `engine`, `SessionLocal`, `Base`.
Plus `get_db()`, the dependency that gives each request its own Session.

`get_db` is a generator:

```python
db = SessionLocal()
try:
    yield db          # FastAPI runs your endpoint here
finally:
    db.close()        # always runs, even if the endpoint raised
```

That `finally` is why connections never leak.

Two settings with real reasoning behind them:

- `expire_on_commit=False` — by default, after `commit()` SQLAlchemy marks
  every loaded object stale and re-queries on the next attribute access. That
  means `return user` after a commit can fire another `SELECT`, or blow up if
  the session is closed. Turning it off keeps things predictable.
- `pool_pre_ping=True` — managed Postgres silently drops idle connections;
  this checks a connection is alive before handing it out.

Note `get_db` does **not** commit for you. Every endpoint commits explicitly,
so reading the endpoint tells you exactly when the write becomes permanent.

### `app/models.py`

The four tables as Python classes.

The comments to reread:

- **`secrets.token` is not the primary key.** `/secrets/41` would tell an
  attacker that `/secrets/42` exists. The token is 32 random bytes.
- **`secrets.ciphertext` is nullable** because destroying a secret means
  setting it to `NULL`.
- **`secrets.team_id` is copied at creation**, not looked up through the
  creator at read time — otherwise switching teams would retroactively hand
  your old secrets to your new colleagues.
- **`audit_logs.secret_token` is a plain string, not a foreign key.** The audit
  trail has to outlive the thing it describes; a FK with `ON DELETE CASCADE`
  would delete the evidence.
- **`foreign_keys=[...]` on the relationships** is required because `secrets`
  has two FKs pointing at `users` (`creator_id` and `viewed_by_id`), so
  SQLAlchemy cannot guess which one each relationship follows.

Also: `ForeignKey` creates the real database constraint; `relationship()`
creates no column at all — it is just the Python convenience that lets you
write `user.team`.

### `app/schemas.py`

Pydantic models: what the outside world may send and see.

**Why they are separate from the ORM models** — this is the habit to internalise.
The ORM model is what the *database* stores; the schema is what the *API*
exposes. If you return ORM objects directly, then the day you add a
`hashed_password` column you have leaked every password hash. `UserRead` simply
does not have that field, so it cannot be serialised.

`from_attributes=True` lets Pydantic read an ORM object's attributes
(`user.email`) instead of expecting a dict.

### `app/security.py`

Two unrelated jobs that people conflate:

**Password hashing** — one-way. `hash_password` produces a bcrypt hash;
`verify_password` hashes the attempt and compares. There is no un-hash. bcrypt
is deliberately *slow*, which is the point: it makes brute-forcing a stolen
database expensive. passlib generates a random salt per password and stores it
inside the hash string, so two users with the same password get different
hashes.

**Tokens** — `create_access_token` and `decode_access_token`.

The line worth memorising:

```python
jwt.decode(token, key, algorithms=[settings.jwt_algorithm])
```

`algorithms=` is a **whitelist and a real security control**. Without it, an
attacker can hand you a token whose header says `alg: "none"` and the library
will skip verification entirely. This is a famous class of JWT vulnerability.

Note also that every failure — expired, forged, malformed — raises the same
`InvalidTokenError` and produces the same 401. Telling the client *which* check
failed is useful information to an attacker.

### `app/encryption.py`

Fernet: symmetric authenticated encryption. Same key encrypts and decrypts, and
the ciphertext is signed so tampering is detected. Good default because it
gives you no knobs to get wrong.

The key must be 32 random bytes, url-safe base64 encoded. `get_cipher()` builds
it once and caches it; `app/main.py` calls it at startup so a bad key stops the
app booting instead of failing on the first real request.

### `app/dependencies.py`

**`get_current_user`** — the whole auth system, in one function. An endpoint
that declares `current_user: User = Depends(get_current_user)` **cannot be
reached without a valid token**. The check is part of the signature, so it is
impossible to forget.

The question you will be asked: *why re-query the database when the user id is
already in the token?* Because the token is a snapshot from up to an hour ago.
The account may have been deactivated or moved teams since. The database is the
source of truth; the token only says who is asking. `test_deactivated_user_
cannot_authenticate` pins this.

**`get_client_ip`** — reads `X-Forwarded-For` first, because behind a proxy
`request.client.host` is the *proxy's* address and every request would look
like it came from one IP. The caveat is in the docstring: that header is
client-settable and only trustworthy because Render overwrites it at its edge.

### `app/rate_limit.py`

A sliding window per IP. For each IP, keep the timestamps of recent requests in
a `deque`, drop the ones older than the window, reject if what remains is at
the limit.

`deque` because old entries leave from the left and new ones arrive on the
right — both O(1).

Two details worth mentioning out loud:

- **`threading.Lock`** — uvicorn runs sync endpoints in a thread pool, so two
  requests really can touch the dict simultaneously. Without the lock, two
  requests could both see "9 hits, room for one more" and both be allowed.
  (Same class of bug as the secret race, at a much lower stakes.)
- **`time.monotonic()`, not `time.time()`** — monotonic cannot jump backwards
  when the machine syncs its clock.

Know the limitations cold: per-process, and lost on restart. Say so before you
are asked.

### `app/audit.py`

One helper, `record_audit`, that adds a row to the session.

The important line: **it does not commit.** The caller commits, so the audit
entry lands in the same transaction as the thing it describes. You can never
get a "secret revealed" log line for a reveal that was rolled back.

### `app/routers/auth.py`

Register, login, me.

- **Duplicate emails are caught by catching `IntegrityError`**, not by a
  `SELECT` first. Between a "does this email exist?" check and your `INSERT`,
  another request can register the same address. The UNIQUE constraint is the
  only check that cannot be raced. This is the same reasoning as the atomic
  UPDATE, in miniature — good thing to point out in an interview.
- **Emails are lowercased** so `Bob@` and `bob@` are one account.
- **Login takes a form body, not JSON**, with the email in a field called
  `username`. That is the OAuth2 password-flow spec, and following it is what
  makes the Authorize button in `/docs` work.
- **Same error for unknown email and wrong password** — otherwise the endpoint
  becomes a tool for discovering who has an account (user enumeration).

### `app/routers/secrets.py` — **the one that matters**

`reveal_secret` runs in three steps, and the order is deliberate:

**Step 1 — access check.** Load the secret, check the caller is the creator or
in the owning team. If not, 404 (not 403 — a 403 would confirm the token is
real). This happens **before** the claim so that a stranger who guessed a token
cannot burn someone else's secret without reading it.

**Step 2 — the atomic claim.**

```sql
UPDATE secrets
   SET viewed = true, viewed_at = ..., viewed_by_id = ...
 WHERE token = :token AND viewed = false AND expires_at > :now
RETURNING ciphertext, label;
```

**Step 3 — decrypt, then wipe, then commit.** Decryption happens *before* the
commit on purpose: if the key has changed, we roll back and the secret survives
for you to fix the config. Then a second `UPDATE` sets `ciphertext = NULL`, and
one `commit()` makes the claim, the wipe and the audit row permanent together.

Two small things that look odd and are not:

- `.execution_options(synchronize_session=False)` tells the ORM not to work out
  which in-memory objects a bulk UPDATE invalidated. We handle that ourselves
  with `db.expire(secret)`.
- The wipe is a *separate statement* because Postgres's `RETURNING` gives you
  the **new** row values. If we wiped `ciphertext` in the same UPDATE,
  `RETURNING ciphertext` would hand back `NULL`.

### `app/routers/teams.py`

Create, join by invite code, view, leave. Joining is by code so nobody can pull
you into a team without your cooperation.

Note `db.flush()` in `create_team`: it sends the `INSERT` so Postgres assigns
`team.id`, without committing. We need that id immediately to set the user's
`team_id`, and both writes still land in one transaction.

### `app/routers/audit.py`

Read-only. You see your own events, plus your team's if you are in one. There is
no endpoint to edit or delete an entry — an audit trail you can quietly rewrite
is not evidence.

### `app/routers/maintenance.py`

`/health` deliberately does **not** touch the database: Render pings it to
decide whether to restart the process, and a slow database should not turn into
an outage.

`/maintenance/cleanup` is guarded by a header token rather than a JWT, because
the caller is a cron job with no account. It uses `hmac.compare_digest` rather
than `==` — a plain `==` returns early on the first wrong character, and that
timing difference is enough to guess the token one character at a time.

Two stages: **wipe** the ciphertext of expired secrets (immediately), then
**purge** rows that expired over 30 days ago.

### `app/main.py`

Wires the routers together. The `lifespan` hook builds the Fernet cipher at
startup so a missing or malformed key stops the app booting — fail fast, with a
message telling you how to generate one.

### `app/static/` — the browser frontend

Four files, no framework and no build step: `index.html` (sign in, create,
team, list), `reveal.html` (the share-link landing page), `api.js` (shared
helpers) and `style.css`. `app/main.py` mounts them with `StaticFiles` and
serves the two pages with `FileResponse`.

Why plain JavaScript: the interesting part of this project is the backend, and
a React toolchain would add a build step without demonstrating anything extra.
Serving it from FastAPI itself also means one deployment and no CORS.

**The point of `reveal.html`** is that it makes the GET/POST split visible.
Loading the page runs a safe `GET /secrets/{token}` that only reads metadata.
The destructive `POST .../reveal` fires only when the reader presses the
button. If revealing happened on page load, pasting your own share link into
Slack would burn the secret before anyone clicked it.

`GET /s/{token}` returns the *same* HTML for every token and never touches the
database — the page reads the token out of the URL in the browser. That is what
makes serving it completely free of side effects.

Two frontend details worth being able to defend:

- **The JWT is in `localStorage`.** Honest trade-off: localStorage is readable
  by any JS on the page, so an XSS bug leaks the token. The safer option is an
  `httpOnly` cookie, which JS cannot read — but cookies are sent automatically,
  which opens CSRF and means adding a CSRF token. For a pure Bearer-token API
  with a one-hour token and no third-party scripts, localStorage is reasonable.
  Say the trade-off out loud rather than pretending it is the only option.
- **User input is escaped before it touches `innerHTML`.** Secret labels are
  user-controlled, so a label like `<img src=x onerror=...>` would execute if
  interpolated raw. `escapeHtml()` in `index.html` handles the list, and the
  revealed secret uses `textContent`, never `innerHTML`.

---

## Part 3 — Interview questions you should expect

**"Walk me through what happens when someone reads a secret."**
Decode the JWT and load the user (401 if bad) → check they are the creator or a
teammate (404 if not, so we do not confirm the token is real) → run one
conditional `UPDATE ... WHERE viewed = false RETURNING ciphertext` → if it
returns no row, someone else got there first, 410 → decrypt → wipe the
ciphertext → write the audit row → one commit for all of it.

**"Why not just check `if secret.viewed` in Python?"**
Check-then-act race. Two requests can both read `viewed = False` before either
writes, both pass the check, and both return the secret. Putting the check
inside the `UPDATE` makes the database arbitrate: the second statement blocks
on the row lock, re-evaluates its `WHERE` against the updated row, matches
nothing, and returns zero rows.

**"Would a transaction fix the naive version?"**
Not under READ COMMITTED, which is Postgres's default — each statement gets a
fresh snapshot, so B's `SELECT` still reads the old value. You would need
`SELECT ... FOR UPDATE` (take the lock explicitly at read time) or
`SERIALIZABLE` isolation (and then handle serialization failures and retry).
The single conditional `UPDATE` gets the same guarantee in one statement with
no retry logic.

**"What is `RETURNING` for?"**
It hands back the row you just claimed in the same round trip. Without it you
would need a separate `SELECT` for the ciphertext, and you would be back to two
statements needing coordination.

**"How do you know it works?"**
Two tests. One is deterministic: two sessions both read the row, both see
`viewed = False`, both run the claim — exactly one gets a row back. The other
fires eight concurrent HTTP requests through a thread barrier and asserts
exactly one 200 and seven 410s.

**"Why encrypt if you delete it after one read?"**
Different attackers. Single-read protects against whoever has the *link*;
encryption protects against whoever has the *database* — a leaked backup, a
misconfigured instance. Without the key the rows are useless.

**"Is it end-to-end encrypted?"**
No, and say so plainly. The server holds the key to do its job. Real E2E would
encrypt in the browser and put the key in the URL fragment (`#key`), which
browsers never transmit to the server.

**"Why is the reveal a POST?"**
`GET` has to be safe. Browsers prefetch and Slack unfurls pasted links — if
`GET` consumed the secret, pasting your own link into Slack would destroy it.

**"Why did you write the frontend in plain JavaScript?"**
Because the project is a backend portfolio piece and a build step would add a
toolchain without demonstrating anything. Serving it from FastAPI keeps it to
one deployment with no CORS. If it grew past two pages I would reach for a
framework.

**"Where do you store the token in the browser, and why?"**
localStorage. The alternative is an httpOnly cookie, which JavaScript cannot
read and so survives XSS — but cookies are sent automatically, so I would then
need CSRF protection. With a Bearer-token API, a one-hour expiry and no
third-party scripts on the page, localStorage is the reasonable trade.

**"How does your rate limiting hold up across multiple workers?"**
It does not, and that is a deliberate trade. It is an in-memory dict, so it is
per-process and resets on deploy. It exists to stop one IP filling the table,
not to enforce a quota. The fix is Redis `INCR` + `EXPIRE`.

**"What is the difference between your SQLAlchemy models and Pydantic schemas?"**
Models are what the database stores; schemas are what the API exposes. Keeping
them separate is what stops a `hashed_password` column leaking into a response
the day someone adds it.

**"What would you do differently at 100x the traffic?"**
Redis for rate limiting, an index-only scan check on the reveal path, read
replicas for the audit log, and moving cleanup to a real scheduler. The atomic
UPDATE itself does not need to change — that is the point of pushing the
guarantee into the database.

---

## Part 4 — Things to be able to do live

```bash
# start postgres and connect
brew services start postgresql@16
psql "postgresql://secretshare:secretshare@localhost:5432/secretshare"

# inside psql
\dt                       -- list tables
\d secrets                -- describe the secrets table
SELECT token, viewed, expires_at FROM secrets ORDER BY created_at DESC LIMIT 5;
SELECT action, user_id, detail FROM audit_logs ORDER BY created_at DESC LIMIT 10;
\q

# migrations
alembic current           -- where is this database?
alembic history           -- the chain
alembic upgrade head
alembic downgrade -1

# run it
uvicorn app.main:app --reload
open http://localhost:8000/docs

# tests
pytest
pytest tests/test_secrets_single_read.py -v
TEST_DATABASE_URL="postgresql+psycopg2://secretshare:secretshare@localhost:5432/secretshare_test" pytest
```

### If someone asks you to add a column, live

```bash
# 1. add the field to the class in app/models.py
# 2. generate the migration
alembic revision --autogenerate -m "add notify_on_read to secrets"
# 3. READ the generated file in alembic/versions/ before running it
# 4. apply it
alembic upgrade head
```

---

## Part 5 — One-line summaries, for the morning of

- **Session** = staging area for one request; `add` stages, `commit` writes.
- **`flush`** = send the SQL now, stay in the transaction (to get an id).
- **Engine** = connection pool, one per app. **Session** = one per request.
- **Migration** = a commit in your schema's history; `alembic_version` is HEAD.
- **JWT** = signed, not encrypted. Anyone can read it; only you can forge it.
- **`algorithms=[...]`** on `jwt.decode` stops the `alg: none` attack.
- **bcrypt is slow on purpose**, and salts each password automatically.
- **Fernet** = symmetric authenticated encryption, 32-byte base64 key.
- **The single-read** = `UPDATE ... WHERE viewed = false RETURNING ...`; the
  loser matches zero rows.
- **READ COMMITTED** is why the naive transaction version still races.
- **404 not 403** for forbidden secrets, so we never confirm a token is real.
- **Access check before the claim**, so a stranger cannot burn your secret.
- **Lazy expiry** gives correctness; **cleanup** gives data retention.
- **`/s/{token}` serves the same HTML for every token** and never touches the
  database, so opening a share link has no side effects at all.
- **localStorage for the JWT** — XSS-readable, but avoids CSRF; know both sides.
