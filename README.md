# postgrest-auth

A small Python library that logs users in for apps built on
[PostgREST](https://postgrest.org). It checks a username and password
against the app's own Postgres users table and returns a signed JWT that
PostgREST accepts.

PostgREST validates JWTs but does not issue them. This library fills that
gap inside each app: the app calls `login()` in-process with its own
database connection, so it needs nothing running beside it except Postgres
and PostgREST. Each app keeps its own schema and users table.

argon2id password hashing (legacy bcrypt still verifies and is upgraded on
login), per-user and per-IP lockout, and no user enumeration by timing.

## Install

Add it as a git dependency pinned to a tag. With uv:

```toml
[project]
dependencies = ["postgrest-auth"]

[tool.uv.sources]
postgrest-auth = { git = "https://github.com/ReadableCode/postgrest-auth.git", tag = "v0.2.0" }
```

uv fetches git dependencies with the `git` binary, so a Docker image that
runs `uv sync` needs `git` installed.

## How it works

1. The app calls `login(connect, schema, username, password, jwt_secret=...)`.
2. The library looks up `<schema>.users`, verifies `password_hash`, and checks
   that the account is not disabled.
3. It returns an HS256 JWT whose `role` claim is `<schema>_user`.
4. The app sends `Authorization: Bearer <jwt>` on every PostgREST request.
   PostgREST trusts the token (same secret) and switches into that Postgres
   role, so the app's GRANTs and Row Level Security apply.

A new app needs only a schema, a `<schema>_user` role and a `<schema>.users`
table.

## API

```python
import postgrest_auth

token = postgrest_auth.login(
    connect,              # zero-argument callable returning a DB-API connection
    "acme",               # schema: picks <schema>.users and the <schema>_user role
    username,
    password,
    jwt_secret=JWT_SECRET,  # same value as PostgREST's PGRST_JWT_SECRET
    client_ip=ip,         # optional: the browser's IP, for the per-IP lockout key
    ttl_hours=720,        # optional: session length, clamped to 720 h (30 days)
)
```

`connect` returns a psycopg2 or psycopg connection that can `SELECT` the
users table and `UPDATE` its `password_hash`. PostgREST deliberately cannot
reach that table, so this is the app's own direct connection.

`login()` raises:

| Exception | Cause |
| --- | --- |
| `InvalidCredentials` | wrong password, unknown user, or disabled account (one error for all three) |
| `LoginLocked` | username or client IP is locked out; `retry_after` holds the seconds left and `str()` is a readable message |
| `ValueError` | schema fails `^[a-z_][a-z0-9_]{0,62}$` (it is used as a SQL identifier) |

Database errors (connection failure, missing table or columns) propagate
unchanged; map them to your app's "unavailable" response.

The JWT (HS256, signed with `jwt_secret`) carries:

- `role`: `"<schema>_user"`, the Postgres role PostgREST switches into. Each
  app defines a `<schema>_user` role that owns the GRANTs for its schema
  (e.g. `acme` -> `acme_user`).
- `user_id`: the user's id (for Row Level Security policies).
- `username`: the stored (canonical) username.
- `app_role`: the row's `role` column, the app-level role (`admin`/`user`),
  distinct from the Postgres `role` claim above.
- `iat`: issue time. Apps that enforce `password_changed_at` revocation
  compare it against the user row on every request.
- `exp`: now + TTL. Without `ttl_hours` the TTL is 24 hours.

Also exported:

- `mint_token(schema, user_id, username, app_role, jwt_secret=..., ttl_hours=None)`:
  the same token without a password check, for scripts and tests that act as
  a known user.
- `hash_password`, `verify_password`, `needs_rehash`: the hashing used above,
  for signup, password changes and account CLIs.
- `LoginRateLimiter`: the lockout tracker. `login()` uses one per process
  unless you pass `limiter=`.
- `client_ip(forwarded_for, peer)`: first `X-Forwarded-For` hop, else the
  socket peer.

## Required `<schema>.users` shape

`login()` selects `id, username, password_hash, role, disabled` and apps'
session validators read `password_changed_at`, so every users table needs:

```sql
id                  uuid PRIMARY KEY
username            text UNIQUE NOT NULL
password_hash       text NOT NULL          -- argon2id (bcrypt tolerated, migrated on login)
role                text NOT NULL DEFAULT 'user'
disabled            boolean NOT NULL DEFAULT false
password_changed_at timestamptz NOT NULL DEFAULT now()
```

## Password hashing

argon2id is the standard. Hashes are self-identifying by prefix, so legacy
bcrypt hashes (`$2b$...`) still verify and are transparently rehashed to
argon2id on the next successful login; nobody has to reset a password. Hashes
with outdated argon2 parameters are rehashed the same way. The rehash
deliberately does not bump `password_changed_at`: the password did not change,
so existing sessions survive. A failed rehash is ignored and retried on the
next login.

Disabled accounts (`disabled = true`) pay the same verify cost and get the same
error as a wrong password, so being disabled is not enumerable either.

## Hardening

- **Lockout**: 5 failed logins inside 15 minutes locks that key for 15 minutes,
  tracked per username (`user:<schema>:<name>`, lowercased) and per client IP
  when the app passes one. A successful login clears the counters. In-memory,
  per app process; resets on restart.
- **Client IP**: pass the first `X-Forwarded-For` hop set by your reverse proxy
  (`client_ip()` does this), so the per-IP key counts the browser.
- **No user enumeration**: unknown usernames verify against a dummy argon2id
  hash so rejects cost the same either way, and the error is identical.
  Until a legacy bcrypt user logs in once, their reject path pays bcrypt cost
  instead of argon2 cost; that gap closes as rehashes land.

TLS, HSTS and security headers belong to the app and its reverse proxy.

## What stays in each app

Session validation stays app-side: apps decode the JWT with the shared secret
and check `disabled`/`password_changed_at` against their users table.
Account management (create, disable, set-password) also stays app-side via
each app's CLI, using `hash_password` from this library.

## Development

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run flake8
uv run pytest
```

The tests use a fake connection; no Postgres is needed.
