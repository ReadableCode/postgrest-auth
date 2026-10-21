# postgrest-auth

A small login service for [PostgREST](https://postgrest.org). It checks a
username and password against a Postgres users table and returns a signed JWT
that PostgREST accepts.

PostgREST validates JWTs but does not issue them. This service fills that gap
for a server that hosts several apps behind one PostgREST: each app keeps its
own schema and users table, and all of them log in through this one endpoint.
It is shared infrastructure, added once next to PostgREST, not one auth
container per app.

FastAPI, two Python files (`main.py`, `security.py`), argon2id password
hashing, and per-user and per-IP lockout.

## How it works

1. A client sends `POST /token` with a schema name, username and password.
2. The service looks up `<schema>.users`, verifies `password_hash`, and checks
   that the account is not disabled.
3. It returns an HS256 JWT whose `role` claim is `<schema>_user`.
4. The client sends `Authorization: Bearer <jwt>` on every PostgREST request.
   PostgREST trusts the token (same secret) and switches into that Postgres
   role, so the app's GRANTs and Row Level Security apply.

The auth call is plain HTTP, so it works the same from a Streamlit app, a TUI
or any other client. A new app needs only a schema, a `<schema>_user` role and
a `<schema>.users` table; no new auth service.

## API

### `POST /token`

```json
{ "schema": "load_log", "username": "alice", "password": "...", "ttl_hours": 720 }
```

`ttl_hours` is optional. Session policy belongs to the calling app; the value
is clamped to 720 h (30 days). Without it the default `JWT_TTL_HOURS` applies.

Response:

```json
{ "token": "<jwt>" }
```

The JWT (HS256, signed with `JWT_SECRET`) carries:

- `role`: `"<schema>_user"`, the Postgres role PostgREST switches into. Each
  app defines a `<schema>_user` role that owns the GRANTs for its schema
  (e.g. `load_log` -> `load_log_user`).
- `user_id`: the user's id (for Row Level Security policies).
- `username`: the stored (canonical) username.
- `app_role`: the row's `role` column, the app-level role (`admin`/`user`),
  distinct from the Postgres `role` claim above.
- `iat`: issue time. Apps that enforce `password_changed_at` revocation
  (Solitaire, Book-Bot) compare it against the user row on every request.
- `exp`: now + TTL.

`JWT_SECRET` must equal PostgREST's `PGRST_JWT_SECRET` (both wired from
`POSTGREST_JWT_SECRET`) so PostgREST trusts the tokens this service issues.

Errors:

| Status | Detail | Cause |
| --- | --- | --- |
| 400 | `Invalid schema name` | schema fails `^[a-z_][a-z0-9_]{0,62}$` (it is used as a SQL identifier) |
| 400 | `Unknown schema` | `<schema>.users` does not exist |
| 401 | `Invalid credentials` | wrong password, unknown user, or disabled account |
| 429 | `too many attempts ...` | username or client IP is locked out |
| 503 | `users table not migrated` | users table is missing required columns |
| 503 | `Database unavailable` / `Database error` | Postgres connection or query failure |

### `GET /health`

Returns `{"status": "ok"}`. The interactive OpenAPI docs pages are disabled.

## Required `<schema>.users` shape

The service selects `id, username, password_hash, role, disabled` and apps'
validators read `password_changed_at`, so every served users table needs:

```sql
id                  uuid PRIMARY KEY
username            text UNIQUE NOT NULL
password_hash       text NOT NULL          -- argon2id (bcrypt tolerated, migrated on login)
role                text NOT NULL DEFAULT 'user'
disabled            boolean NOT NULL DEFAULT false
password_changed_at timestamptz NOT NULL DEFAULT now()
```

(Solitaire's `deploy/02_schema.sql` is the reference.) A table missing columns
gets a clear `503 users table not migrated`: land the app's additive migration
before deploying a service that serves its schema.

## Password hashing

argon2id is the standard. Hashes are self-identifying by prefix, so legacy
bcrypt hashes (`$2b$...`) still verify and are transparently rehashed to
argon2id on the next successful login; nobody has to reset a password. Hashes
with outdated argon2 parameters are rehashed the same way. The rehash
deliberately does not bump `password_changed_at`: the password did not change,
so existing sessions survive. A failed rehash is ignored and retried on the
next login.

Disabled accounts (`disabled = true`) pay the same verify cost and get the same
401 as a wrong password, so being disabled is not enumerable either.

## Hardening

The endpoint faces the internet directly (no Authelia in front of it), so it
regulates itself (see `security.py`):

- **Lockout**: 5 failed logins inside 15 minutes locks that key for 15 minutes,
  tracked per username (`user:<schema>:<name>`, lowercased) and per client IP.
  Locked requests get `429` with a human-readable `detail`. A successful login
  clears the counters. In-memory; resets on container restart.
- **Client IP**: first `X-Forwarded-For` hop (the SWAG reverse proxy sets it;
  server-side callers like load-log's Streamlit container forward their
  viewer's IP in the same header), falling back to the socket peer.
- **No user enumeration**: unknown usernames verify against a dummy argon2id
  hash so rejects cost the same either way, and the `401` body is identical.
  Until a legacy bcrypt user logs in once, their reject path pays bcrypt cost
  instead of argon2 cost; that gap closes as rehashes land.
- **Security headers** on every response (`X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`). TLS and
  HSTS stay at the reverse proxy.

## What stays in each app

This service owns verification (KDF policy, throttling, timing defense) in one
place. Session validation stays app-side: apps decode the JWT with the shared
secret and check `disabled`/`password_changed_at` against their users table
(Solitaire's `app/auth.py` is the reference). Account management (create,
disable, set-password) also stays app-side via each app's CLI.

## Running it

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

Environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `POSTGRES_URL` | required | Postgres host |
| `POSTGRES_PORT` | `5432` | |
| `POSTGRES_DB` | `load_log` | the database PostgREST serves; all app schemas live in it |
| `POSTGRES_USER` | required | needs SELECT, and UPDATE on `password_hash`, for each served `<schema>.users` |
| `POSTGRES_PASSWORD` | required | |
| `JWT_SECRET` | required | same value as PostgREST's `PGRST_JWT_SECRET` |
| `JWT_TTL_HOURS` | `24` | default token lifetime when the request sends no `ttl_hours` |

Locally:

```sh
uv sync
POSTGRES_URL=localhost POSTGRES_USER=... POSTGRES_PASSWORD=... JWT_SECRET=... \
  uv run uvicorn main:app --port 8000
```

With Docker: the `Dockerfile` builds a `python:3.13-slim` image that serves
uvicorn on port 8000.

Tests: `uv run pytest` (mocks the DB lookup; no Postgres needed).

## Deployment

The compose service definition lives in `deploy/` and is pulled into the
server's central compose file via `include:`. It runs as the `auth` container
(host `8006` -> `8000`) next to the `postgres` service, behind a SWAG reverse
proxy that terminates TLS. Its `${VARS}` interpolate from this repo's `.env`,
which is a machine-local file and never committed. The compose file sets
`POSTGRES_URL=postgres`, `POSTGRES_DB=apps`, and wires `JWT_SECRET` from
`POSTGREST_JWT_SECRET`.
