# postgrest-auth

Shared, **app-agnostic** JWT auth service that sits alongside PostgREST. This is
permanent server infrastructure — add it **once**, like PostgREST itself. You do
**not** add a new auth container per app.

## What it does

`POST /token` with:

```json
{ "schema": "load_log", "username": "jason", "password": "...", "ttl_hours": 720 }
```

(`ttl_hours` is optional — session policy belongs to the calling app; it is
clamped to 720 h / 30 days. Without it the default `JWT_TTL_HOURS` applies.)

It looks up `<schema>.users`, verifies the `password_hash`, and returns a
signed JWT:

```json
{ "token": "<jwt>" }
```

The JWT (HS256, signed with `JWT_SECRET`) carries:

- `role`: `"<schema>_user"` — the Postgres role PostgREST switches into. Each app
  defines a `<schema>_user` role that owns the GRANTs for its schema
  (e.g. `load_log` → `load_log_user`).
- `user_id`: the user's id (for Row Level Security policies).
- `username`: the stored (canonical) username.
- `app_role`: the row's `role` column — the app-level role (`admin`/`user`),
  distinct from the Postgres `role` claim above.
- `iat`: issue time. Apps that enforce `password_changed_at` revocation
  (Solitaire, Book-Bot) compare it against the user row on every request.
- `exp`: now + TTL.

`JWT_SECRET` must equal PostgREST's `PGRST_JWT_SECRET` (both wired from
`POSTGREST_JWT_SECRET`) so PostgREST trusts the tokens this service issues.

`GET /health` → `{"status": "ok"}`.

## Password hashing

**argon2id is the standard.** Hashes are self-identifying by prefix, so legacy
bcrypt hashes (`$2b$…`) still verify and are transparently rehashed to argon2id
on the next successful login — no password resets, ever. The rehash deliberately
does **not** bump `password_changed_at`: the password didn't change, so existing
sessions survive.

Disabled accounts (`disabled = true`) pay the same verify cost and get the same
401 as a wrong password — being disabled is not enumerable either.

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
gets a clear `503 users table not migrated` — land the app's additive migration
**before** deploying a service that serves its schema.

## Hardening

This endpoint faces the internet directly (no Authelia in front of
`auth.tinkernet.me`), so it regulates itself (see `security.py`):

- **Lockout**: 5 failed logins inside 15 minutes locks that key for 15 minutes,
  tracked per-username (`user:<schema>:<name>`) **and** per-client-IP. Locked
  requests get `429` with a human-readable `detail`. In-memory; resets on
  container restart.
- **Client IP**: first `X-Forwarded-For` hop (SWAG sets it; server-side callers
  like load-log's Streamlit container forward their viewer's IP in the same
  header), falling back to the socket peer.
- **No user enumeration**: unknown usernames verify against a dummy argon2id hash
  so rejects cost the same either way, and the `401` body is identical.
- **Security headers** on every response; TLS/HSTS stay at the SWAG proxy.

Tests: `uv run pytest` (mocks the DB lookup; no Postgres needed).

## Why shared

The auth call is plain HTTP, so it works identically from a Streamlit app, a TUI,
or any other client: POST credentials → get a JWT → send
`Authorization: Bearer <jwt>` on every PostgREST request. New apps just add a
schema + a `<schema>_user` role + a `<schema>.users` table; no new auth service.

This service owns **verification** (KDF policy, throttling, timing defense) in
one place. **Session validation** stays app-side: apps decode the JWT with the
shared secret and check `disabled`/`password_changed_at` against their users
table (Solitaire's `app/auth.py` is the reference). Account management (create,
disable, set-password) also stays app-side via each app's CLI.

## Deployment

Runs via compose include from `deploy/compose.elitedesk.yaml` as the `auth`
container (host `8006` → `8000`), reverse-proxied at `https://auth.tinkernet.me`.

Env vars: `POSTGRES_URL`, `POSTGRES_PORT`, `POSTGRES_DB` (the database PostgREST
serves — all app schemas live in it), `POSTGRES_USER`, `POSTGRES_PASSWORD`,
`JWT_SECRET`, optional `JWT_TTL_HOURS`.
