# postgrest-auth

Shared, **app-agnostic** JWT auth service that sits alongside PostgREST. This is
permanent server infrastructure — add it **once**, like PostgREST itself. You do
**not** add a new auth container per app.

## What it does

`POST /token` with:

```json
{ "schema": "load_log", "username": "jason", "password": "..." }
```

It looks up `<schema>.users`, verifies the bcrypt `password_hash`, and returns a
signed JWT:

```json
{ "token": "<jwt>" }
```

The JWT (HS256, signed with `JWT_SECRET`) carries:

- `role`: `"<schema>_user"` — the Postgres role PostgREST switches into. Each app
  defines a `<schema>_user` role that owns the GRANTs for its schema
  (e.g. `load_log` → `load_log_user`).
- `user_id`: the user's id (for Row Level Security policies).
- `exp`: now + `JWT_TTL_HOURS` (default 24h).

`JWT_SECRET` must equal PostgREST's `PGRST_JWT_SECRET` (both wired from
`POSTGREST_JWT_SECRET`) so PostgREST trusts the tokens this service issues.

`GET /health` → `{"status": "ok"}`.

## Hardening

This endpoint faces the internet directly (no Authelia in front of
`auth.tinkernet.me`), so it regulates itself — the same posture Sync_Plex and
Book-Bot ship in-app (see `security.py`):

- **Lockout**: 5 failed logins inside 15 minutes locks that key for 15 minutes,
  tracked per-username (`user:<schema>:<name>`) **and** per-client-IP. Locked
  requests get `429` with a human-readable `detail`. In-memory; resets on
  container restart.
- **Client IP**: first `X-Forwarded-For` hop (SWAG sets it; server-side callers
  like load-log's Streamlit container forward their viewer's IP in the same
  header), falling back to the socket peer.
- **No user enumeration**: unknown usernames verify against a dummy bcrypt hash
  so rejects cost the same either way, and the `401` body is identical.
- **Security headers** on every response; TLS/HSTS stay at the SWAG proxy.

Tests: `uv run pytest` (mocks the DB lookup; no Postgres needed).

## Why shared

The auth call is plain HTTP, so it works identically from a Streamlit app, a TUI,
or any other client: POST credentials → get a JWT → send
`Authorization: Bearer <jwt>` on every PostgREST request. New apps just add a
schema + a `<schema>_user` role + a `<schema>.users` table; no new auth service.

## Deployment

Runs in the server's `docker_compose_projects.yaml` as the `auth` container
(host `8006` → `8000`), reverse-proxied at `https://auth.tinkernet.me`.

Env vars: `POSTGRES_URL`, `POSTGRES_PORT`, `POSTGRES_DB` (the database PostgREST
serves — all app schemas live in it), `POSTGRES_USER`, `POSTGRES_PASSWORD`,
`JWT_SECRET`, optional `JWT_TTL_HOURS`.
