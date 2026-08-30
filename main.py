# %% Imports
import datetime
import os
import re

import jwt
import psycopg2
from psycopg2 import sql
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from security import (
    DUMMY_HASH,
    LoginRateLimiter,
    client_ip,
    hash_password,
    needs_rehash,
    verify_password,
)

# %% Configuration
# Shared, app-agnostic auth service that sits alongside PostgREST. It is added
# ONCE as permanent infrastructure and serves every app. Each app gets its own
# Postgres schema and a "<schema>_user" role; this service issues JWTs that
# PostgREST validates (same secret) and uses to SET ROLE.
POSTGRES_URL = os.environ["POSTGRES_URL"]
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "load_log")  # the DB PostgREST serves
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_TTL_HOURS = int(os.environ.get("JWT_TTL_HOURS", "24"))
MAX_TTL_HOURS = 720  # 30 days — the longest session any app runs

# A request's schema picks both the users table ("<schema>.users") and the role
# claim ("<schema>_user"). It is interpolated into SQL as an identifier, so it
# must be validated against a strict allowlist to prevent injection.
SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

app = FastAPI(title="postgrest-auth", docs_url=None, redoc_url=None)

# Brute-force protection: this endpoint faces the internet directly (no
# Authelia in front of auth.tinkernet.me), so it regulates itself — same
# policy Sync_Plex/Book-Bot use: 5 failures / 15 min locks the key.
login_limiter = LoginRateLimiter()


@app.middleware("http")
async def security_headers(request, call_next):
    """Edge hardening this JSON-only API owns itself; TLS/HSTS stay at the
    SWAG proxy in front."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    return response


# %% Models
class TokenRequest(BaseModel):
    # Field is named `schema_` to avoid shadowing pydantic's BaseModel.schema;
    # the wire/body key is still "schema".
    schema_: str = Field(alias="schema")
    username: str
    password: str
    # Session policy belongs to the calling app (Solitaire runs 30-day
    # sessions, load-log is fine with the default). Clamped to MAX_TTL_HOURS.
    ttl_hours: int | None = None

    model_config = {"populate_by_name": True}


# %% DB access
def _connect():
    try:
        return psycopg2.connect(
            host=POSTGRES_URL,
            port=POSTGRES_PORT,
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
        )
    except psycopg2.Error:
        raise HTTPException(status_code=503, detail="Database unavailable")


def fetch_user(schema: str, username: str) -> tuple | None:
    """(id, username, password_hash, role, disabled) from <schema>.users,
    or None. The username comes back in its stored casing so token claims
    are canonical."""
    conn = _connect()
    try:
        with conn, conn.cursor() as cur:
            query = sql.SQL(
                "SELECT id, username, password_hash, role, disabled "
                "FROM {}.users WHERE username = %s"
            ).format(sql.Identifier(schema))
            cur.execute(query, (username,))
            return cur.fetchone()
    except psycopg2.errors.UndefinedTable:
        raise HTTPException(status_code=400, detail="Unknown schema")
    except psycopg2.errors.UndefinedColumn:
        # The app's users table predates the standard shape (role, disabled,
        # password_changed_at — see README). Its additive migration must land
        # before this service serves it.
        raise HTTPException(status_code=503, detail="users table not migrated")
    except psycopg2.Error:
        raise HTTPException(status_code=503, detail="Database error")
    finally:
        conn.close()


def update_password_hash(schema: str, user_id, new_hash: str) -> None:
    """Transparent rehash to argon2id after a successful legacy verify.
    Deliberately does NOT touch password_changed_at — the password didn't
    change, so existing sessions must survive. Best-effort: the caller
    ignores failures and the next login retries."""
    conn = _connect()
    try:
        with conn, conn.cursor() as cur:
            query = sql.SQL(
                "UPDATE {}.users SET password_hash = %s WHERE id = %s"
            ).format(sql.Identifier(schema))
            cur.execute(query, (new_hash, user_id))
    finally:
        conn.close()


# %% Routes
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/token")
def token(req: TokenRequest, request: Request):
    schema = req.schema_
    if not SCHEMA_RE.match(schema):
        raise HTTPException(status_code=400, detail="Invalid schema name")

    keys = (f"user:{schema}:{req.username.lower()}", f"ip:{client_ip(request)}")
    remaining = login_limiter.locked_for(*keys)
    if remaining:
        raise HTTPException(
            status_code=429,
            detail=f"too many attempts — locked for {int(remaining // 60) + 1} more minute(s)",
        )

    row = fetch_user(schema, req.username)

    # Unknown usernames verify against a dummy hash so the reject path
    # always pays the KDF cost (no user enumeration by timing), and the
    # 401 reads the same either way. Disabled accounts also pay the cost
    # and reject identically.
    if row:
        ok = verify_password(req.password, row[2]) and not row[4]
    else:
        verify_password(req.password, DUMMY_HASH)
        ok = False
    if not ok:
        login_limiter.record_failure(*keys)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    login_limiter.record_success(*keys)

    if needs_rehash(row[2]):
        try:
            update_password_hash(schema, row[0], hash_password(req.password))
        except (HTTPException, psycopg2.Error):
            pass

    ttl = min(req.ttl_hours, MAX_TTL_HOURS) if req.ttl_hours else JWT_TTL_HOURS
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "role": f"{schema}_user",
        "user_id": str(row[0]),
        "username": row[1],
        "app_role": row[3],
        "iat": now,
        "exp": now + datetime.timedelta(hours=max(ttl, 1)),
    }
    return {"token": jwt.encode(payload, JWT_SECRET, algorithm="HS256")}
