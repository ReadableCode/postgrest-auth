"""Verify a password against <schema>.users and mint the JWT PostgREST trusts.

The app calls login() in-process with its own Postgres connection (one that
can SELECT the users table and UPDATE password_hash; PostgREST deliberately
cannot reach it). The token carries role "<schema>_user", so PostgREST
switches into the app's role and its GRANTs and Row Level Security apply.

Unknown usernames verify against a dummy hash so the reject path always pays
the KDF cost (no user enumeration by timing), and the error is the same
either way. Disabled accounts also pay the cost and reject identically.
"""

import datetime
import re
from collections.abc import Callable

import jwt

from .limiter import LoginRateLimiter
from .passwords import DUMMY_HASH, hash_password, needs_rehash, verify_password

DEFAULT_TTL_HOURS = 24
MAX_TTL_HOURS = 720  # 30 days, the longest session any app runs

# The schema picks both the users table ("<schema>.users") and the role claim
# ("<schema>_user"). It is interpolated into SQL as an identifier, so it must
# match this allowlist.
SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

# One limiter per process, shared by every login() call that doesn't pass
# its own.
default_limiter = LoginRateLimiter()


class InvalidCredentials(Exception):
    """Wrong password, unknown user, or disabled account. Deliberately one
    error for all three."""


class LoginLocked(Exception):
    """The username or the client IP is locked out."""

    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(
            f"too many attempts — locked for {int(retry_after // 60) + 1} more minute(s)")


def _users_table(schema: str) -> str:
    if not SCHEMA_RE.match(schema):
        raise ValueError(f"invalid schema name: {schema!r}")
    return f'"{schema}".users'


def fetch_user(connect: Callable, schema: str, username: str) -> tuple | None:
    """(id, username, password_hash, role, disabled) from <schema>.users, or
    None. The username comes back in its stored casing so token claims are
    canonical. Database errors propagate to the caller."""
    table = _users_table(schema)
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(
            f"SELECT id, username, password_hash, role, disabled FROM {table} "
            "WHERE username = %s",
            (username,),
        )
        row = cur.fetchone()
        conn.rollback()
        return row
    finally:
        conn.close()


def update_password_hash(connect: Callable, schema: str, user_id, new_hash: str) -> None:
    """Rehash to argon2id after a successful legacy verify. Deliberately does
    NOT touch password_changed_at: the password didn't change, so existing
    sessions must survive."""
    table = _users_table(schema)
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE {table} SET password_hash = %s WHERE id = %s", (new_hash, user_id))
        conn.commit()
    finally:
        conn.close()


def mint_token(schema: str, user_id, username: str, app_role: str, *,
               jwt_secret: str, ttl_hours: int | None = None) -> str:
    """HS256 JWT with role/user_id/username/app_role/iat/exp. ttl_hours
    defaults to DEFAULT_TTL_HOURS and is clamped to MAX_TTL_HOURS."""
    _users_table(schema)
    ttl = min(ttl_hours, MAX_TTL_HOURS) if ttl_hours else DEFAULT_TTL_HOURS
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "role": f"{schema}_user",
        "user_id": str(user_id),
        "username": username,
        "app_role": app_role,
        "iat": now,
        "exp": now + datetime.timedelta(hours=max(ttl, 1)),
    }
    return jwt.encode(payload, jwt_secret, algorithm="HS256")


def login(connect: Callable, schema: str, username: str, password: str, *,
          jwt_secret: str, client_ip: str | None = None,
          limiter: LoginRateLimiter | None = None,
          ttl_hours: int | None = None) -> str:
    """Return a signed token, or raise LoginLocked / InvalidCredentials.

    connect: zero-argument callable returning a DB-API connection (psycopg2
    or psycopg) that can read <schema>.users and update password_hash.
    client_ip: the browser's IP, for the per-IP lockout key.
    """
    limiter = limiter or default_limiter
    _users_table(schema)
    keys = [f"user:{schema}:{username.lower()}"]
    if client_ip:
        keys.append(f"ip:{client_ip}")
    remaining = limiter.locked_for(*keys)
    if remaining:
        raise LoginLocked(remaining)

    row = fetch_user(connect, schema, username)
    if row:
        ok = verify_password(password, row[2]) and not row[4]
    else:
        verify_password(password, DUMMY_HASH)
        ok = False
    if not ok:
        limiter.record_failure(*keys)
        raise InvalidCredentials("invalid username or password")
    limiter.record_success(*keys)

    if needs_rehash(row[2]):
        try:
            update_password_hash(connect, schema, row[0], hash_password(password))
        except Exception:
            # best-effort: the next login retries
            pass

    return mint_token(schema, row[0], row[1], row[3], jwt_secret=jwt_secret, ttl_hours=ttl_hours)
