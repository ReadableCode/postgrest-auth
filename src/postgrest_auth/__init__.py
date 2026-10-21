"""Login for apps that serve their data through PostgREST.

Each app keeps its own <schema>.users table and calls login() in-process to
verify a password and mint the JWT PostgREST trusts. See README.md.
"""

from .limiter import LoginRateLimiter, client_ip
from .login import (
    DEFAULT_TTL_HOURS,
    MAX_TTL_HOURS,
    InvalidCredentials,
    LoginLocked,
    login,
    mint_token,
)
from .passwords import hash_password, needs_rehash, verify_password

__all__ = [
    "DEFAULT_TTL_HOURS",
    "MAX_TTL_HOURS",
    "InvalidCredentials",
    "LoginLocked",
    "LoginRateLimiter",
    "client_ip",
    "hash_password",
    "login",
    "mint_token",
    "needs_rehash",
    "verify_password",
]
