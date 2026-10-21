"""Password hashing.

argon2id is the standard. Stored hashes are self-identifying by prefix, so
bcrypt hashes from before the argon2id migration still verify ($2* ->
bcrypt) and are rehashed to argon2id on the next successful login (see
login.py), so nobody resets a password. Until a legacy user logs in once,
their reject path pays bcrypt cost instead of argon2 cost; that only
distinguishes "known bcrypt-era user" from "unknown user" and disappears as
rehashes land.
"""

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# Verified for unknown usernames so the reject path always pays the argon2
# cost. Never compare against it with a real password expecting a match.
DUMMY_HASH = _hasher.hash("postgrest-auth-dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Prefix-dispatched verify: $2* -> bcrypt (legacy), else argon2id."""
    if stored_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except ValueError:
            return False
    try:
        _hasher.verify(stored_hash, password)
        return True
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True for bcrypt (migrate to argon2id) or outdated argon2 params."""
    if not stored_hash.startswith("$argon2"):
        return True
    return _hasher.check_needs_rehash(stored_hash)
