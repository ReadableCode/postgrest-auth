"""login(): per-user + per-IP lockout, non-enumerable rejects, success
resetting the counter, argon2id/bcrypt prefix dispatch with transparent
rehash, disabled accounts, token claims and TTL clamping. The users table is
a fake DB-API connection, so no Postgres is needed."""

import bcrypt
import jwt
import pytest
from argon2 import PasswordHasher

import postgrest_auth
from postgrest_auth import InvalidCredentials, LoginLocked, LoginRateLimiter

SECRET = "test-secret-at-least-32-bytes-long!!"
PASSWORD = "correct-horse"
ARGON_HASH = PasswordHasher().hash(PASSWORD)
BCRYPT_HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
USER_ID = "11111111-1111-1111-1111-111111111111"


class FakeDB:
    """Stands in for a psycopg2 connection to <schema>.users."""

    def __init__(self, password_hash=ARGON_HASH, role="user", disabled=False):
        self.row = [USER_ID, "jason", password_hash, role, disabled]
        self.updates = []
        self.queries = []

    def connect(self):
        return _Conn(self)


class _Conn:
    def __init__(self, db):
        self.db = db
        self._result = None

    def cursor(self):
        return self

    def execute(self, query, params):
        self.db.queries.append(query)
        if query.startswith("SELECT"):
            self._result = tuple(self.db.row) if params[0] == "jason" else None
        else:
            self.db.updates.append(params)
            self.db.row[2] = params[0]

    def fetchone(self):
        return self._result

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture()
def db():
    return FakeDB()


@pytest.fixture()
def limiter():
    return LoginRateLimiter()


def _login(db, limiter, username, password, ip="1.2.3.4", **extra):
    return postgrest_auth.login(
        db.connect, "acme", username, password,
        jwt_secret=SECRET, client_ip=ip, limiter=limiter, **extra)


def _claims(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def test_login_success(db, limiter):
    assert _login(db, limiter, "jason", PASSWORD)


def test_token_claims(db, limiter):
    payload = _claims(_login(db, limiter, "jason", PASSWORD))
    assert payload["role"] == "acme_user"
    assert payload["user_id"] == USER_ID
    assert payload["username"] == "jason"
    assert payload["app_role"] == "user"
    assert payload["iat"] <= payload["exp"]


def test_ttl_hours_respected_and_clamped(db, limiter):
    default = _claims(_login(db, limiter, "jason", PASSWORD))
    long = _claims(_login(db, limiter, "jason", PASSWORD, ttl_hours=720))
    over = _claims(_login(db, limiter, "jason", PASSWORD, ttl_hours=9999))
    assert default["exp"] - default["iat"] == postgrest_auth.DEFAULT_TTL_HOURS * 3600
    assert long["exp"] - long["iat"] == 720 * 3600
    assert over["exp"] - over["iat"] == 720 * 3600


def test_schema_is_quoted_identifier(db, limiter):
    _login(db, limiter, "jason", PASSWORD)
    assert 'FROM "acme".users' in db.queries[0]


def test_legacy_bcrypt_verifies_and_rehashes():
    db = FakeDB(password_hash=BCRYPT_HASH)
    assert _login(db, LoginRateLimiter(), "jason", PASSWORD)
    new_hash, user_id = db.updates[0]
    assert user_id == USER_ID
    assert new_hash.startswith("$argon2")
    # the new hash verifies the same password: nobody resets anything
    PasswordHasher().verify(new_hash, PASSWORD)


def test_argon2_hash_not_rehashed(db, limiter):
    _login(db, limiter, "jason", PASSWORD)
    assert db.updates == []


def test_failed_rehash_does_not_block_login(limiter):
    db = FakeDB(password_hash=BCRYPT_HASH)

    class Broken(_Conn):
        def execute(self, query, params):
            if query.startswith("UPDATE"):
                raise RuntimeError("db hiccup")
            super().execute(query, params)

    db.connect = lambda: Broken(db)
    assert _login(db, limiter, "jason", PASSWORD)


def test_disabled_account_rejects_like_bad_password(limiter):
    db = FakeDB(disabled=True)
    with pytest.raises(InvalidCredentials) as disabled:
        _login(db, limiter, "jason", PASSWORD)
    with pytest.raises(InvalidCredentials) as unknown:
        _login(db, limiter, "nobody", PASSWORD)
    assert str(disabled.value) == str(unknown.value)


def test_wrong_password_and_unknown_user_read_the_same(db, limiter):
    with pytest.raises(InvalidCredentials) as wrong:
        _login(db, limiter, "jason", "nope-nope-nope")
    with pytest.raises(InvalidCredentials) as unknown:
        _login(db, limiter, "nobody", "nope-nope-nope")
    assert str(wrong.value) == str(unknown.value)


def test_lockout_per_username(db, limiter):
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            _login(db, limiter, "jason", "wrong", ip="1.2.3.4")
    # locked even from a different IP: the username key tripped
    with pytest.raises(LoginLocked) as locked:
        _login(db, limiter, "jason", PASSWORD, ip="5.6.7.8")
    assert "locked" in str(locked.value)
    assert locked.value.retry_after > 0


def test_lockout_per_ip(db, limiter):
    for i in range(5):
        with pytest.raises(InvalidCredentials):
            _login(db, limiter, f"user{i}", "wrong", ip="9.9.9.9")
    # same IP is locked even for a fresh, valid account
    with pytest.raises(LoginLocked):
        _login(db, limiter, "jason", PASSWORD, ip="9.9.9.9")
    # but another IP + untouched username is unaffected
    assert _login(db, limiter, "jason", PASSWORD, ip="8.8.8.8")


def test_success_resets_failure_count(db, limiter):
    for _ in range(4):
        with pytest.raises(InvalidCredentials):
            _login(db, limiter, "jason", "wrong")
    assert _login(db, limiter, "jason", PASSWORD)
    # counter reset: four more failures still don't lock
    for _ in range(4):
        with pytest.raises(InvalidCredentials):
            _login(db, limiter, "jason", "wrong")
    assert _login(db, limiter, "jason", PASSWORD)


def test_login_without_client_ip_uses_username_key_only(db, limiter):
    for _ in range(5):
        with pytest.raises(InvalidCredentials):
            _login(db, limiter, "jason", "wrong", ip=None)
    with pytest.raises(LoginLocked):
        _login(db, limiter, "jason", PASSWORD, ip=None)


def test_bad_schema_rejected(db, limiter):
    with pytest.raises(ValueError):
        postgrest_auth.login(db.connect, 'bad"schema', "jason", PASSWORD,
                             jwt_secret=SECRET, limiter=limiter)
    assert db.queries == []


def test_mint_token_matches_login_claims():
    token = postgrest_auth.mint_token("acme", USER_ID, "jason", "admin", jwt_secret=SECRET, ttl_hours=2)
    payload = _claims(token)
    assert payload["role"] == "acme_user"
    assert payload["app_role"] == "admin"
    assert payload["exp"] - payload["iat"] == 2 * 3600


def test_client_ip_prefers_first_forwarded_hop():
    assert postgrest_auth.client_ip("203.0.113.5, 10.0.0.1", "10.0.0.2") == "203.0.113.5"
    assert postgrest_auth.client_ip(None, "10.0.0.2") == "10.0.0.2"
    assert postgrest_auth.client_ip("", None) == "unknown"


def test_hash_roundtrip():
    stored = postgrest_auth.hash_password(PASSWORD)
    assert stored.startswith("$argon2id$")
    assert postgrest_auth.verify_password(PASSWORD, stored)
    assert not postgrest_auth.verify_password("other", stored)
    assert not postgrest_auth.needs_rehash(stored)
    assert postgrest_auth.needs_rehash(BCRYPT_HASH)
