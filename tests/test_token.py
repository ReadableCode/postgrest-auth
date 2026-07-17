# %% Imports
"""Hardening tests for /token: per-user + per-IP lockout, non-enumerable
401s, success resetting the counter, and security headers. fetch_user is
monkeypatched so no Postgres is needed."""

import os

import bcrypt
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("POSTGRES_URL", "unused")
os.environ.setdefault("POSTGRES_USER", "unused")
os.environ.setdefault("POSTGRES_PASSWORD", "unused")
os.environ.setdefault("JWT_SECRET", "test-secret")

import main  # noqa: E402  (env must be set before the module reads it)
from security import LoginRateLimiter  # noqa: E402

PASSWORD = "correct-horse"
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()


@pytest.fixture()
def client(monkeypatch):
    def fake_fetch_user(schema, username):
        return ("11111111-1111-1111-1111-111111111111", HASH) if username == "jason" else None

    monkeypatch.setattr(main, "fetch_user", fake_fetch_user)
    monkeypatch.setattr(main, "login_limiter", LoginRateLimiter())
    return TestClient(main.app)


def _token(client, username, password, ip="1.2.3.4"):
    return client.post(
        "/token",
        json={"schema": "load_log", "username": username, "password": password},
        headers={"X-Forwarded-For": ip},
    )


def test_login_success(client):
    resp = _token(client, "jason", PASSWORD)
    assert resp.status_code == 200
    assert resp.json()["token"]


def test_wrong_password_and_unknown_user_read_the_same(client):
    wrong = _token(client, "jason", "nope-nope-nope")
    unknown = _token(client, "nobody", "nope-nope-nope")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_lockout_per_username(client):
    for _ in range(5):
        assert _token(client, "jason", "wrong", ip="1.2.3.4").status_code == 401
    # locked even from a different IP: the username key tripped
    resp = _token(client, "jason", PASSWORD, ip="5.6.7.8")
    assert resp.status_code == 429
    assert "locked" in resp.json()["detail"]


def test_lockout_per_ip(client):
    for i in range(5):
        assert _token(client, f"user{i}", "wrong", ip="9.9.9.9").status_code == 401
    # same IP is locked even for a fresh, valid account
    assert _token(client, "jason", PASSWORD, ip="9.9.9.9").status_code == 429
    # but another IP + untouched username is unaffected
    assert _token(client, "jason", PASSWORD, ip="8.8.8.8").status_code == 200


def test_success_resets_failure_count(client):
    for _ in range(4):
        _token(client, "jason", "wrong")
    assert _token(client, "jason", PASSWORD).status_code == 200
    # counter reset: four more failures still don't lock
    for _ in range(4):
        assert _token(client, "jason", "wrong").status_code == 401
    assert _token(client, "jason", PASSWORD).status_code == 200


def test_bad_schema_rejected(client):
    resp = client.post(
        "/token",
        json={"schema": 'bad"schema', "username": "x", "password": "y"},
    )
    assert resp.status_code == 400


def test_security_headers_present(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
