# %% Imports
import datetime
import os
import re

import bcrypt
import jwt
import psycopg2
from psycopg2 import sql
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

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

# A request's schema picks both the users table ("<schema>.users") and the role
# claim ("<schema>_user"). It is interpolated into SQL as an identifier, so it
# must be validated against a strict allowlist to prevent injection.
SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

app = FastAPI(title="postgrest-auth")


# %% Models
class TokenRequest(BaseModel):
    # Field is named `schema_` to avoid shadowing pydantic's BaseModel.schema;
    # the wire/body key is still "schema".
    schema_: str = Field(alias="schema")
    username: str
    password: str

    model_config = {"populate_by_name": True}


# %% Routes
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/token")
def token(req: TokenRequest):
    schema = req.schema_
    if not SCHEMA_RE.match(schema):
        raise HTTPException(status_code=400, detail="Invalid schema name")

    try:
        conn = psycopg2.connect(
            host=POSTGRES_URL,
            port=POSTGRES_PORT,
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
        )
    except psycopg2.Error:
        raise HTTPException(status_code=503, detail="Database unavailable")

    try:
        with conn, conn.cursor() as cur:
            query = sql.SQL(
                "SELECT id, password_hash FROM {}.users WHERE username = %s"
            ).format(sql.Identifier(schema))
            cur.execute(query, (req.username,))
            row = cur.fetchone()
    except psycopg2.errors.UndefinedTable:
        raise HTTPException(status_code=400, detail="Unknown schema")
    except psycopg2.Error:
        raise HTTPException(status_code=503, detail="Database error")
    finally:
        conn.close()

    if not row or not bcrypt.checkpw(req.password.encode(), row[1].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    payload = {
        "role": f"{schema}_user",
        "user_id": str(row[0]),
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=JWT_TTL_HOURS),
    }
    return {"token": jwt.encode(payload, JWT_SECRET, algorithm="HS256")}
