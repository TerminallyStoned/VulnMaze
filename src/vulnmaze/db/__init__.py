from __future__ import annotations

import os
from importlib import resources

import psycopg


def dsn_from_env(var: str = "VULNMAZE_DSN") -> str:
    dsn = os.environ.get(var)
    if not dsn:
        raise RuntimeError(f"{var} is not set")
    return dsn


def schema_sql() -> str:
    return resources.files("vulnmaze.db").joinpath("schema.sql").read_text()


def check_encoding(conn: psycopg.Connection) -> None:
    """The schema stores attacker text and model output as JSONB. In a
    non-UTF8 database (e.g. SQL_ASCII) Postgres rejects non-ASCII JSON escapes
    and psycopg returns text as bytes, which fails far from the cause."""
    enc = conn.execute("SHOW server_encoding").fetchone()[0]
    if enc != "UTF8":
        raise RuntimeError(
            f"database encoding is {enc}, VulnMaze needs UTF8. "
            "Create it with: CREATE DATABASE vulnmaze ENCODING 'UTF8' TEMPLATE template0;"
        )


def apply_schema(conn: psycopg.Connection) -> None:
    check_encoding(conn)
    with conn.transaction():
        conn.execute(schema_sql())
