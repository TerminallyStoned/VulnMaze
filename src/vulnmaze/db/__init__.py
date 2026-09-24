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


def apply_schema(conn: psycopg.Connection) -> None:
    with conn.transaction():
        conn.execute(schema_sql())
