"""HTTP front for the state store, on the internal network only.

The LLM gateway is its first client. It is never published to the
host or reachable from the honeypot network.

    uvicorn vulnmaze.state.api:app --host 0.0.0.0 --port 8081
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

from vulnmaze.common.deid import Deidentifier
from vulnmaze.db import apply_schema, dsn_from_env
from vulnmaze.state.store import StateStore

_pool: ConnectionPool | None = None
_deid: Deidentifier | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _pool, _deid
    _deid = Deidentifier.from_env()
    _pool = ConnectionPool(dsn_from_env(), open=True, min_size=1, max_size=int(os.environ.get("POOL_MAX", "10")),
                           kwargs={"autocommit": True})
    with _pool.connection() as conn:
        apply_schema(conn)
    yield
    _pool.close()


app = FastAPI(title="VulnMaze state store", lifespan=lifespan)


def require_token(authorization: str = Header(default="")) -> None:
    expected = os.environ.get("VULNMAZE_STATE_TOKEN")
    if not expected or authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="unauthorised")


class CreateBody(BaseModel):
    value: Any
    created_by: str = Field(default="unknown", max_length=100)


def _fact_json(f) -> dict:
    return {"fact": f.fact, "value": f.value, "created_by": f.created_by, "created": f.created}


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/v1/attackers/{src_ip}/{username}/facts", dependencies=[Depends(require_token)])
def list_facts(src_ip: str, username: str, prefix: str = "") -> list[dict]:
    with _pool.connection() as conn:
        return [_fact_json(f) for f in StateStore(conn, _deid).list(src_ip, username, prefix)]


@app.get("/v1/attackers/{src_ip}/{username}/facts/{fact:path}", dependencies=[Depends(require_token)])
def get_fact(src_ip: str, username: str, fact: str) -> dict:
    with _pool.connection() as conn:
        f = StateStore(conn, _deid).get(src_ip, username, fact)
    if f is None:
        raise HTTPException(status_code=404, detail="no such fact")
    return _fact_json(f)


@app.put("/v1/attackers/{src_ip}/{username}/facts/{fact:path}", dependencies=[Depends(require_token)])
def create_fact(src_ip: str, username: str, fact: str, body: CreateBody) -> dict:
    """Create-if-absent. 201-style semantics are in the body: created=true
    only for the request that wrote the fact."""
    with _pool.connection() as conn:
        try:
            f = StateStore(conn, _deid).create_if_absent(src_ip, username, fact, body.value, body.created_by)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _fact_json(f)
