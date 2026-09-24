"""Live ingester: tail Cowrie's JSON log into PostgreSQL.

Run inside the `ingester` container:

    VULNMAZE_DSN=postgresql://... VULNMAZE_DEID_KEY=<hex> \\
    VULNMAZE_COWRIE_JSON=/cowrie-logs/cowrie.json vulnmaze-ingest
"""

from __future__ import annotations

import logging
import os
import signal
import time

import psycopg

from vulnmaze.common.deid import Deidentifier
from vulnmaze.db import apply_schema, dsn_from_env
from vulnmaze.ingest.pipeline import Ingestor
from vulnmaze.ingest.tailer import Checkpoint, FileTailer

log = logging.getLogger("vulnmaze.ingest")


def load_checkpoint(conn: psycopg.Connection, path: str) -> Checkpoint | None:
    row = conn.execute('SELECT inode, "offset" FROM ingest_checkpoints WHERE path=%s', (path,)).fetchone()
    return Checkpoint(*row) if row else None


def save_checkpoint(conn: psycopg.Connection, path: str, cp: Checkpoint) -> None:
    conn.execute(
        """INSERT INTO ingest_checkpoints (path, inode, "offset", updated_at) VALUES (%s, %s, %s, now())
           ON CONFLICT (path) DO UPDATE SET inode=EXCLUDED.inode, "offset"=EXCLUDED."offset", updated_at=now()""",
        (path, cp.inode, cp.offset),
    )


def run(dsn: str, path: str, deid: Deidentifier, poll_s: float = 0.5, stop=lambda: False) -> None:
    with psycopg.connect(dsn) as conn:
        apply_schema(conn)
        tailer = FileTailer(path, load_checkpoint(conn, path))
        ingestor = Ingestor(conn, deid, source="live")
        log.info("tailing %s", path)
        while not stop():
            lines = tailer.poll()
            if not lines:
                time.sleep(poll_s)
                continue
            with conn.transaction():
                n = ingestor.ingest_lines(lines)
                cp = tailer.checkpoint
                if cp:
                    save_checkpoint(conn, path, cp)
            log.info("ingested %d new events (%s)", n, ingestor.stats)


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    deid = Deidentifier.from_env()          # fails closed if the key is missing
    stopping = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stopping.__setitem__("flag", True))
    run(
        dsn_from_env(),
        os.environ.get("VULNMAZE_COWRIE_JSON", "/cowrie-logs/cowrie.json"),
        deid,
        stop=lambda: stopping["flag"],
    )


if __name__ == "__main__":
    main()
