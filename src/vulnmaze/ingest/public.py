"""Load public Cowrie datasets into the same schema as live data.

Most public sets are Cowrie JSON lines, often gzipped, one file per day, e.g.
the CyberLab honeynet dataset (Zenodo 3687527) and COW160x4 (Zenodo
21260400). They go through exactly the same normalise/de-identify/digest path
as live data, tagged with source='public:<name>'.

    vulnmaze-load-public --name cyberlab /data/cyberlab/*.json.gz

Older Cowrie versions use slightly different field names; ALIASES maps them.
Extend ALIASES when a dataset fails to load.
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
from collections.abc import Iterator

import psycopg

from vulnmaze.common.deid import Deidentifier
from vulnmaze.db import apply_schema, dsn_from_env
from vulnmaze.ingest.pipeline import Ingestor

log = logging.getLogger("vulnmaze.public")

# old field name -> current Cowrie field name. Empty until a dataset needs it;
# check a few lines of each new dataset and add what differs.
ALIASES: dict[str, str] = {}


def _open(path: str):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.endswith(".gz") else \
        open(path, encoding="utf-8", errors="replace")


def iter_events(path: str) -> Iterator[str]:
    """Yield raw JSON lines, rewriting aliased field names. Handles both
    JSON-lines files and files holding one JSON array."""
    with _open(path) as fh:
        first = fh.read(1)
        fh.seek(0)
        if first == "[":
            records = json.load(fh)
        else:
            records = []  # placeholder so the loop below handles both shapes
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    yield line          # the ingester records it in ingest_errors
                    continue
                yield from _rewrite(rec)
        for rec in records:
            yield from _rewrite(rec)


def _rewrite(rec) -> Iterator[str]:
    if isinstance(rec, dict):
        for old, new in ALIASES.items():
            if old in rec and new not in rec:
                rec[new] = rec.pop(old)
        yield json.dumps(rec, sort_keys=True)


def load(conn: psycopg.Connection, name: str, paths: list[str], deid: Deidentifier, batch: int = 5000) -> dict:
    ingestor = Ingestor(conn, deid, source=f"public:{name}")
    for path in paths:
        buf: list[str] = []
        for line in iter_events(path):
            buf.append(line)
            if len(buf) >= batch:
                with conn.transaction():
                    ingestor.ingest_lines(buf)
                buf.clear()
        if buf:
            with conn.transaction():
                ingestor.ingest_lines(buf)
        log.info("%s: %s", os.path.basename(path), ingestor.stats)
    return ingestor.stats


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="dataset tag, stored as source='public:<name>'")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    with psycopg.connect(dsn_from_env()) as conn:
        apply_schema(conn)
        print(load(conn, args.name, sorted(args.paths), Deidentifier.from_env()))


if __name__ == "__main__":
    main()
