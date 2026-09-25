-- VulnMaze schema (applied idempotently).
-- Nothing in this database holds a raw IP address or a plaintext password.

CREATE TABLE IF NOT EXISTS events (
    id             BIGSERIAL PRIMARY KEY,
    event_hash     BYTEA       NOT NULL UNIQUE,      -- sha256 of the raw line: idempotent ingest
    source         TEXT        NOT NULL,             -- 'live' or 'public:<name>'
    sensor         TEXT,
    session        TEXT        NOT NULL,
    eventid        TEXT        NOT NULL,
    ts             TIMESTAMPTZ NOT NULL,
    src_ip_hmac    TEXT,
    src_prefix     CIDR,
    username       TEXT,
    password_hmac  TEXT,
    password_len   INTEGER,
    input          TEXT,
    data           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_session_idx ON events (source, session, ts, id);
CREATE INDEX IF NOT EXISTS events_eventid_ts_idx ON events (eventid, ts);
CREATE INDEX IF NOT EXISTS events_attacker_idx ON events (src_ip_hmac);

CREATE TABLE IF NOT EXISTS session_digests (
    source      TEXT        NOT NULL,
    session     TEXT        NOT NULL,
    digest      JSONB       NOT NULL,
    closed      BOOLEAN     NOT NULL DEFAULT false,
    n_events    INTEGER     NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, session)
);
CREATE INDEX IF NOT EXISTS session_digests_open_idx ON session_digests (closed, updated_at);

CREATE TABLE IF NOT EXISTS ingest_checkpoints (
    path        TEXT PRIMARY KEY,
    inode       BIGINT NOT NULL,
    "offset"    BIGINT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ingest_errors (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT NOT NULL,
    error       TEXT NOT NULL,
    line_sha256 BYTEA,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-attacker state store. Write-once: a fact is never updated.
CREATE TABLE IF NOT EXISTS attacker_facts (
    attacker_key  TEXT        NOT NULL,   -- HMAC of the source IP
    username      TEXT        NOT NULL,
    fact          TEXT        NOT NULL,   -- e.g. 'file:/home/bob/notes.txt', 'user:bob', 'banner:mysql'
    value         JSONB       NOT NULL,
    created_by    TEXT        NOT NULL DEFAULT 'unknown',   -- 'cowrie', 'llm:<model>', 'honeytoken'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (attacker_key, username, fact)
);

-- Enforce write-once in the database itself, not only in application code.
CREATE OR REPLACE FUNCTION attacker_facts_write_once() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'attacker_facts is write-once (fact % for %/%)', OLD.fact, OLD.attacker_key, OLD.username;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS attacker_facts_no_update ON attacker_facts;
CREATE TRIGGER attacker_facts_no_update
    BEFORE UPDATE ON attacker_facts
    FOR EACH ROW EXECUTE FUNCTION attacker_facts_write_once();

-- One row per request the LLM gateway handled: latency, cost and safety metrics.
CREATE TABLE IF NOT EXISTS llm_calls (
    id                 BIGSERIAL PRIMARY KEY,
    ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    session            TEXT,
    attacker_key       TEXT,
    username           TEXT,
    command            TEXT        NOT NULL,   -- argv joined, attacker IP redacted
    outcome            TEXT        NOT NULL,   -- generated | pinned | not_installed | refused | fallback
    reasons            TEXT[]      NOT NULL DEFAULT '{}',
    attempts           SMALLINT    NOT NULL DEFAULT 0,
    model              TEXT,
    latency_ms         INTEGER     NOT NULL,   -- total time in the gateway
    model_ms           INTEGER,                -- time spent waiting for the model
    prompt_tokens      INTEGER,
    completion_tokens  INTEGER,
    rejected_output    TEXT                    -- first rejected model output (for leak/fabrication analysis)
);
CREATE INDEX IF NOT EXISTS llm_calls_ts_idx ON llm_calls (ts);
CREATE INDEX IF NOT EXISTS llm_calls_outcome_idx ON llm_calls (outcome, ts);
