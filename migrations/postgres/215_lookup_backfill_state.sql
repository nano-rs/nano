-- NAN-1581 Phase 2/3: PG→ClickHouse lookup row-data backfill bookkeeping.
--
-- When LOOKUP_STORAGE_BACKEND flips to `clickhouse`, the api boot path runs a
-- ONE-TIME backfill that copies every existing Postgres `lookup_<name>` table's
-- rows into the shared ClickHouse `lookup_rows` table (lookup data has no
-- upstream re-sync, so it must be migrated without loss).
--
-- The api runs multi-replica, so the backfill is guarded by THIS small table:
--   * A single sentinel row (table_name = '*') is claimed transactionally via
--     `INSERT ... ON CONFLICT DO NOTHING` — only the pod that inserts the claim
--     row runs the backfill; the others see the row already present and skip.
--   * One row per logical lookup table records a per-table DONE marker so a
--     partial / crashed backfill resumes only the remaining tables on the next
--     boot (a table already marked done is skipped — its rows are already in
--     ClickHouse and re-copying would only bump ReplacingMergeTree versions).
--
-- `state` is one of: 'claimed' (the global lock holder), 'done' (per-table
-- completion). `pg_count` / `ch_count` capture the post-copy verification so a
-- count mismatch is auditable rather than silently passed.

CREATE TABLE IF NOT EXISTS lookup_backfill_state (
    -- '*' is the global claim sentinel; otherwise the logical lookup table name.
    table_name  TEXT PRIMARY KEY,
    state       TEXT NOT NULL,
    pg_count    BIGINT,
    ch_count    BIGINT,
    claimed_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
