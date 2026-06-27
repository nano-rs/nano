-- NAN-1581: move lookup-table ROW DATA from Postgres into ClickHouse.
--
-- Lookup tables (user-uploaded reference data joined into search/detection via
-- `@<name>` / `| lookup` / `inputlookup`) historically lived as one dynamically
-- CREATE'd Postgres table per lookup. This migration introduces a single, TALL,
-- SHARED ClickHouse table that holds the rows of EVERY lookup, partitioned only
-- logically by `lookup_table_name`. The lookup REGISTRY (names, columns,
-- primary key, row_count, size, creator) STAYS in Postgres — only the row data
-- moves here. There is intentionally NO table-per-lookup and NO runtime CH DDL:
-- this static table is created once by the migrator and therefore inherits the
-- cluster's Replicated / ON CLUSTER topology automatically (the migrator's
-- sql_transform rewrites `ReplacingMergeTree(version)` →
-- `ReplicatedReplacingMergeTree(...)` and injects `ON CLUSTER` on clustered /
-- Cloud deployments — see clickhouse_migrate/sql_transform.rs).
--
-- DEDUP MODEL (no FINAL on reads):
--   * `row_id` is an IMMUTABLE surrogate per logical row and is the dedup
--     identity — it is the ORDER BY trailing key. Editing a key CELL changes
--     `key_raw`/`key_lc` but NOT `row_id`, so an edit replaces the row rather
--     than spawning a duplicate (which keying dedup on `key_lc` would do).
--   * `version` is a strictly-monotonic, globally-unique snowflake generated
--     app-side (NOT now_ms — same-ms edits would tie and lose data under
--     ReplacingMergeTree). The app writes a new row at a higher version for
--     every insert/update; a delete writes a tombstone row (deleted=1) at a
--     higher version. Multi-writer-safe: version = (now_ms<<22)|(node_id<<12)|seq.
--   * Reads dedup WITHOUT FINAL via argMax over `version` grouped by `row_id`,
--     then filter `deleted = 0`:
--       SELECT row_id,
--              argMax(key_raw, version)  key_raw,
--              argMax(key_lc,  version)  key_lc,
--              argMax(cols_json,version) cols_json,
--              argMax(deleted, version)  d
--       FROM nanosiem.lookup_rows
--       WHERE lookup_table_name = ?
--       GROUP BY row_id
--       HAVING/ WHERE d = 0 [AND key_lc IN (...) | key_raw IN (...)]
--     FINAL is avoided because it forces a merge-on-read across the whole shared
--     table; the argMax/GROUP BY form prunes by `lookup_table_name` and is the
--     same pattern user_registry uses.
--
-- `key_lc` is a PLAIN column written app-side as lower(key_raw) (NOT
-- MATERIALIZED) so the case-insensitive read predicate `key_lc IN (...)` matches
-- the bloom skip-index EXPRESSION exactly (ClickHouse matches skip indexes by
-- expression). `cols_json` is the remaining (non-key) columns as a JSON object;
-- the repository decodes it against the registry's ColumnType definitions.
--
-- This migration only creates storage. The one-time PG→CH backfill and the
-- read-path consumer repoints (| lookup / inputlookup / ioc-in-lookup) ship in
-- later phases; the storage backend is selected at runtime by
-- LOOKUP_STORAGE_BACKEND (default: postgres), so creating this table is inert
-- until that flag flips.

CREATE TABLE IF NOT EXISTS nanosiem.lookup_rows
(
    lookup_table_name LowCardinality(String),
    row_id            UInt64,
    key_raw           String,
    key_lc            String,
    cols_json         String DEFAULT '{}',
    version           UInt64,
    deleted           UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (lookup_table_name, row_id)
SETTINGS index_granularity = 8192;

ALTER TABLE nanosiem.lookup_rows ADD INDEX IF NOT EXISTS idx_key_lc key_lc TYPE bloom_filter GRANULARITY 4;
