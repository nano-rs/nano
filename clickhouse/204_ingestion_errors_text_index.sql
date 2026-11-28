-- NAN-5919 (ClickHouse best-practices gap G11): replace the deprecated
-- tokenbf_v1 index on ingestion_errors.error_message with a text index.
--
-- tokenbf_v1 is deprecated from ClickHouse 26.2 in favor of the `text` index
-- type (nano pins 26.10). The event tables already moved in migrations 119 and
-- 120; ingestion_errors was the last tokenbf_v1 left in the schema.
--
-- The new index follows the migration 119 convention: a splitByNonAlpha text
-- index over lower(error_message). ClickHouse matches skip indexes by
-- EXPRESSION, so it serves the case-insensitive forms an operator writes when
-- hunting failed rows:
--   lower(error_message) LIKE '%timeout%'
--   hasToken(lower(error_message), 'timeout')
--   lower(error_message) = '<exact message>'
-- A predicate on the raw column (error_message LIKE ...) never used the old
-- bloom for substring search either, so nothing loses pruning.
--
-- No MATERIALIZE INDEX: ingestion_errors keeps 90 days and nothing in the app
-- filters it by message, so existing parts are left as they are (they are read
-- in full, as before, until TTL drops them) and new parts get the index on
-- insert and merge. That keeps this migration DDL only, with no mutation that
-- rewrites data. DROP INDEX on its own still queues a small mutation to remove
-- the old index files, so it runs with mutations_sync = 0 (returns at once,
-- same as migration 120).
--
-- Cluster installs: the migrator adds ON CLUSTER to both ALTERs and they run
-- on the physical table (`ingestion_errors`; the `_distributed` wrapper holds
-- no indexes). The legacy deploy/scripts/init-clickhouse-cluster.sh path
-- renames the target to `ingestion_errors_local` the same way. Both ALTERs are
-- idempotent (IF EXISTS / IF NOT EXISTS), so a re-run converges.
--
-- clickhouse/init.sql now creates the same index directly, so a fresh install
-- never has tokenbf_v1; this file is then a no-op there.

ALTER TABLE nanosiem.ingestion_errors DROP INDEX IF EXISTS idx_error_message
    SETTINGS mutations_sync = 0;

ALTER TABLE nanosiem.ingestion_errors ADD INDEX IF NOT EXISTS idx_error_message_words
    lower(error_message) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
