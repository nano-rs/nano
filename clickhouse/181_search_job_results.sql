-- Migration: durable search background job results (NAN-4915).
--
-- WHY THIS EXISTS
-- ---------------
-- Background search jobs (PostgreSQL `search_jobs`, migration 291) keep their
-- metadata and lease state in PostgreSQL, but a result set can be tens of
-- thousands of rows. PostgreSQL stays metadata-only; the rows land here so an
-- analyst can page through a finished background search ("continuation")
-- without re-running it, from any search replica, after a restart.
--
-- SHAPE
-- -----
-- One row per result row. `row` is the JSON object the search API would have
-- returned for that row, verbatim, so paging a job returns byte-identical rows
-- to the interactive path for every query shape (raw events, stats, eval,
-- prevalence, lookups — including Rust-side pipeline stages).
--
-- `attempt` fences restarts: a job whose worker died mid-insert is re-run as a
-- new attempt, and PostgreSQL `search_jobs.result_attempt` names the attempt
-- whose rows are the result. Rows of an abandoned attempt are never read and
-- age out with the TTL. Nothing ever UPDATEs or DELETEs here.
--
-- ACCESS
-- ------
-- Written and read only by the nanosiem-search runtime user (`nanosiem`, which
-- already holds SELECT+INSERT on nanosiem.* — no grant change is needed). Every
-- read is authorized in the application first (owner or admin, search:execute,
-- source-scope re-check against the job's stamp). The raw-SQL feature users
-- (`nanosiem_rawsql*`) have table-scoped SELECT allowlists and are deliberately
-- NOT granted this table: raw SQL must never be able to read another user's
-- job results.
--
-- RETENTION
-- ---------
-- 24 hours, matching `search_jobs.expires_at`. `ttl_only_drop_parts` drops whole
-- parts instead of rewriting them: each job writes its own parts in a short
-- burst, so parts expire whole and the TTL costs no merge I/O.
--
-- CLUSTERS
-- --------
-- Listed in `dual_pool::DISTRIBUTED_TABLES`: on a sharded cluster the reconciler
-- creates `search_job_results_distributed`, reads route through it (so a page
-- is found regardless of which shard the worker's INSERT landed on), and writes
-- target the local table.

CREATE TABLE IF NOT EXISTS nanosiem.search_job_results
(
    `job_id` String,
    `attempt` UInt32,
    `seq` UInt64,
    `row` String CODEC(ZSTD(3)),
    `created_at` DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(created_at)
ORDER BY (job_id, attempt, seq)
TTL created_at + toIntervalHour(24)
SETTINGS index_granularity = 1024, ttl_only_drop_parts = 1;
