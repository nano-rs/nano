-- Migration: synthetic-check probe results (NAN-1538).
--
-- WHAT THIS IS
-- ------------
-- The Observability console's synthetic monitoring stores its check
-- *definitions* in PostgreSQL (`observability_synthetic_checks`, migration
-- 210). The probe *results* — one row per executed probe — land here.
--
-- Unlike the OCSF/otel lanes there is NO Null staging table + derivation MV:
-- the nanosiem-jobs synthetics runner executes each due HTTP check and writes
-- the result row directly (a single INSERT per probe), so a plain MergeTree is
-- all that's needed. Reads are always scoped to one or a handful of checks over
-- a bounded time window (summary GROUP BY check_id; per-check history), which
-- ORDER BY (check_id, timestamp) serves directly.
--
-- ONE ROW = ONE PROBE EXECUTION.
--   success     = 1 when the HTTP response status == the check's expected_status.
--   latency_ms  = wall-clock request latency in milliseconds.
--   status_code = the observed HTTP status (0 when the request never completed).
--   error       = a short failure description (empty on success).
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

CREATE TABLE IF NOT EXISTS nanosiem.synthetic_check_results
(
    -- The owning check's PG id (UUID stringified). Leads the sort key so a
    -- per-check summary/history scan prunes to the check's parts.
    `check_id` String CODEC(ZSTD(1)),
    `timestamp` DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    -- 1 when status == expected_status, else 0.
    `success` UInt8 CODEC(ZSTD(1)),
    -- Wall-clock request latency (ms). Gorilla is the canonical codec for the
    -- slowly-varying float metric stream.
    `latency_ms` Float64 CODEC(Gorilla, ZSTD(1)),
    -- Observed HTTP status (0 when the request never completed — DNS / connect
    -- / timeout error).
    `status_code` UInt16 CODEC(ZSTD(1)),
    -- Short failure description; empty on success.
    `error` String DEFAULT '' CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (check_id, timestamp)
TTL toDateTime(timestamp) + toIntervalDay(30)
SETTINGS index_granularity = 8192
;
