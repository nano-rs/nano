-- Migration: per-service-per-minute RED rollup for the observability console (NAN-1539).
--
-- WHAT THIS IS
-- ------------
-- The Services tab of the observability console (GET /api/search/services) and
-- the per-service RED time series (GET /api/search/services/{service}) used to
-- aggregate over the RAW nanosiem.otel_spans table on every load
-- (services_overview_sql / services_sparkline_sql / service_red_timeseries_sql,
-- all GROUP BY raw spans). That re-scans every span in the window on each page
-- load — the same scaling tax the SIEM's prevalence/entity rollups
-- (domain_prevalence_agg, entity_time_range_agg in clickhouse/init.sql) were
-- built to avoid: pre-aggregate into an AggregatingMergeTree fed by a MV, then
-- read the merged states.
--
-- This adds nanosiem.otel_service_red_1m: ONE row per (service_name, minute)
-- carrying the request count, error count, and a quantilesTDigest STATE over the
-- span duration in MILLISECONDS (duration_ns / 1e6). The console RED reads
-- sumMerge the counts and quantilesTDigestMerge the latency state, bucketing by
-- minute — identical numbers to the raw GROUP BY, but bounded by the (tiny)
-- minute-cardinality of the rollup instead of the (unbounded) span volume.
--
-- WHY quantilesTDigest STATE (not three separate quantileTDigest columns):
-- t-digests merge — the partial state for minute M across many inserts/parts
-- folds into one digest, and reading p50/p95/p99 from the merged state is a
-- single -Merge. This mirrors how the raw SQL already used quantileTDigest over
-- duration_ns; the rollup just persists the digest instead of recomputing it.
--
-- duration is stored in MS in the digest (duration_ns / 1e6) so the read path
-- does NOT re-divide — quantilesTDigestMerge(...)[i] is already ms, matching the
-- `... / 1e6 AS pXX_ms` contract the FE/glue expect.
--
-- PARTITION BY toYYYYMMDD(minute), ORDER BY (service_name, minute) — clusters by
-- service then time, the exact read order (per-service RED series, all-services
-- overview both filter/group on this prefix). 30d TTL matches otel_spans.
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

-- =============================================================================
-- ROLLUP TABLE  (nanosiem.otel_service_red_1m — AggregatingMergeTree)
-- =============================================================================
CREATE TABLE IF NOT EXISTS nanosiem.otel_service_red_1m
(
    `service_name` LowCardinality(String),
    -- minute bucket (toStartOfMinute of the span start). Plain (non-aggregate)
    -- column so it is sort/partition-key legal.
    `minute` DateTime('UTC') CODEC(Delta(4), ZSTD(1)),
    -- request / error counts: simple-mergeable sums (no -Merge needed on read;
    -- sumMerge is still used for symmetry and to fold partial states across parts).
    `request_count` SimpleAggregateFunction(sum, UInt64),
    `error_count` SimpleAggregateFunction(sum, UInt64),
    -- latency digest over duration in MILLISECONDS; p50/p95/p99 read via
    -- quantilesTDigestMerge(0.5,0.95,0.99)(duration_state).
    `duration_state` AggregateFunction(quantilesTDigest(0.5, 0.95, 0.99), Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (service_name, minute)
TTL minute + toIntervalDay(30)
SETTINGS index_granularity = 8192
;

-- =============================================================================
-- DERIVATION MATERIALIZED VIEW  (otel_spans -> otel_service_red_1m)
-- =============================================================================
-- Folds each block inserted into nanosiem.otel_spans into per-(service, minute)
-- partial aggregates. The AggregatingMergeTree merges those partials across
-- blocks/parts so the per-minute row is correct regardless of insert batching.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.otel_service_red_1m_mv
TO nanosiem.otel_service_red_1m
AS SELECT
    service_name,
    toStartOfMinute(start_time) AS minute,
    count() AS request_count,
    countIf(status_code = 'ERROR') AS error_count,
    quantilesTDigestState(0.5, 0.95, 0.99)(duration_ns / 1e6) AS duration_state
FROM nanosiem.otel_spans
GROUP BY service_name, minute
;

-- =============================================================================
-- ONE-TIME BACKFILL  (existing spans -> rollup)
-- =============================================================================
-- The MV only sees spans inserted AFTER it is created, so backfill the rows
-- already in otel_spans. Safe to re-run: AggregatingMergeTree re-merges
-- identical partial states, but a re-run would DOUBLE the counts for the
-- backfilled minutes (sum is additive), so this is a one-shot backfill — the
-- migration runner applies each numbered file once. (Re-running the whole
-- migration would re-INSERT; do NOT manually re-execute this statement against a
-- table that already holds the backfill.)
INSERT INTO nanosiem.otel_service_red_1m
SELECT
    service_name,
    toStartOfMinute(start_time) AS minute,
    count() AS request_count,
    countIf(status_code = 'ERROR') AS error_count,
    quantilesTDigestState(0.5, 0.95, 0.99)(duration_ns / 1e6) AS duration_state
FROM nanosiem.otel_spans
GROUP BY service_name, minute
;
