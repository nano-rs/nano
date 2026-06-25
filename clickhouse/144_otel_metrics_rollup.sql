-- Migration: generic multi-resolution metric rollup for the observability console (NAN-1555).
--
-- WHAT THIS IS
-- ------------
-- Wide-window metric aggregations (the metrics-explorer time series, dashboard
-- panels, alert backtesting) GROUP BY over the RAW nanosiem.otel_metrics table
-- (140), re-scanning every data point in the window on each load. That is the
-- same scaling tax the per-service RED rollup (143, otel_service_red_1m) and the
-- SIEM's prevalence/entity rollups were built to avoid: pre-aggregate into an
-- AggregatingMergeTree fed by a MV, then read the merged states.
--
-- This adds TWO resolutions of a GENERIC per-(metric, service, bucket) rollup:
--   nanosiem.otel_metrics_1m  — one row per (metric_name, service_name, minute)
--   nanosiem.otel_metrics_1h  — one row per (metric_name, service_name, hour)
-- Each row carries the value sum / count / min / max (SimpleAggregateFunction —
-- mergeable, read with the plain agg, no -Merge) plus a quantilesTDigest STATE
-- over `value` (read with quantilesTDigestMerge). avg is sum/count, p50/p95/p99
-- come off the digest — identical numbers to the raw GROUP BY, but bounded by
-- the (tiny) bucket-cardinality of the rollup instead of raw point volume.
--
-- WHY KEYED (metric_name, service_name, bucket) AND NOT BY TAGS
-- ------------------------------------------------------------
-- Folding the data-point `attributes` map into the key would explode its
-- cardinality (per-label-combination rows), defeating the rollup. So the rollup
-- is deliberately tag-AGNOSTIC: it answers "metric M for service S over a wide
-- window" cheaply; tag-broken-down queries fall back to scanning raw
-- otel_metrics. Number rows (gauge/sum) carry `value`; histogram rows leave
-- `value` at 0, so the rollup is meaningful for the scalar metrics it targets.
--
-- WHY quantilesTDigest STATE (not three separate quantile columns):
-- t-digests merge — the partial state for a bucket across many inserts/parts
-- folds into one digest, and reading p50/p95/p99 from the merged state is a
-- single quantilesTDigestMerge. Mirrors 143's duration_state.
--
-- 1m: PARTITION BY toYYYYMMDD(minute), ORDER BY (metric_name, service_name,
-- minute), 90d TTL (matches otel_metrics raw retention). 1h: same shape on the
-- hour bucket with a longer 400d TTL — the coarse rollup is cheap to keep and
-- powers year-over-year / long-horizon panels after the raw 1m data has aged out.
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

-- =============================================================================
-- ROLLUP TABLE  (nanosiem.otel_metrics_1m — AggregatingMergeTree, 1-minute)
-- =============================================================================
CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics_1m
(
    `metric_name` LowCardinality(String),
    `service_name` LowCardinality(String),
    -- minute bucket (toStartOfMinute of the data point time). Plain (non-aggregate)
    -- column so it is sort/partition-key legal. DateTime64 (not plain DateTime) so
    -- the nPL generator's microsecond-precision time-bound literal parses against
    -- it (a fractional string fails to convert to DateTime, CH Code 53) — the same
    -- precision otel_metrics.timestamp carries.
    `minute` DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    -- value sum / count / min / max: simple-mergeable aggregates (read with the
    -- plain agg, e.g. sum(value_sum) — no -Merge). avg is value_sum / value_count.
    `value_sum` SimpleAggregateFunction(sum, Float64),
    `value_count` SimpleAggregateFunction(sum, UInt64),
    `value_min` SimpleAggregateFunction(min, Float64),
    `value_max` SimpleAggregateFunction(max, Float64),
    -- value distribution digest; p50/p95/p99 read via
    -- quantilesTDigestMerge(0.5,0.95,0.99)(value_state).
    `value_state` AggregateFunction(quantilesTDigest(0.5, 0.95, 0.99), Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (metric_name, service_name, minute)
TTL minute + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- =============================================================================
-- ROLLUP TABLE  (nanosiem.otel_metrics_1h — AggregatingMergeTree, 1-hour)
-- =============================================================================
CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics_1h
(
    `metric_name` LowCardinality(String),
    `service_name` LowCardinality(String),
    -- hour bucket (toStartOfHour of the data point time). Plain (non-aggregate)
    -- column so it is sort/partition-key legal. DateTime64 so the generator's
    -- fractional time-bound literal parses (see the 1m note above).
    `hour` DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    `value_sum` SimpleAggregateFunction(sum, Float64),
    `value_count` SimpleAggregateFunction(sum, UInt64),
    `value_min` SimpleAggregateFunction(min, Float64),
    `value_max` SimpleAggregateFunction(max, Float64),
    `value_state` AggregateFunction(quantilesTDigest(0.5, 0.95, 0.99), Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (metric_name, service_name, hour)
TTL hour + toIntervalDay(400)
SETTINGS index_granularity = 8192
;

-- =============================================================================
-- DERIVATION MATERIALIZED VIEW  (otel_metrics -> otel_metrics_1m)
-- =============================================================================
-- Folds each block inserted into nanosiem.otel_metrics into per-(metric, service,
-- minute) partial aggregates. The AggregatingMergeTree merges those partials
-- across blocks/parts so the per-minute row is correct regardless of batching.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.otel_metrics_1m_mv
TO nanosiem.otel_metrics_1m
AS SELECT
    metric_name,
    service_name,
    toStartOfMinute(timestamp) AS minute,
    sum(value) AS value_sum,
    count() AS value_count,
    min(value) AS value_min,
    max(value) AS value_max,
    quantilesTDigestState(0.5, 0.95, 0.99)(value) AS value_state
FROM nanosiem.otel_metrics
GROUP BY metric_name, service_name, minute
;

-- =============================================================================
-- DERIVATION MATERIALIZED VIEW  (otel_metrics -> otel_metrics_1h)
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.otel_metrics_1h_mv
TO nanosiem.otel_metrics_1h
AS SELECT
    metric_name,
    service_name,
    toStartOfHour(timestamp) AS hour,
    sum(value) AS value_sum,
    count() AS value_count,
    min(value) AS value_min,
    max(value) AS value_max,
    quantilesTDigestState(0.5, 0.95, 0.99)(value) AS value_state
FROM nanosiem.otel_metrics
GROUP BY metric_name, service_name, hour
;

-- =============================================================================
-- ONE-TIME BACKFILL  (existing metrics -> 1m rollup)
-- =============================================================================
-- The MV only sees data points inserted AFTER it is created, so backfill the
-- rows already in otel_metrics. Safe to re-run AS A MERGE, but a re-run would
-- DOUBLE the counts/sums for the backfilled buckets (sum is additive), so this
-- is a one-shot backfill — the migration runner applies each numbered file
-- once. Do NOT manually re-execute this statement against a table that already
-- holds the backfill.
INSERT INTO nanosiem.otel_metrics_1m
SELECT
    metric_name,
    service_name,
    toStartOfMinute(timestamp) AS minute,
    sum(value) AS value_sum,
    count() AS value_count,
    min(value) AS value_min,
    max(value) AS value_max,
    quantilesTDigestState(0.5, 0.95, 0.99)(value) AS value_state
FROM nanosiem.otel_metrics
GROUP BY metric_name, service_name, minute
;

-- =============================================================================
-- ONE-TIME BACKFILL  (existing metrics -> 1h rollup)
-- =============================================================================
-- Same one-shot semantics as the 1m backfill above: sum is additive, do NOT
-- re-run against an already-backfilled table.
INSERT INTO nanosiem.otel_metrics_1h
SELECT
    metric_name,
    service_name,
    toStartOfHour(timestamp) AS hour,
    sum(value) AS value_sum,
    count() AS value_count,
    min(value) AS value_min,
    max(value) AS value_max,
    quantilesTDigestState(0.5, 0.95, 0.99)(value) AS value_state
FROM nanosiem.otel_metrics
GROUP BY metric_name, service_name, hour
;
