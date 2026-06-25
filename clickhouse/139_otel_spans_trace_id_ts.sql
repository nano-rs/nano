-- Migration: per-trace [min,max] time-range index for cheap trace assembly (NAN-1528).
--
-- WHAT THIS IS
-- ------------
-- Trace assembly ("give me every span for trace_id X, ordered") wants to scan
-- nanosiem.otel_spans WITHIN the tight time window that trace actually spans,
-- so partition pruning + the start_time sort-key prefix do the work instead of
-- a full-range trace_id bloom scan. This AggregatingMergeTree maintains, per
-- trace_id, the earliest start_time and latest end_time across its spans. The
-- trace-fetch query path resolves [min(start), max(end)] from here first, then
-- SELECTs from otel_spans bounded by that window (the single-WHERE / no explicit
-- PREWHERE rule, NAN-1412, still applies on that second query).
--
-- SimpleAggregateFunction(min/max, DateTime64(9)) is used (not the heavier
-- AggregateFunction) — min/max are simple-mergeable, so reads need no -Merge
-- combinator and the column reads as a plain DateTime64. Mirrors the
-- nanosiem.entity_time_range_agg first/last-seen idiom.
--
-- KEY-EXPRESSION CAVEAT: ClickHouse forbids a SimpleAggregateFunction column in
-- the sort/partition key (Code 549), so the AggregatingMergeTree is ORDERed BY
-- (trace_id) alone (the merge granularity — one merged row per trace). We add a
-- plain `start_date Date` that the MV derives from min(start_time) purely to
-- carry the daily PARTITION and the 30d TTL (the date of a trace's first span is
-- stable, so it makes a sound partition key). `start_date` is NOT aggregated:
-- AggregatingMergeTree leaves non-aggregate, non-key columns as the value from
-- an arbitrary row of the group — fine here because every span of a trace shares
-- (near enough) the same day, and the column is only used for pruning/TTL.
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

CREATE TABLE IF NOT EXISTS nanosiem.otel_spans_trace_id_ts
(
    `trace_id` String CODEC(ZSTD(1)),
    -- partition/TTL anchor: the calendar day of the trace's first span. Plain
    -- (non-aggregate) column — key-legal, unlike the SimpleAggregateFunction cols.
    `start_date` Date CODEC(Delta(2), ZSTD(1)),
    -- earliest span start / latest span end for this trace.
    `start` SimpleAggregateFunction(min, DateTime64(9, 'UTC')) CODEC(Delta(8), ZSTD(3)),
    `end`   SimpleAggregateFunction(max, DateTime64(9, 'UTC')) CODEC(Delta(8), ZSTD(3)),
    INDEX idx_trace_id_ts trace_id TYPE bloom_filter(0.001) GRANULARITY 1
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(start_date)
ORDER BY (trace_id)
TTL start_date + toIntervalDay(30)
SETTINGS index_granularity = 8192
;

-- MV: fold each block of otel_spans into per-trace (min start, max end).
-- The AggregatingMergeTree merges partial states across blocks/parts so a
-- trace's window is correct even when its spans arrive in separate inserts.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.otel_spans_trace_id_ts_mv
TO nanosiem.otel_spans_trace_id_ts
AS SELECT
    trace_id,
    toDate(min(start_time)) AS `start_date`,
    min(start_time) AS `start`,
    max(end_time) AS `end`
FROM nanosiem.otel_spans
WHERE trace_id != ''
GROUP BY trace_id
;
