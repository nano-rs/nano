-- Migration: Per-source_type 5-minute log telemetry rollup (NAN-733).
--
-- A dozen+ ClickHouse read sites independently scan the raw `logs` table to
-- compute the same per-source_type aggregate (events, bytes, last_event_at)
-- over a recent time window: source-configs list/detail, log-sources health,
-- feeds, /api/system/overview, meloD briefing, feed-staleness scheduler, etc.
-- Each had its own SQL, its own SAMPLE 0.1 band-aid, and its own partition
-- prune. The visible symptom was /ingestion/source-configurations taking ~3 s
-- to render a 6-row Postgres list.
--
-- This migration adds a single AggregatingMergeTree rollup keyed on
-- (source_type, 5-minute bucket). Consumers cut over to read from this table
-- instead of scanning raw `logs`. Mirrors the *_prevalence_summary pattern
-- (clickhouse/110_prevalence_summary_tables.sql).
--
-- Decisions:
--   - 5-minute bucketing: ~14k rows/day post-merge for 50 source_types. Hour
--     windows roll up cleanly; preserves the "events_last_hour" semantics
--     used by Dashboard / Log Source health.
--   - 7-day TTL: covers all 24h/1h/7d callers. Longer-window callers
--     (get_health_clickhouse total_events at 90d) stay on raw `logs`.
--   - source_type stored lowercased — every existing read site already
--     does `lower(source_type)`, so this matches semantics without forcing
--     callers to lowercase at read time.
--
-- NOTE: the backfill INSERT below blocks migration apply. On saturn-scale
-- ingest (50–100 GB/day) expect 30–90 s of additional API startup time when
-- this migration first runs. The _migrations runner skips it on subsequent
-- boots; it only happens once per cluster.

-- ============================================================================
-- Target table
-- ============================================================================

-- last_event_at / first_event_at match `logs.timestamp` (DateTime64(6, 'UTC'))
-- so the MV's max/min insert without lossy implicit casts and preserve
-- microsecond precision + timezone metadata. bucket_start stays plain
-- DateTime — 5-minute granularity doesn't need sub-second precision and the
-- coarser type makes partition pruning expressions cheaper.
CREATE TABLE IF NOT EXISTS nanosiem.logs_per_source_5m
(
    `source_type`    LowCardinality(String),
    `bucket_start`   DateTime,
    `events`         SimpleAggregateFunction(sum, UInt64),
    `bytes`          SimpleAggregateFunction(sum, UInt64),
    `last_event_at`  SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `first_event_at` SimpleAggregateFunction(min, DateTime64(6, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(bucket_start)
ORDER BY (source_type, bucket_start)
TTL bucket_start + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- Live MV from raw `logs` → rollup. Lowercases source_type at write time so
-- readers don't have to. AggregatingMergeTree merges identical (source_type,
-- bucket_start) rows in the background.
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.logs_per_source_5m_mv
TO nanosiem.logs_per_source_5m AS
SELECT
    lower(source_type)                       AS source_type,
    toStartOfFiveMinute(timestamp)           AS bucket_start,
    count()                                  AS events,
    sum(length(message) + length(metadata))  AS bytes,
    max(timestamp)                           AS last_event_at,
    min(timestamp)                           AS first_event_at
FROM nanosiem.logs
GROUP BY source_type, bucket_start;

-- ============================================================================
-- Backfill last 7 days. The 10-minute cutoff (one bucket of headroom) leaves
-- a safe gap so any rows arriving between the SELECT scan and the live MV's
-- first capture cannot land in both paths and double-count under
-- SimpleAggregateFunction(sum). The MV catches the tail.
-- ============================================================================

INSERT INTO nanosiem.logs_per_source_5m
    (source_type, bucket_start, events, bytes, last_event_at, first_event_at)
SELECT
    lower(source_type)                       AS source_type,
    toStartOfFiveMinute(timestamp)           AS bucket_start,
    count()                                  AS events,
    sum(length(message) + length(metadata))  AS bytes,
    max(timestamp)                           AS last_event_at,
    min(timestamp)                           AS first_event_at
FROM nanosiem.logs
WHERE timestamp >= now() - INTERVAL 7 DAY
  AND timestamp <  now() - INTERVAL 10 MINUTE
GROUP BY source_type, bucket_start;
