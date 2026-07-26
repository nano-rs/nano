-- Migration: per-parser 5-minute production health rollup (NAN-2164).
--
-- Parser output is forked before optional sampling and reduced to four tiny
-- scalar fields. The Null-engine ingress table retains no per-event copy; its
-- materialized view writes five-minute aggregates into the seven-day rollup.
-- This keeps the health denominator exact even when the searchable log stream
-- is sampled. No backfill: instrumentation starts with this release.

CREATE TABLE IF NOT EXISTS nanosiem.parser_health_ingest
(
    `parser_id`     String,
    `source_type`   LowCardinality(String),
    `observed_at`   DateTime,
    `parse_failure` UInt8
)
ENGINE = Null;

CREATE TABLE IF NOT EXISTS nanosiem.parser_health_5m
(
    `parser_id`    String,
    `source_type`  LowCardinality(String),
    `bucket_start` DateTime,
    `events`       SimpleAggregateFunction(sum, UInt64),
    `parse_errors` SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(bucket_start)
ORDER BY (parser_id, source_type, bucket_start)
TTL bucket_start + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.parser_health_5m_mv
TO nanosiem.parser_health_5m AS
SELECT
    parser_id,
    lower(source_type) AS source_type,
    toStartOfFiveMinute(observed_at) AS bucket_start,
    count() AS events,
    countIf(parse_failure != 0) AS parse_errors
FROM nanosiem.parser_health_ingest
WHERE parser_id != ''
GROUP BY parser_id, source_type, bucket_start;
