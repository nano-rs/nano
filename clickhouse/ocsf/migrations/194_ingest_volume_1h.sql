-- =============================================================================
-- OCSF/194: arrival-time ingest volume for Self-run usage metering (NAN-5170)
-- =============================================================================
-- Mirrors the OCSF half of clickhouse/194_ingest_volume_1h.sql for OCSF
-- deployments, so the view exists even where ocsf_logs did not yet exist when
-- the primary chain ran (its OCSF statement is skip-if-unknown-table). Both
-- statements are IF NOT EXISTS and identical to 194, so the order of the two
-- chains does not matter. See 194 for the rationale.

CREATE TABLE IF NOT EXISTS nanosiem.ingest_volume_1h
(
    `schema_profile` LowCardinality(String),
    `platform`       UInt8,
    `received_hour`  DateTime('UTC'),
    `events`         SimpleAggregateFunction(sum, UInt64),
    `bytes`          SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(received_hour)
ORDER BY (schema_profile, platform, received_hour)
TTL received_hour + INTERVAL 35 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ingest_volume_1h_mv
TO nanosiem.ingest_volume_1h
(
    `schema_profile` LowCardinality(String),
    `platform` UInt8,
    `received_hour` DateTime('UTC'),
    `events` UInt64,
    `bytes` UInt64
)
AS SELECT
    'ocsf'                                                 AS schema_profile,
    toUInt8(lower(source_type) IN ('audit', 'findings'))   AS platform,
    toStartOfHour(now('UTC'))                              AS received_hour,
    count()                                                AS events,
    sum(event_bytes)                                       AS bytes
FROM nanosiem.ocsf_logs
GROUP BY
    schema_profile,
    platform,
    received_hour;
