-- NAN-5170: hourly ingest volume by ARRIVAL time, for Self-run usage metering.
--
-- The Self-Run Addendum defines Daily Ingest as what the Software receives in
-- one UTC calendar day. `logs_per_source_5m_v2` buckets by EVENT timestamp, so
-- backfilled history and late arrivals land on the wrong (often already
-- reported) day. These views stamp each insert block with `now('UTC')` at the
-- moment ClickHouse receives it, so a day's total is exactly what arrived that
-- day and never changes after it ends.
--
-- Deliberately tiny: no source names, hosts or any other dimension. `platform`
-- marks rows the platform writes itself (`audit`, `findings`; a sender cannot
-- forge these, see 192/ocsf-193) so the meter can exclude them. Bytes use the
-- same per-event size as logs_per_source_5m_v2 (UDM: message + metadata; OCSF:
-- the materialized event_bytes). Both MVs read only columns the ingest
-- credential already holds SELECT on (source_type, message, metadata;
-- source_type, event_bytes), so no grant changes.
--
-- No backfill (forward-only): metering starts when this migration runs, and the
-- reader treats the first (partial) day as unmetered.
--
-- Listed in dual_pool::DISTRIBUTED_TABLES: on a cluster reads go through
-- ingest_volume_1h_distributed.

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

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ingest_volume_1h_mv
TO nanosiem.ingest_volume_1h AS
SELECT
    'udm'                                                  AS schema_profile,
    toUInt8(lower(source_type) IN ('audit', 'findings'))   AS platform,
    toStartOfHour(now('UTC'))                              AS received_hour,
    count()                                                AS events,
    sum(length(message) + length(metadata))                AS bytes
FROM nanosiem.logs
GROUP BY
    schema_profile,
    platform,
    received_hour;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ingest_volume_1h_mv /* nano:skip-if-unknown-table */
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
