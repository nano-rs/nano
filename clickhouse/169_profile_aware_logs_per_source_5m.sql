-- =============================================================================
-- 169: profile-aware, scope-preserving per-source telemetry (NAN-2154)
-- =============================================================================
--
-- The original logs_per_source_5m target is profile-blind. On OCSF deployments
-- Vector writes the same logical event to both `logs` and `ocsf_logs`, and one
-- MV from each source writes the shared target, doubling every Vector event.
-- The OCSF MV also replaces raw source_type='unknown' with a product-name
-- display key, discarding the identifier canonical search authorizes against.
--
-- A new target is required: AggregatingMergeTree cannot safely add dimensions
-- that are absent from its ORDER BY key because rows from distinct profiles or
-- raw scope keys would still merge. This target keys both dimensions.
--
-- There is intentionally no migration-path backfill. A large INSERT SELECT is
-- prohibited in boot-gating migrations, and copying the old aggregate would
-- preserve neither its lane nor its raw scope provenance. Live MVs cold-start
-- the seven-day rollup. Any manual row that omits scope provenance gets the
-- DEFAULT complete=0 and restricted readers reject it.

CREATE TABLE IF NOT EXISTS nanosiem.logs_per_source_5m_v2
(
    `schema_profile`             LowCardinality(String),
    `source_type`                LowCardinality(String),
    `scope_source_type`          LowCardinality(String),
    `scope_source_type_complete` UInt8 DEFAULT 0,
    `bucket_start`               DateTime,
    `events`                     SimpleAggregateFunction(sum, UInt64),
    `bytes`                      SimpleAggregateFunction(sum, UInt64),
    `last_event_at`              SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `first_event_at`             SimpleAggregateFunction(min, DateTime64(6, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(bucket_start)
ORDER BY
(
    schema_profile,
    source_type,
    scope_source_type_complete,
    scope_source_type,
    bucket_start
)
TTL bucket_start + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS nanosiem.logs_per_source_5m_mv;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.logs_per_source_5m_mv
TO nanosiem.logs_per_source_5m_v2 AS
SELECT
    'udm'                                    AS schema_profile,
    lower(source_type)                       AS source_type,
    lower(source_type)                       AS scope_source_type,
    toUInt8(1)                               AS scope_source_type_complete,
    toStartOfFiveMinute(timestamp)           AS bucket_start,
    count()                                  AS events,
    sum(length(message) + length(metadata))  AS bytes,
    max(timestamp)                           AS last_event_at,
    min(timestamp)                           AS first_event_at
FROM nanosiem.logs
GROUP BY
    schema_profile,
    source_type,
    scope_source_type,
    scope_source_type_complete,
    bucket_start;

DROP VIEW IF EXISTS nanosiem.ocsf_logs_per_source_5m_mv;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_per_source_5m_mv /* nano:skip-if-unknown-table */
TO nanosiem.logs_per_source_5m_v2
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `scope_source_type` LowCardinality(String),
    `scope_source_type_complete` UInt8,
    `bucket_start` DateTime,
    `events` UInt64,
    `bytes` UInt64,
    `last_event_at` DateTime64(6, 'UTC'),
    `first_event_at` DateTime64(6, 'UTC')
)
AS SELECT
    'ocsf' AS schema_profile,
    if(raw_source_type != '' AND raw_source_type != 'unknown', raw_source_type,
       if(product_name != '', product_name, 'unknown')) AS source_type,
    raw_source_type AS scope_source_type,
    toUInt8(1) AS scope_source_type_complete,
    toStartOfFiveMinute(timestamp) AS bucket_start,
    count() AS events,
    sum(event_bytes) AS bytes,
    max(timestamp) AS last_event_at,
    min(timestamp) AS first_event_at
FROM
(
    SELECT
        timestamp,
        event_bytes,
        lower(source_type) AS raw_source_type,
        lower(`metadata.product.name`) AS product_name
    FROM nanosiem.ocsf_logs
)
GROUP BY
    schema_profile,
    source_type,
    scope_source_type,
    scope_source_type_complete,
    bucket_start;
