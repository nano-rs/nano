-- =============================================================================
-- 170: source-attributed prevalence aggregates (NAN-2053)
-- =============================================================================
--
-- The legacy *_prevalence_{agg,summary,final} families intentionally have no
-- source key. Once contributions from two source_types are merged into their
-- uniq states / counters, a later per-source deny cannot subtract one origin.
--
-- Keep those tables as the byte-identical fast path for SYSTEM/unrestricted
-- callers. Restricted viewers read this parallel family instead. Its grain is
-- (schema_profile, artifact, source_type, time), and the entity summary keeps
-- the same source key. Readers filter profile + source_type BEFORE uniqMerge,
-- aggregation, ordering, and LIMIT.
--
-- schema_profile is required because OCSF deployments may temporarily
-- dual-write UDM and OCSF. Mixing both lanes would double total_count and make
-- the source-attributed result profile-blind (the same class tracked by
-- NAN-2154 for logs_per_source_5m).
--
-- No historical INSERT ... SELECT belongs in a boot migration. Existing
-- source-less aggregate rows are deliberately absent here and therefore fail
-- closed for restricted viewers. New events are attributed synchronously by
-- the MVs below; a bounded, resumable historical backfill can be added
-- independently without weakening the read-side policy.

CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_source_agg
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (schema_profile, file_hash, source_type, hash_type, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_source_agg
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `domain` String,
    `is_subdomain` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (schema_profile, domain, source_type, is_subdomain, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_source_agg
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `ip` String,
    `direction` LowCardinality(String),
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (schema_profile, ip, source_type, direction, is_private, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

-- Entity/source summaries remove the hourly multiplier from rare/new/explorer
-- scans while preserving mergeable host sketches across the allowed sources.
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_source_summary
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (schema_profile, file_hash, source_type, hash_type)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_source_summary
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (schema_profile, domain, source_type, is_subdomain)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_source_summary
(
    `schema_profile` LowCardinality(String),
    `source_type` LowCardinality(String),
    `ip` String,
    `direction` LowCardinality(String),
    `is_private` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 1,
    INDEX idx_last_seen last_seen TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
ORDER BY (schema_profile, ip, source_type, direction, is_private)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_source_summary_mv
TO nanosiem.hash_prevalence_source_summary AS
SELECT schema_profile, source_type, file_hash, hash_type,
       host_count, first_seen, last_seen, total_count
FROM nanosiem.hash_prevalence_source_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_source_summary_mv
TO nanosiem.domain_prevalence_source_summary AS
SELECT schema_profile, source_type, domain, is_subdomain,
       source_host_count, first_seen, last_seen, total_count
FROM nanosiem.domain_prevalence_source_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_source_summary_mv
TO nanosiem.ip_prevalence_source_summary AS
SELECT schema_profile, source_type, ip, direction, is_private,
       source_host_count, first_seen, last_seen, total_count
FROM nanosiem.ip_prevalence_source_agg;

-- UDM hash branches, expressed as one ARRAY JOIN. The process value is blanked
-- when it duplicates file_hash, matching the legacy branch-dedup predicate.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_source_udm_mv
TO nanosiem.hash_prevalence_source_agg AS
SELECT
    'udm' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(hash_value) AS file_hash,
    multiIf(length(hash_value) = 32, 'md5', length(hash_value) = 40, 'sha1',
            length(hash_value) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
ARRAY JOIN [logs.file_hash,
            if(lower(logs.process_hash) != lower(logs.file_hash), logs.process_hash, '')] AS hash_value
WHERE hash_value != ''
  AND length(hash_value) IN (32, 40, 64)
  AND match(hash_value, '^[a-fA-F0-9]+$')
GROUP BY schema_profile, source_type, file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_source_udm_mv
TO nanosiem.domain_prevalence_source_agg AS
SELECT
    'udm' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(domain_value) AS domain,
    if(length(splitByChar('.', domain_value)) > 2, 1, 0) AS is_subdomain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
ARRAY JOIN [
    dest_host,
    if(lower(query) != lower(dest_host), query, ''),
    if(lower(url_domain) != lower(dest_host) AND lower(url_domain) != lower(query), url_domain, '')
] AS domain_value
WHERE domain_value != ''
  AND position(domain_value, '.') > 0
  AND NOT match(domain_value, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT position(domain_value, ':') > 0
  AND match(domain_value, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
  AND length(splitByChar('.', domain_value)[-1]) >= 2
  AND NOT match(splitByChar('.', domain_value)[-1], '^[0-9]+$')
  AND length(domain_value) <= 253
  AND lower(splitByChar('.', domain_value)[-1]) NOT IN
      ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa')
GROUP BY schema_profile, source_type, domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_source_udm_mv
TO nanosiem.ip_prevalence_source_agg AS
SELECT
    'udm' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    ip_tuple.1 AS ip,
    ip_tuple.2 AS direction,
    if(match(ip, '^10\\.') OR match(ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.')
       OR match(ip, '^192\\.168\\.') OR match(ip, '^127\\.')
       OR match(ip, '^169\\.254\\.'), 1, 0) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(ip_tuple.3) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
ARRAY JOIN [
    (dest_ip, 'dest', if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))),
    (if(src_ip != dest_ip, src_ip, ''), 'src',
     if(dest_host != '', dest_host, if(dest_ip != '', dest_ip, 'unknown')))
] AS ip_tuple
WHERE ip != ''
  AND match(ip, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(ip, '^127\\.')
  AND NOT match(ip, '^169\\.254\\.')
GROUP BY schema_profile, source_type, ip, direction, is_private, time_bucket;

-- OCSF statements are skipped on UDM-only installations. On an existing OCSF
-- deployment ocsf_logs already exists and these are created here. On a FRESH
-- OCSF deployment numbered migrations run before the profile overlay, so the
-- same three definitions also live in clickhouse/ocsf/init.sql; the overlay
-- creates them after ocsf_logs exists.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_source_ocsf_mv /* nano:skip-if-unknown-table */
TO nanosiem.hash_prevalence_source_agg AS
SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(hash_value) AS file_hash,
    multiIf(length(hash_value) = 32, 'md5', length(hash_value) = 40, 'sha1',
            length(hash_value) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
                 if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
ARRAY JOIN [`file.hashes.sha256`,
            if(lower(`process.file.hashes.sha256`) != lower(`file.hashes.sha256`),
               `process.file.hashes.sha256`, '')] AS hash_value
WHERE hash_value != ''
  AND length(hash_value) IN (32, 40, 64)
  AND match(hash_value, '^[a-fA-F0-9]+$')
GROUP BY schema_profile, source_type, file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_source_ocsf_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_source_agg AS
SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(domain_value) AS domain,
    if(length(splitByChar('.', domain_value)) > 2, 1, 0) AS is_subdomain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
                 if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
ARRAY JOIN [
    `dst_endpoint.hostname`,
    if(lower(`query.hostname`) != lower(`dst_endpoint.hostname`), `query.hostname`, ''),
    if(lower(`url.hostname`) != lower(`dst_endpoint.hostname`)
       AND lower(`url.hostname`) != lower(`query.hostname`), `url.hostname`, '')
] AS domain_value
WHERE domain_value != ''
  AND position(domain_value, '.') > 0
  AND NOT match(domain_value, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT position(domain_value, ':') > 0
  AND match(domain_value, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
  AND length(splitByChar('.', domain_value)[-1]) >= 2
  AND NOT match(splitByChar('.', domain_value)[-1], '^[0-9]+$')
  AND length(domain_value) <= 253
  AND lower(splitByChar('.', domain_value)[-1]) NOT IN
      ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa')
GROUP BY schema_profile, source_type, domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_source_ocsf_mv /* nano:skip-if-unknown-table */
TO nanosiem.ip_prevalence_source_agg AS
SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    ip_tuple.1 AS ip,
    ip_tuple.2 AS direction,
    if(match(ip, '^10\\.') OR match(ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.')
       OR match(ip, '^192\\.168\\.') OR match(ip, '^127\\.')
       OR match(ip, '^169\\.254\\.'), 1, 0) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(ip_tuple.3) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
ARRAY JOIN [
    (`dst_endpoint.ip`, 'dest',
     if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
        if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))),
    (if(`src_endpoint.ip` != `dst_endpoint.ip`, `src_endpoint.ip`, ''), 'src',
     if(`dst_endpoint.hostname` != '', `dst_endpoint.hostname`,
        if(`dst_endpoint.ip` != '', `dst_endpoint.ip`, 'unknown')))
] AS ip_tuple
WHERE ip != ''
  AND match(ip, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(ip, '^127\\.')
  AND NOT match(ip, '^169\\.254\\.')
GROUP BY schema_profile, source_type, ip, direction, is_private, time_bucket;
