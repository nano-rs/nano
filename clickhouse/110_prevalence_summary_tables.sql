-- Migration: Per-entity prevalence summary tables (NAN-365).
--
-- The existing *_prevalence_agg tables key on (entity, hour). Dict refresh runs
-- uniqMerge GROUP BY entity over 30d of hourly rows every 5-10 min — the
-- unbounded GROUP BY that OOMs on busy tenants.
--
-- This migration adds *_prevalence_summary tables keyed only on entity, maintained
-- via chained MVs from the existing agg tables. Background AggregatingMergeTree
-- merges collapse states to one row per entity over time. TTL on last_seen auto-
-- prunes stale entities. Dict refresh now reads a table sized by N_entities,
-- not N_entities x N_hours.
--
-- Backfill is a straight pass-through INSERT SELECT (no GROUP BY, no memory
-- pressure) — background merges aggregate later.
--
-- Dict names are preserved, so logs.prevalence_* ingest-time materialized columns
-- and the `| prevalence` search command need no changes. Dict sources swap to
-- the summary tables atomically via CREATE OR REPLACE DICTIONARY.

-- ============================================================================
-- Summary tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_summary
(
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
ORDER BY (file_hash, hash_type)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_summary
(
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
ORDER BY (domain, is_subdomain)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_summary
(
    `ip` String,
    `is_private` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
ORDER BY (ip, is_private)
TTL toDateTime(last_seen) + toIntervalDay(30)
SETTINGS index_granularity = 8192;

-- ============================================================================
-- Chained MVs (agg -> summary, pass-through). AggregatingMergeTree merges
-- states in the background keyed by ORDER BY. Direction/time_bucket are
-- dropped because the summary aggregates across them.
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_summary_mv
TO nanosiem.hash_prevalence_summary AS
SELECT
    file_hash,
    hash_type,
    host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.hash_prevalence_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_summary_mv
TO nanosiem.domain_prevalence_summary AS
SELECT
    domain,
    is_subdomain,
    source_host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.domain_prevalence_agg;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_summary_mv
TO nanosiem.ip_prevalence_summary AS
SELECT
    ip,
    is_private,
    source_host_count,
    first_seen,
    last_seen,
    total_count
FROM nanosiem.ip_prevalence_agg;

-- ============================================================================
-- Backfill. Pass-through INSERT SELECT with no GROUP BY — row count equals
-- the agg table row count, but per-row memory is trivial (no aggregation).
-- AggregatingMergeTree background merges will collapse to one row per key.
--
-- Cutoff split: `time_bucket < (SELECT max(time_bucket) FROM agg)` lets the
-- MV (created above) own the current/future bucket while the backfill owns
-- everything strictly earlier. Prevents the same agg row being captured both
-- by MV fire and by backfill, which would double `total_count` for the
-- overlapping buckets (HLL uniq states are idempotent under merge; sum is
-- not). Small tradeoff: entities that only appear in the current max bucket
-- prior to MV creation are not re-captured by backfill, but the source MV
-- keeps firing on new ingestion so the summary accrues them organically.
-- ============================================================================

INSERT INTO nanosiem.hash_prevalence_summary
    (file_hash, hash_type, host_count, first_seen, last_seen, total_count)
SELECT file_hash, hash_type, host_count, first_seen, last_seen, total_count
FROM nanosiem.hash_prevalence_agg
WHERE time_bucket >= now() - INTERVAL 30 DAY
  AND time_bucket < (SELECT coalesce(max(time_bucket), toDateTime(0)) FROM nanosiem.hash_prevalence_agg);

INSERT INTO nanosiem.domain_prevalence_summary
    (domain, is_subdomain, source_host_count, first_seen, last_seen, total_count)
SELECT domain, is_subdomain, source_host_count, first_seen, last_seen, total_count
FROM nanosiem.domain_prevalence_agg
WHERE time_bucket >= now() - INTERVAL 30 DAY
  AND time_bucket < (SELECT coalesce(max(time_bucket), toDateTime(0)) FROM nanosiem.domain_prevalence_agg);

INSERT INTO nanosiem.ip_prevalence_summary
    (ip, is_private, source_host_count, first_seen, last_seen, total_count)
SELECT ip, is_private, source_host_count, first_seen, last_seen, total_count
FROM nanosiem.ip_prevalence_agg
WHERE time_bucket >= now() - INTERVAL 30 DAY
  AND time_bucket < (SELECT coalesce(max(time_bucket), toDateTime(0)) FROM nanosiem.ip_prevalence_agg);

-- ============================================================================
-- Rewire dicts to source from summary tables. Dict names, attributes, and
-- layout are identical — atomic swap via CREATE OR REPLACE. Ingest-time
-- MATERIALIZED columns (logs.prevalence_*) continue to work without changes.
-- ============================================================================

CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict
(
    file_hash String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY file_hash
SOURCE(CLICKHOUSE(
    HOST 'localhost'
    PORT 9000
    USER 'nanosiem'
    PASSWORD 'nanosiem'
    DB 'nanosiem'
    QUERY 'SELECT file_hash, toUInt16(least(9998, host_count)) as host_count, first_seen, last_seen, total_occurrences FROM (
        SELECT file_hash,
               uniqMerge(host_count) as host_count,
               min(first_seen) as first_seen,
               max(last_seen) as last_seen,
               sum(total_count) as total_occurrences
        FROM nanosiem.hash_prevalence_summary
        GROUP BY file_hash
    ) WHERE host_count < 1000'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(SPARSE_HASHED());

CREATE OR REPLACE DICTIONARY nanosiem.domain_prevalence_dict
(
    domain String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY domain
SOURCE(CLICKHOUSE(
    HOST 'localhost'
    PORT 9000
    USER 'nanosiem'
    PASSWORD 'nanosiem'
    DB 'nanosiem'
    QUERY 'SELECT domain, toUInt16(least(9998, host_count)) as host_count, first_seen, last_seen, total_occurrences FROM (
        SELECT domain,
               uniqMerge(source_host_count) as host_count,
               min(first_seen) as first_seen,
               max(last_seen) as last_seen,
               sum(total_count) as total_occurrences
        FROM nanosiem.domain_prevalence_summary
        GROUP BY domain
    ) WHERE host_count < 1000'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(SPARSE_HASHED());

CREATE OR REPLACE DICTIONARY nanosiem.ip_prevalence_dict
(
    ip String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(
    HOST 'localhost'
    PORT 9000
    USER 'nanosiem'
    PASSWORD 'nanosiem'
    DB 'nanosiem'
    QUERY 'SELECT ip, toUInt16(least(9998, host_count)) as host_count, first_seen, last_seen, total_occurrences FROM (
        SELECT ip,
               uniqMerge(source_host_count) as host_count,
               min(first_seen) as first_seen,
               max(last_seen) as last_seen,
               sum(total_count) as total_occurrences
        FROM nanosiem.ip_prevalence_summary
        WHERE is_private = 0
        GROUP BY ip
    ) WHERE host_count < 1000'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(SPARSE_HASHED());
