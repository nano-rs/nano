-- NanoSIEM ClickHouse Schema
-- This file is used for initial ClickHouse setup during deployment

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS nanosiem;

-- =============================================================================
-- SUPPORT TABLES (must exist before dictionaries that source from them)
-- =============================================================================

-- Custom Enrichment Results - stores output from user-defined TypeScript enrichments
CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results (
    namespace LowCardinality(String),
    enrichment_id UUID,
    enrichment_name LowCardinality(String),
    key_type LowCardinality(String),  -- 'ip', 'domain', 'hash', 'url', 'custom'
    key_value String,
    risk_score Nullable(UInt8),
    tags Array(String),
    data String,  -- JSON
    fetched_at DateTime64(3),
    expires_at DateTime64(3),
    version UInt32,
    -- IOC fields (added by migration 081)
    is_ioc UInt8 DEFAULT 0,
    threat_type LowCardinality(String) DEFAULT '',
    malware LowCardinality(String) DEFAULT '',
    confidence UInt8 DEFAULT 0,
    -- Provenance: 1 = OOTB marketplace feed (routes to ioc_*), 0 = user-created
    -- custom enrichment (routes to custom_ioc_*). See migration 122 (NAN-1114).
    is_marketplace UInt8 DEFAULT 0,
    INDEX idx_risk_score risk_score TYPE minmax GRANULARITY 4,
    INDEX idx_tags tags TYPE bloom_filter GRANULARITY 4,
    INDEX idx_key_value key_value TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(fetched_at)
ORDER BY (namespace, enrichment_name, key_type, key_value)
TTL expires_at + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- =============================================================================
-- DICTIONARIES (must be created BEFORE tables that reference them in DEFAULT)
-- =============================================================================

-- IP Enrichment payload table (ClickHouse-sourced as of NAN-1117).
-- Mirrors the columns ip_enrichment_dict reads. ReplacingMergeTree keyed by
-- (source_id, network) gives last-write-wins per CIDR; `updated_at` is the
-- version, `deleted` is a tombstone for CIDRs a newer feed dropped. `network`
-- MUST stay a CIDR String — IP_TRIE builds its trie from the CIDR text.
-- Created BEFORE the dict so the dict always references an existing table
-- (an empty-but-LOADED dict returns defaults; a missing-table dict THROWS on
-- every logs insert — see migration 123 / NAN-1114).
CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichments
(
    network         String,
    source_id       LowCardinality(String) DEFAULT 'ipinfo_lite',
    country         String DEFAULT '',
    country_code    String DEFAULT '',
    continent       String DEFAULT '',
    continent_code  String DEFAULT '',
    asn             String DEFAULT '',
    as_name         String DEFAULT '',
    as_domain       String DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64(3),
    deleted         UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (source_id, network);

-- IP Enrichment Dictionary
-- Loads GeoIP/ASN data from the ClickHouse ip_enrichments table (NAN-1117;
-- was PostgreSQL-sourced — moved to CH for the same ingestion-halt reason as
-- the IOC dict in migration 122 / NAN-1114). The 14 nanosiem.logs enriched_*
-- MATERIALIZED columns call dictGetOrDefault on this dict on every insert.
-- Works with empty data - returns empty strings until enrichment is synced.
-- Disabling the source blanks the dict by deleting its CH rows (the old PG
-- `WHERE enabled = true` gate is preserved write-side, EnrichmentService).
CREATE DICTIONARY IF NOT EXISTS nanosiem.ip_enrichment_dict
(
    network String,
    country String DEFAULT '',
    country_code String DEFAULT '',
    continent String DEFAULT '',
    continent_code String DEFAULT '',
    asn String DEFAULT '',
    as_name String DEFAULT '',
    as_domain String DEFAULT ''
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain FROM nanosiem.ip_enrichments GROUP BY network HAVING argMax(deleted, updated_at) = 0'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(IP_TRIE());

-- IOC Enrichment Dictionary
-- OOTB marketplace IOC feeds (e.g. ThreatFox) populate nanosiem.logs `ioc_*`
-- columns via this dictionary. Sourced from ClickHouse custom_enrichment_results
-- filtered to marketplace-provided rows (is_marketplace = 1). The legacy
-- PostgreSQL source (ioc_enrichments table) was removed in NAN-1112; see
-- migration 122 (NAN-1114) for the repoint + incident write-up. User-created
-- IOC enrichments route through custom_ioc_enrichment_dict (is_marketplace = 0).
-- Works with empty data - returns empty values until a marketplace IOC feed syncs.
CREATE DICTIONARY IF NOT EXISTS nanosiem.ioc_enrichment_dict
(
    ioc_value String,
    ioc_type String DEFAULT '',
    source_id String DEFAULT '',
    threat_type String DEFAULT '',
    malware String DEFAULT '',
    confidence_level Int32 DEFAULT 0,
    tags String DEFAULT ''
)
PRIMARY KEY ioc_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        key_value AS ioc_value,
        anyLast(key_type) AS ioc_type,
        anyLast(enrichment_name) AS source_id,
        anyLast(threat_type) AS threat_type,
        anyLast(malware) AS malware,
        toInt32(anyLast(confidence)) AS confidence_level,
        arrayStringConcat(groupUniqArrayArray(tags), '','') AS tags
    FROM (
        SELECT * FROM nanosiem.custom_enrichment_results
        WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
        ORDER BY confidence DESC
    )
    GROUP BY key_value'
))
LIFETIME(MIN 60 MAX 300)
LAYOUT(HASHED());

-- Prevalence aggregation tables (must exist before dictionaries that source from them)

-- Table: domain_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_domain domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_parent_domain parent_domain TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (domain, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- Table: hash_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` LowCardinality(String),
    `time_bucket` DateTime,
    `host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6)),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6)),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (file_hash, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- Table: ip_prevalence_agg
CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` LowCardinality(String),
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `total_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (ip, direction, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

-- =============================================================================
-- Prevalence Summary Tables (NAN-365)
-- Per-entity summaries keyed only on entity (no time_bucket). Populated by
-- chained MVs from the *_prevalence_agg tables. AggregatingMergeTree background
-- merges collapse states to one row per entity; TTL on last_seen auto-prunes.
-- Dicts source from these instead of the hourly agg to avoid N_entities x
-- N_hours GROUP BY at refresh time.
-- =============================================================================

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

-- Per-source_type 5-minute log telemetry rollup (NAN-733).
-- Single source of truth for "events / bytes / last_event_at per source_type
-- over a recent window". Replaces ~12 ad-hoc `FROM logs ... GROUP BY
-- source_type` scans. Migration 116 mirrors this block + the live MV in the
-- MATERIALIZED VIEWS section below.
-- last_event_at / first_event_at match `logs.timestamp` so MV inserts don't
-- truncate or drop tz info; bucket_start is plain DateTime (5-min coarse).
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

-- Custom Enrichment Dictionary (non-IOC)
-- Aggregates tags and risk scores from user-defined TypeScript enrichments
CREATE DICTIONARY IF NOT EXISTS nanosiem.custom_enrichment_dict
(
    key_type String,
    key_value String,
    tags Array(String),
    risk_score UInt8,
    enrichment_names Array(String)
)
PRIMARY KEY key_type, key_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        key_type,
        key_value,
        groupUniqArrayArray(tags) as tags,
        max(coalesce(risk_score, 0)) as risk_score,
        groupUniqArray(enrichment_name) as enrichment_names
    FROM nanosiem.custom_enrichment_results
    WHERE expires_at > now() AND is_ioc = 0
    GROUP BY key_type, key_value'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- Custom IOC Enrichment Dictionary
-- Aggregates IOC threat intel from user-defined TypeScript enrichments
CREATE DICTIONARY IF NOT EXISTS nanosiem.custom_ioc_enrichment_dict
(
    key_type String,
    key_value String,
    threat_type String,
    malware String,
    confidence UInt8,
    tags Array(String),
    enrichment_names Array(String)
)
PRIMARY KEY key_type, key_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        key_type,
        key_value,
        anyLast(threat_type) as threat_type,
        anyLast(malware) as malware,
        anyLast(confidence) as confidence,
        groupUniqArrayArray(tags) as tags,
        groupUniqArray(enrichment_name) as enrichment_names
    FROM (
        SELECT * FROM nanosiem.custom_enrichment_results
        WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 0
        ORDER BY confidence DESC
    )
    GROUP BY key_type, key_value'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- Prevalence Enrichment Dictionaries (FRO-243 / NAN-606 layout — folded in from migration 112)
-- These dictionaries enable prevalence filtering at ingest time and power the `| prevalence` search command.
-- Returns host_count: number of unique hosts that have seen this artifact
-- Values: 1-9998 = actual count, 9999 = common (>1000 hosts or not tracked)
--
-- LAYOUT(COMPLEX_KEY_CACHE): bounded ~80 MiB cache. On a miss CH pushes the key
-- predicate into the source query so the GROUP BY runs over just the missed-key
-- rows rather than the full *_prevalence_summary table. SPARSE_HASHED was
-- unbounded and tripped the 6 GiB Team-tier max_server_memory_usage on
-- non-trivial tenants; see migration 112 for the full incident write-up.
-- Per-source-query max_memory_usage = 512 MiB is a belt-and-suspenders cap
-- in case the legacy analyzer is ever forced on and pushdown is lost.

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
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT file_hash,
                  toUInt16(least(9998, uniqMerge(host_count))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.hash_prevalence_summary
           GROUP BY file_hash
           HAVING host_count < 1000
           SETTINGS max_memory_usage = 536870912'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));

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
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT domain,
                  toUInt16(least(9998, uniqMerge(source_host_count))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.domain_prevalence_summary
           GROUP BY domain
           HAVING host_count < 1000
           SETTINGS max_memory_usage = 536870912'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));

-- NAN-706: 5M cells (vs 1M for hash/domain) — saturn ip_prevalence_dict
-- saturated the 1M cap at 89.85% hit rate; bumping gives ~400 MiB
-- cache for the IP working set. Migration 114 applies the same swap
-- to existing tenants. Hash and domain dicts stay at 1M; revisit if
-- their hit rates dip below 95%.
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
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT ip,
                  toUInt16(least(9998, uniqMerge(source_host_count))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.ip_prevalence_summary
           WHERE is_private = 0
           GROUP BY ip
           HAVING host_count < 1000
           SETTINGS max_memory_usage = 536870912'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));

-- Identity enrichment (user_registry) payload table — ClickHouse-sourced as of
-- NAN-1117 (was a PG table feeding a PG-sourced dict; moved to CH for the same
-- ingestion-halt reason as the IP/IOC dicts in migrations 122/123/NAN-1114).
-- This is the directory ENRICHMENT feed only — NOT the public.users auth table.
-- ReplacingMergeTree(version) keyed on (provider_id, external_id) so re-syncs
-- collapse to the latest version; account_status='deleted'/'anonymized' rows
-- are KEPT and filtered out by the dict QUERY. Materialized *_lc lookup keys
-- mirror the PG lower() indexes the dict + exact-match lookup used.
-- Created BEFORE the dict (and well before the logs table) so the dict always
-- references an existing table — an empty-but-LOADED dict returns defaults; a
-- missing-table dict THROWS on every logs insert.
CREATE TABLE IF NOT EXISTS nanosiem.user_registry
(
    provider_id        LowCardinality(String),
    external_id        String,
    username           String DEFAULT '',
    upn                String DEFAULT '',
    email              String DEFAULT '',
    display_name       String DEFAULT '',
    first_name         String DEFAULT '',
    last_name          String DEFAULT '',
    department         String DEFAULT '',
    title              String DEFAULT '',
    manager_upn        String DEFAULT '',
    manager_display_name String DEFAULT '',
    company            String DEFAULT '',
    office_location    String DEFAULT '',
    city               String DEFAULT '',
    country            String DEFAULT '',
    groups             Array(String) DEFAULT [],
    account_enabled    UInt8 DEFAULT 1,
    account_status     LowCardinality(String) DEFAULT 'active',
    mfa_enabled        UInt8 DEFAULT 0,
    last_sign_in_at    DateTime64(3) DEFAULT toDateTime64(0, 3),
    created_in_directory_at DateTime64(3) DEFAULT toDateTime64(0, 3),
    phone              String DEFAULT '',
    employee_id        String DEFAULT '',
    employee_type      LowCardinality(String) DEFAULT 'employee',
    sync_hash          String DEFAULT '',
    last_synced_at     DateTime64(3) DEFAULT now64(3),
    version            UInt64,
    username_lc        String MATERIALIZED lower(username),
    upn_lc             String MATERIALIZED lower(upn),
    email_lc           String MATERIALIZED lower(email)
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (provider_id, external_id);

-- Dictionary: user_registry_dict (keyed by lowercased username, sources from
-- the ClickHouse user_registry table — NAN-1117; was PostgreSQL-sourced).
-- Attributes/key/LAYOUT(HASHED()) are byte-identical to the prior PG dict so
-- the 24 nanosiem.logs user_identity_* columns keep resolving unchanged.
-- argMax(..., version) GROUP BY username_lc dedups ReplacingMergeTree rows at
-- load time (merges are async); HAVING account_status != 'deleted' + the
-- username_lc != '' WHERE reproduce the old PG dict filter. groups is
-- comma-joined to keep user_identity_groups a String (matching PG
-- array_to_string(groups, ',')).
CREATE DICTIONARY IF NOT EXISTS nanosiem.user_registry_dict
(
    username String,
    email String DEFAULT '',
    display_name String DEFAULT '',
    department String DEFAULT '',
    title String DEFAULT '',
    manager_upn String DEFAULT '',
    manager_display_name String DEFAULT '',
    company String DEFAULT '',
    groups String DEFAULT '',
    account_enabled UInt8 DEFAULT 1,
    account_status String DEFAULT '',
    mfa_enabled UInt8 DEFAULT 0,
    employee_type String DEFAULT '',
    country String DEFAULT '',
    office_location String DEFAULT ''
)
PRIMARY KEY username
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT * FROM (SELECT username_lc AS username, argMax(email, version) AS email, argMax(display_name, version) AS display_name, argMax(department, version) AS department, argMax(title, version) AS title, argMax(manager_upn, version) AS manager_upn, argMax(manager_display_name, version) AS manager_display_name, argMax(company, version) AS company, argMax(arrayStringConcat(groups, '',''), version) AS groups, argMax(account_enabled, version) AS account_enabled, argMax(account_status, version) AS account_status, argMax(mfa_enabled, version) AS mfa_enabled, argMax(employee_type, version) AS employee_type, argMax(country, version) AS country, argMax(office_location, version) AS office_location FROM nanosiem.user_registry WHERE username_lc != '''' GROUP BY username_lc) WHERE account_status != ''deleted'''
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(HASHED());

-- =============================================================================
-- BASE TABLES
-- =============================================================================

-- Table: logs
CREATE TABLE IF NOT EXISTS nanosiem.logs
(
    `id` UUID DEFAULT generateUUIDv7() CODEC(ZSTD(3)),
    `timestamp` DateTime64(6, 'UTC') CODEC(Delta(8), ZSTD(3)),
    `message` String CODEC(ZSTD(3)),
    `metadata` String CODEC(ZSTD(3)),
    `source_type` LowCardinality(String) DEFAULT 'unknown' CODEC(ZSTD(1)),
    `source` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `ingest_time` DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta(8), ZSTD(3)),
    `enrich_time` Nullable(DateTime64(6, 'UTC')) DEFAULT NULL CODEC(ZSTD(3)),
    `_inserted_at` DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta(8), ZSTD(3)),
    `src_ip` String DEFAULT '' CODEC(ZSTD(1)),
    `dest_ip` String DEFAULT '' CODEC(ZSTD(1)),
    `src_host` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `dest_host` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `src_port` UInt16 DEFAULT 0 CODEC(T64, LZ4),
    `dest_port` UInt16 DEFAULT 0 CODEC(T64, LZ4),
    `protocol` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `bytes_in` UInt64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `bytes_out` UInt64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `packets_in` UInt64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `packets_out` UInt64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `direction` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `src_mac` String DEFAULT '' CODEC(ZSTD(1)),
    `dest_mac` String DEFAULT '' CODEC(ZSTD(1)),
    `vlan` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `user` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `src_user` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `dest_user` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `user_id` String DEFAULT '' CODEC(ZSTD(1)),
    `user_name` String DEFAULT '' CODEC(ZSTD(1)),
    `user_domain` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `user_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `action` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `event_type` LowCardinality(String) ALIAS action,
    `status` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `status_code` UInt16 DEFAULT 0 CODEC(T64, LZ4),
    `result` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `severity` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `category` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `auth_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `auth_result` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `session_id` String DEFAULT '' CODEC(ZSTD(1)),
    `authentication_method` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `process_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `process_id` UInt32 DEFAULT 0 CODEC(T64, LZ4),
    `process_path` String DEFAULT '' CODEC(ZSTD(1)),
    `process_hash` String DEFAULT '' CODEC(ZSTD(3)),
    `process_guid` String MATERIALIZED if((src_host != '') AND (process_id != 0), lower(hex(cityHash64(concat(src_host, '_', toString(process_id))))), '') CODEC(ZSTD(3)),
    `parent_command_line` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `parent_process_id` UInt32 DEFAULT 0 CODEC(T64, LZ4),
    `parent_process_path` String DEFAULT '' CODEC(ZSTD(1)),
    `file_path` String DEFAULT '' CODEC(ZSTD(1)),
    `file_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `file_hash` String DEFAULT '' CODEC(ZSTD(3)),
    `file_size` UInt64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `file_action` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `registry_path` String DEFAULT '' CODEC(ZSTD(1)),
    `registry_key_name` String DEFAULT '' CODEC(ZSTD(1)),
    `registry_value_name` String DEFAULT '' CODEC(ZSTD(1)),
    `registry_value_data` String DEFAULT '' CODEC(ZSTD(1)),
    `url` String DEFAULT '' CODEC(ZSTD(1)),
    `url_domain` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `uri_path` String DEFAULT '' CODEC(ZSTD(1)),
    `http_method` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `http_user_agent` String DEFAULT '' CODEC(ZSTD(1)),
    `http_referrer` String DEFAULT '' CODEC(ZSTD(1)),
    `http_content_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `http_status_code` UInt16 DEFAULT 0 CODEC(T64, LZ4),
    `query` String DEFAULT '' CODEC(ZSTD(1)),
    `query_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `answer` String DEFAULT '' CODEC(ZSTD(1)),
    `dns_answers` String DEFAULT '' CODEC(ZSTD(1)),
    `record_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `sender` String DEFAULT '' CODEC(ZSTD(1)),
    `sender_domain` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `recipient` String DEFAULT '' CODEC(ZSTD(1)),
    `recipient_domain` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `subject` String DEFAULT '' CODEC(ZSTD(1)),
    `message_id` String DEFAULT '' CODEC(ZSTD(1)),
    `signature` String DEFAULT '' CODEC(ZSTD(1)),
    `signature_id` String DEFAULT '' CODEC(ZSTD(1)),
    `cve` String DEFAULT '' CODEC(ZSTD(1)),
    `mitre_technique_id` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `rule_id` String DEFAULT '' CODEC(ZSTD(1)),
    `rule_name` String DEFAULT '' CODEC(ZSTD(1)),
    `vendor_product` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `risk_entity` String DEFAULT '' CODEC(ZSTD(1)),
    `risk_score` Float32 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
    `risk_level` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `dvc` String DEFAULT '' CODEC(ZSTD(1)),
    `dvc_ip` String DEFAULT '' CODEC(ZSTD(1)),
    `dvc_mac` String DEFAULT '' CODEC(ZSTD(1)),
    `duration` Int64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `response_time` Int64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `user_agent` String DEFAULT '' CODEC(ZSTD(1)),
    `ext` JSON(max_dynamic_paths = 512) DEFAULT '{}' CODEC(ZSTD(3)),
    `enriched_src_country` LowCardinality(String) MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_src_country_code` LowCardinality(String) MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_src_continent` LowCardinality(String) MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_src_asn` String MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_src_as_name` String MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_country` LowCardinality(String) MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_country_code` LowCardinality(String) MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'country_code', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_continent` LowCardinality(String) MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_asn` String MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'asn', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_as_name` String MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_name', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_src_as_domain` String MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_domain', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_domain', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_src_continent_code` LowCardinality(String) MATERIALIZED if(src_ip != '', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent_code', toIPv4OrDefault(src_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent_code', toIPv6OrDefault(src_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_as_domain` String MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_domain', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'as_domain', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    `enriched_dest_continent_code` LowCardinality(String) MATERIALIZED if(dest_ip != '', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent_code', toIPv4OrDefault(dest_ip), ''), dictGetOrDefault('nanosiem.ip_enrichment_dict', 'continent_code', toIPv6OrDefault(dest_ip), '')), '') CODEC(ZSTD(1)),
    -- IOC enrichment columns (dictionary lookups from ioc_enrichment_dict at insert time)
    `ioc_matched` UInt8 DEFAULT 0 CODEC(T64, LZ4),
    `ioc_src_ip_threat_type` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', src_ip, ''), '') CODEC(ZSTD(1)),
    `ioc_src_ip_malware` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', src_ip, ''), '') CODEC(ZSTD(1)),
    `ioc_src_ip_confidence` UInt8 MATERIALIZED if(src_ip != '', toUInt8(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', src_ip, toInt32(0))), 0) CODEC(T64, LZ4),
    `ioc_dest_ip_threat_type` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', dest_ip, ''), '') CODEC(ZSTD(1)),
    `ioc_dest_ip_malware` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', dest_ip, ''), '') CODEC(ZSTD(1)),
    `ioc_dest_ip_confidence` UInt8 MATERIALIZED if(dest_ip != '', toUInt8(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', dest_ip, toInt32(0))), 0) CODEC(T64, LZ4),
    `ioc_domain_threat_type` LowCardinality(String) MATERIALIZED multiIf((url_domain != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(url_domain), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(url_domain), ''), (query != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(query), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(query), ''), '') CODEC(ZSTD(1)),
    `ioc_domain_malware` LowCardinality(String) MATERIALIZED multiIf((url_domain != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(url_domain), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(url_domain), ''), (query != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(query), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(query), ''), '') CODEC(ZSTD(1)),
    `ioc_domain_confidence` UInt8 MATERIALIZED toUInt8(multiIf((url_domain != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(url_domain), toInt32(0)) > 0), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(url_domain), toInt32(0)), (query != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(query), toInt32(0)) > 0), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(query), toInt32(0)), 0)) CODEC(T64, LZ4),
    `ioc_hash_threat_type` LowCardinality(String) MATERIALIZED multiIf((file_hash != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(file_hash), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(file_hash), ''), (process_hash != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(process_hash), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(process_hash), ''), '') CODEC(ZSTD(1)),
    `ioc_hash_malware` LowCardinality(String) MATERIALIZED multiIf((file_hash != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(file_hash), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(file_hash), ''), (process_hash != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(process_hash), '') != ''), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'malware', lower(process_hash), ''), '') CODEC(ZSTD(1)),
    `ioc_hash_confidence` UInt8 MATERIALIZED toUInt8(multiIf((file_hash != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(file_hash), toInt32(0)) > 0), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(file_hash), toInt32(0)), (process_hash != '') AND (dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(process_hash), toInt32(0)) > 0), dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'confidence_level', lower(process_hash), toInt32(0)), 0)) CODEC(T64, LZ4),
    `ioc_confidence` UInt8 MATERIALIZED greatest(ioc_src_ip_confidence, ioc_dest_ip_confidence, ioc_domain_confidence, ioc_hash_confidence) CODEC(T64, LZ4),
    `ioc_tags` String MATERIALIZED multiIf(ioc_src_ip_confidence > 0, dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', src_ip, ''), ioc_dest_ip_confidence > 0, dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', dest_ip, ''), ioc_domain_confidence > 0, dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', lower(url_domain), ''), ioc_hash_confidence > 0, dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'tags', lower(file_hash), ''), '') CODEC(ZSTD(1)),
    `ioc_source` LowCardinality(String) MATERIALIZED multiIf(ioc_src_ip_confidence > 0, toString(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', src_ip, toInt32(0))), ioc_dest_ip_confidence > 0, toString(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', dest_ip, toInt32(0))), ioc_domain_confidence > 0, toString(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', lower(url_domain), toInt32(0))), ioc_hash_confidence > 0, toString(dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'source_id', lower(file_hash), toInt32(0))), '') CODEC(ZSTD(1)),
    -- Custom enrichment columns (dictionary lookups from custom_enrichment_dict at insert time)
    `custom_src_ip_tags` Array(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', src_ip), []), []) CODEC(ZSTD(1)),
    `custom_src_ip_risk` UInt8 MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('ip', src_ip), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `custom_dest_ip_tags` Array(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', dest_ip), []), []) CODEC(ZSTD(1)),
    `custom_dest_ip_risk` UInt8 MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('ip', dest_ip), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `custom_domain_tags` Array(String) MATERIALIZED multiIf(url_domain != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('domain', lower(url_domain)), []), (dest_host != '') AND (NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')), dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('domain', lower(dest_host)), []), (src_host != '') AND (NOT match(src_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')), dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('domain', lower(src_host)), []), query != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('domain', lower(query)), []), []) CODEC(ZSTD(1)),
    `custom_domain_risk` UInt8 MATERIALIZED toUInt8(multiIf(url_domain != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('domain', lower(url_domain)), toUInt8(0)), (dest_host != '') AND (NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')), dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('domain', lower(dest_host)), toUInt8(0)), (src_host != '') AND (NOT match(src_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')), dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('domain', lower(src_host)), toUInt8(0)), query != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('domain', lower(query)), toUInt8(0)), toUInt8(0))) CODEC(T64, LZ4),
    `custom_hash_tags` Array(String) MATERIALIZED multiIf(file_hash != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('hash', lower(file_hash)), []), process_hash != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('hash', lower(process_hash)), []), []) CODEC(ZSTD(1)),
    `custom_hash_risk` UInt8 MATERIALIZED toUInt8(multiIf(file_hash != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('hash', lower(file_hash)), toUInt8(0)), process_hash != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('hash', lower(process_hash)), toUInt8(0)), toUInt8(0))) CODEC(T64, LZ4),
    `custom_url_tags` Array(String) MATERIALIZED if(url != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('url', url), []), []) CODEC(ZSTD(1)),
    `custom_url_risk` UInt8 MATERIALIZED if(url != '', dictGetOrDefault('nanosiem.custom_enrichment_dict', 'risk_score', tuple('url', url), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    -- Custom IOC enrichment (from custom_ioc_enrichment_dict)
    `custom_ioc_src_ip_threat_type` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('ip', src_ip), ''), '') CODEC(ZSTD(1)),
    `custom_ioc_src_ip_malware` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('ip', src_ip), ''), '') CODEC(ZSTD(1)),
    `custom_ioc_src_ip_confidence` UInt8 MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('ip', src_ip), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `custom_ioc_dest_ip_threat_type` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('ip', dest_ip), ''), '') CODEC(ZSTD(1)),
    `custom_ioc_dest_ip_malware` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'malware', tuple('ip', dest_ip), ''), '') CODEC(ZSTD(1)),
    `custom_ioc_dest_ip_confidence` UInt8 MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('ip', dest_ip), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `custom_ioc_domain_threat_type` LowCardinality(String) MATERIALIZED multiIf(url_domain != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('domain', lower(url_domain)), ''), query != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('domain', lower(query)), ''), '') CODEC(ZSTD(1)),
    `custom_ioc_domain_confidence` UInt8 MATERIALIZED toUInt8(multiIf(url_domain != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('domain', lower(url_domain)), toUInt8(0)), query != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('domain', lower(query)), toUInt8(0)), toUInt8(0))) CODEC(T64, LZ4),
    `custom_ioc_hash_threat_type` LowCardinality(String) MATERIALIZED multiIf(file_hash != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('hash', lower(file_hash)), ''), process_hash != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'threat_type', tuple('hash', lower(process_hash)), ''), '') CODEC(ZSTD(1)),
    `custom_ioc_hash_confidence` UInt8 MATERIALIZED toUInt8(multiIf(file_hash != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('hash', lower(file_hash)), toUInt8(0)), process_hash != '', dictGetOrDefault('nanosiem.custom_ioc_enrichment_dict', 'confidence', tuple('hash', lower(process_hash)), toUInt8(0)), toUInt8(0))) CODEC(T64, LZ4),
    -- Identity enrichment (from user_registry_dict, keyed by user/src_user/dest_user)
    `user_identity_department` LowCardinality(String) MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'department', lower("user"), ''), '') CODEC(ZSTD(1)),
    `user_identity_title` LowCardinality(String) MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'title', lower("user"), ''), '') CODEC(ZSTD(1)),
    `user_identity_groups` String MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'groups', lower("user"), ''), '') CODEC(ZSTD(1)),
    `user_identity_account_status` LowCardinality(String) MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'account_status', lower("user"), ''), '') CODEC(ZSTD(1)),
    `user_identity_employee_type` LowCardinality(String) MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'employee_type', lower("user"), ''), '') CODEC(ZSTD(1)),
    `user_identity_mfa_enabled` UInt8 MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'mfa_enabled', lower("user"), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `user_identity_country` LowCardinality(String) MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'country', lower("user"), ''), '') CODEC(ZSTD(1)),
    `user_identity_display_name` String MATERIALIZED if("user" != '', dictGetOrDefault('nanosiem.user_registry_dict', 'display_name', lower("user"), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_department` LowCardinality(String) MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'department', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_title` LowCardinality(String) MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'title', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_groups` String MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'groups', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_account_status` LowCardinality(String) MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'account_status', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_employee_type` LowCardinality(String) MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'employee_type', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_mfa_enabled` UInt8 MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'mfa_enabled', lower(src_user), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `src_user_identity_country` LowCardinality(String) MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'country', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `src_user_identity_display_name` String MATERIALIZED if(src_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'display_name', lower(src_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_department` LowCardinality(String) MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'department', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_title` LowCardinality(String) MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'title', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_groups` String MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'groups', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_account_status` LowCardinality(String) MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'account_status', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_employee_type` LowCardinality(String) MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'employee_type', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_mfa_enabled` UInt8 MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'mfa_enabled', lower(dest_user), toUInt8(0)), toUInt8(0)) CODEC(T64, LZ4),
    `dest_user_identity_country` LowCardinality(String) MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'country', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    `dest_user_identity_display_name` String MATERIALIZED if(dest_user != '', dictGetOrDefault('nanosiem.user_registry_dict', 'display_name', lower(dest_user), ''), '') CODEC(ZSTD(1)),
    -- Additional fields from migrations
    `namespace` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    -- Cloud context fields
    `cloud_provider` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `cloud_account_id` String DEFAULT '' CODEC(ZSTD(1)),
    `cloud_account_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `cloud_region` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `cloud_service` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    -- Resource fields
    `resource_id` String DEFAULT '' CODEC(ZSTD(1)),
    `resource_name` String DEFAULT '' CODEC(ZSTD(1)),
    `resource_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    -- Change tracking & MFA
    `change_type` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `mfa_used` UInt8 DEFAULT 0 CODEC(T64, LZ4),
    `parent_process_guid` String MATERIALIZED if((src_host != '') AND (parent_process_id != 0), lower(hex(cityHash64(concat(src_host, '_', toString(parent_process_id))))), '') CODEC(ZSTD(3)),
    `parent_process_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `command_line` String DEFAULT '' CODEC(ZSTD(1)),
    -- Prevalence columns (lookup from prevalence dictionaries)
    `prevalence_file_hash` UInt16 MATERIALIZED if(file_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(file_hash), toUInt16(9999)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_process_hash` UInt16 MATERIALIZED if(process_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(process_hash), toUInt16(9999)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_dest_domain` UInt16 MATERIALIZED if(dest_host != '' AND NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(dest_host), toUInt16(9999)), toUInt16(65535)) CODEC(T64, LZ4),
    `prevalence_dest_ip` UInt16 MATERIALIZED if(dest_ip != '' AND NOT (startsWith(dest_ip, '10.') OR startsWith(dest_ip, '172.16.') OR startsWith(dest_ip, '192.168.') OR startsWith(dest_ip, '127.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', dest_ip, toUInt16(9999)), toUInt16(65535)) CODEC(T64, LZ4),
    -- prevalence_min: inlined dict lookups instead of cross-column DEFAULT references
    -- (ClickHouse 26.x analyzer can't resolve inter-column DEFAULT refs during INSERT)
    `prevalence_min` UInt16 DEFAULT least(
        if(file_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(file_hash), toUInt16(9999)), toUInt16(9999)),
        if(process_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(process_hash), toUInt16(9999)), toUInt16(9999)),
        if(dest_host != '' AND NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(dest_host), toUInt16(9999)), toUInt16(9999)),
        if(dest_ip != '' AND NOT (startsWith(dest_ip, '10.') OR startsWith(dest_ip, '172.16.') OR startsWith(dest_ip, '192.168.') OR startsWith(dest_ip, '127.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', dest_ip, toUInt16(9999)), toUInt16(9999))
    ) CODEC(T64, LZ4),
    -- Flexible enrichment output columns
    `enrichment_label_1` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_value_1` String DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_label_2` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_value_2` String DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_label_3` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_value_3` String DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_label_4` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_value_4` String DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_label_5` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `enrichment_value_5` String DEFAULT '' CODEC(ZSTD(1)),
    INDEX idx_src_ip src_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dest_ip dest_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_src_mac src_mac TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dest_mac dest_mac TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user user TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user_words lower(user) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_src_user src_user TYPE bloom_filter GRANULARITY 4,
    INDEX idx_src_user_words lower(src_user) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_dest_user dest_user TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dest_user_words lower(dest_user) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_user_id user_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_process_name process_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_process_name_words lower(process_name) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_process_hash process_hash TYPE bloom_filter GRANULARITY 4,
    INDEX idx_process_guid process_guid TYPE bloom_filter GRANULARITY 4,
    INDEX idx_command_line command_line TYPE bloom_filter GRANULARITY 4,
    INDEX idx_command_line_words lower(command_line) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_parent_command_line parent_command_line TYPE bloom_filter GRANULARITY 4,
    INDEX idx_parent_command_line_words lower(parent_command_line) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_file_path_words lower(file_path) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_file_hash file_hash TYPE bloom_filter GRANULARITY 4,
    INDEX idx_file_name file_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_registry_path_words lower(registry_path) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_url_domain url_domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_http_method http_method TYPE set(20) GRANULARITY 4,
    INDEX idx_http_user_agent_words lower(http_user_agent) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_query_words lower(query) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_answer answer TYPE bloom_filter GRANULARITY 4,
    INDEX idx_sender sender TYPE bloom_filter GRANULARITY 4,
    INDEX idx_sender_domain sender_domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_recipient recipient TYPE bloom_filter GRANULARITY 4,
    INDEX idx_recipient_domain recipient_domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_subject_words lower(subject) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_message_id message_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_signature signature TYPE bloom_filter GRANULARITY 4,
    INDEX idx_signature_id signature_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_cve cve TYPE bloom_filter GRANULARITY 4,
    INDEX idx_mitre_technique mitre_technique_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_rule_id rule_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_action action TYPE set(100) GRANULARITY 4,
    INDEX idx_status status TYPE set(100) GRANULARITY 4,
    INDEX idx_source_type source_type TYPE set(100) GRANULARITY 4,
    INDEX idx_severity severity TYPE set(20) GRANULARITY 4,
    INDEX idx_category category TYPE set(100) GRANULARITY 4,
    INDEX idx_risk_entity risk_entity TYPE bloom_filter GRANULARITY 4,
    INDEX idx_message_words lower(message) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_inserted_at _inserted_at TYPE minmax GRANULARITY 4,
    -- Enrichment field indexes (GeoIP / ASN lookups)
    INDEX idx_enriched_src_country enriched_src_country TYPE set(200) GRANULARITY 4,
    INDEX idx_enriched_src_country_code enriched_src_country_code TYPE set(200) GRANULARITY 4,
    INDEX idx_enriched_src_asn enriched_src_asn TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_src_as_name enriched_src_as_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_src_as_domain enriched_src_as_domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_src_continent enriched_src_continent TYPE set(10) GRANULARITY 4,
    INDEX idx_enriched_src_continent_code enriched_src_continent_code TYPE set(10) GRANULARITY 4,
    INDEX idx_enriched_dest_country enriched_dest_country TYPE set(200) GRANULARITY 4,
    INDEX idx_enriched_dest_country_code enriched_dest_country_code TYPE set(200) GRANULARITY 4,
    INDEX idx_enriched_dest_asn enriched_dest_asn TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_dest_as_name enriched_dest_as_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_dest_as_domain enriched_dest_as_domain TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enriched_dest_continent enriched_dest_continent TYPE set(10) GRANULARITY 4,
    INDEX idx_enriched_dest_continent_code enriched_dest_continent_code TYPE set(10) GRANULARITY 4,
    -- Cloud field indexes
    INDEX idx_cloud_provider cloud_provider TYPE set(20) GRANULARITY 4,
    INDEX idx_cloud_account_id cloud_account_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_cloud_account_name cloud_account_name TYPE set(500) GRANULARITY 4,
    INDEX idx_cloud_region cloud_region TYPE set(100) GRANULARITY 4,
    INDEX idx_cloud_service cloud_service TYPE set(200) GRANULARITY 4,
    INDEX idx_resource_id resource_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_resource_name_words lower(resource_name) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_resource_type resource_type TYPE set(200) GRANULARITY 4,
    INDEX idx_change_type change_type TYPE set(20) GRANULARITY 4,
    INDEX idx_src_host src_host TYPE bloom_filter GRANULARITY 4,
    INDEX idx_src_host_words lower(src_host) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_dest_host dest_host TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dest_host_words lower(dest_host) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    INDEX idx_enrichment_value_1 enrichment_value_1 TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enrichment_value_2 enrichment_value_2 TYPE bloom_filter GRANULARITY 4,
    INDEX idx_enrichment_value_3 enrichment_value_3 TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source_type, timestamp, src_host, src_ip, cityHash64(id))
SAMPLE BY cityHash64(id)
TTL timestamp + toIntervalDay(365)
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000
;

-- Table: signals
CREATE TABLE IF NOT EXISTS nanosiem.signals
(
    `id` UUID DEFAULT generateUUIDv7(),
    `timestamp` DateTime64(6, 'UTC'),
    `rule_id` UUID,
    `rule_name` String,
    `severity` LowCardinality(String),
    `risk_score` Int32,
    `risk_entity` String,
    `matched_log_id` UUID,
    `metadata` String DEFAULT '{}',
    `_inserted_at` DateTime64(6, 'UTC') DEFAULT now64(6),
    INDEX idx_rule_id rule_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_risk_entity risk_entity TYPE bloom_filter GRANULARITY 4,
    INDEX idx_severity severity TYPE set(10) GRANULARITY 4,
    INDEX idx_matched_log_id matched_log_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, rule_id, risk_entity)
TTL timestamp + toIntervalDay(365)
SETTINGS index_granularity = 8192
;

-- Table: ingestion_errors
CREATE TABLE IF NOT EXISTS nanosiem.ingestion_errors
(
    `id` UUID DEFAULT generateUUIDv7(),
    `timestamp` DateTime64(6, 'UTC') DEFAULT now64(6),
    `error_type` LowCardinality(String),
    `error_message` String,
    `raw_content` String,
    `source_info` String DEFAULT '',
    `_inserted_at` DateTime64(6, 'UTC') DEFAULT now64(6),
    INDEX idx_error_type error_type TYPE set(50) GRANULARITY 4,
    INDEX idx_error_message error_message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, error_type)
TTL timestamp + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- Table: _migrations (tracks applied schema migrations)
CREATE TABLE IF NOT EXISTS nanosiem._migrations
(
    `version` String,
    `name` String,
    `applied_at` DateTime64(6, 'UTC') DEFAULT now64(6),
    `checksum` String DEFAULT ''
)
ENGINE = MergeTree
ORDER BY (version)
SETTINGS index_granularity = 8192
;

-- =============================================================================
-- MATERIALIZED VIEWS (must be created after base tables)
-- =============================================================================

-- Materialized View: domain_prevalence_mv
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_mv TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(dest_host) AS domain,
    if(length(splitByChar('.', dest_host)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (dest_host != '') AND (position(dest_host, '.') > 0) AND (NOT match(dest_host, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(dest_host, ':') > 0)) AND match(dest_host, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', dest_host)[-1]) >= 2) AND (NOT match(splitByChar('.', dest_host)[-1], '^[0-9]+$')) AND (length(dest_host) <= 253)
    -- NAN-366: drop internal/non-public TLDs (e.g. ws-support-041.corp.local) to keep domain_prevalence focused on real domains.
    AND (lower(splitByChar('.', dest_host)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY
    domain,
    is_subdomain,
    time_bucket
UNION ALL
SELECT
    lower(query) AS domain,
    if(length(splitByChar('.', query)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (query != '') AND (position(query, '.') > 0) AND (NOT match(query, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(query, ':') > 0)) AND match(query, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', query)[-1]) >= 2) AND (NOT match(splitByChar('.', query)[-1], '^[0-9]+$')) AND (length(query) <= 253) AND ((dest_host = '') OR (lower(dest_host) != lower(query)))
    AND (lower(splitByChar('.', query)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY
    domain,
    is_subdomain,
    time_bucket
UNION ALL
SELECT
    lower(url_domain) AS domain,
    if(length(splitByChar('.', url_domain)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (url_domain != '') AND (position(url_domain, '.') > 0) AND (NOT match(url_domain, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND match(url_domain, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', url_domain)[-1]) >= 2) AND (NOT match(splitByChar('.', url_domain)[-1], '^[0-9]+$')) AND (length(url_domain) <= 253) AND ((dest_host = '') OR (lower(dest_host) != lower(url_domain))) AND ((query = '') OR (lower(query) != lower(url_domain)))
    AND (lower(splitByChar('.', url_domain)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY
    domain,
    is_subdomain,
    time_bucket
;

-- Materialized View: hash_prevalence_mv
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_mv TO nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` String,
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(file_hash) AS file_hash,
    multiIf(length(file_hash) = 32, 'md5', length(file_hash) = 40, 'sha1', length(file_hash) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (file_hash != '') AND ((length(file_hash) = 32) OR (length(file_hash) = 40) OR (length(file_hash) = 64)) AND match(file_hash, '^[a-fA-F0-9]+$')
GROUP BY
    file_hash,
    hash_type,
    time_bucket
UNION ALL
SELECT
    lower(process_hash) AS file_hash,
    multiIf(length(process_hash) = 32, 'md5', length(process_hash) = 40, 'sha1', length(process_hash) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (process_hash != '') AND ((length(process_hash) = 32) OR (length(process_hash) = 40) OR (length(process_hash) = 64)) AND match(process_hash, '^[a-fA-F0-9]+$') AND ((file_hash = '') OR (lower(file_hash) != lower(process_hash)))
GROUP BY
    process_hash,
    hash_type,
    time_bucket
;

-- Materialized View: process_hash_prevalence_mv
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.process_hash_prevalence_mv TO nanosiem.hash_prevalence_agg
(
    `file_hash` String,
    `hash_type` String,
    `time_bucket` DateTime('UTC'),
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    process_hash AS file_hash,
    multiIf(length(process_hash) = 32, 'md5', length(process_hash) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (process_hash != '') AND ((length(process_hash) = 32) OR (length(process_hash) = 64)) AND match(process_hash, '^[a-fA-F0-9]+$')
GROUP BY
    process_hash,
    hash_type,
    time_bucket
;

-- Materialized View: ip_prevalence_mv
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_mv TO nanosiem.ip_prevalence_agg AS
SELECT
    dest_ip AS ip,
    'dest' AS direction,
    if(
        match(dest_ip, '^10\\.') OR
        match(dest_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(dest_ip, '^192\\.168\\.') OR
        match(dest_ip, '^127\\.') OR
        match(dest_ip, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE dest_ip != ''
  AND match(dest_ip, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(dest_ip, '^127\\.')
  AND NOT match(dest_ip, '^169\\.254\\.')
GROUP BY ip, direction, is_private, time_bucket
UNION ALL
SELECT
    src_ip AS ip,
    'src' AS direction,
    if(
        match(src_ip, '^10\\.') OR
        match(src_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(src_ip, '^192\\.168\\.') OR
        match(src_ip, '^127\\.') OR
        match(src_ip, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(dest_host != '', dest_host, if(dest_ip != '', dest_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE src_ip != ''
  AND match(src_ip, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(src_ip, '^127\\.')
  AND NOT match(src_ip, '^169\\.254\\.')
  AND src_ip != dest_ip
GROUP BY ip, direction, is_private, time_bucket;

-- =============================================================================
-- Prevalence Summary MVs (NAN-365)
-- Chained off *_prevalence_agg (pass-through — no GROUP BY). The summary
-- table's AggregatingMergeTree merges states in the background.
-- =============================================================================

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

-- Per-source_type 5-minute log telemetry MV (NAN-733).
-- Lowercases source_type at write time so callers don't have to.
-- AggregatingMergeTree merges identical (source_type, bucket_start) rows in
-- the background. Target table is declared above near the prevalence summary
-- tables.
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

-- Table: entity_time_range_agg
-- Pre-aggregates first/last seen timestamps for asset entities (IPs and hostnames)
CREATE TABLE IF NOT EXISTS nanosiem.entity_time_range_agg
(
    `entity_type` LowCardinality(String),  -- 'src_ip' or 'src_host'
    `entity_value` String,                  -- IP address or lower(hostname)
    `time_bucket` DateTime('UTC'),
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `last_seen` SimpleAggregateFunction(max, DateTime64(6, 'UTC')),
    `event_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_entity_value entity_value TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (entity_type, entity_value, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

-- Materialized View: entity_time_range_mv
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_time_range_mv TO nanosiem.entity_time_range_agg AS
SELECT
    'src_ip' AS entity_type,
    src_ip AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.logs
WHERE src_ip != ''
GROUP BY entity_type, entity_value, time_bucket
UNION ALL
SELECT
    'src_host' AS entity_type,
    lower(src_host) AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.logs
WHERE src_host != ''
GROUP BY entity_type, entity_value, time_bucket;

-- ============================================================================
-- Cloud User Activity Aggregation (for cloud investigation Users tab)
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.cloud_user_activity_agg
(
    user String,
    time_bucket DateTime,
    event_count SimpleAggregateFunction(sum, UInt64),
    fail_count SimpleAggregateFunction(sum, UInt64),
    permission_change_count SimpleAggregateFunction(sum, UInt64),
    delete_count SimpleAggregateFunction(sum, UInt64),
    mfa_count SimpleAggregateFunction(sum, UInt64),
    no_mfa_count SimpleAggregateFunction(sum, UInt64),
    distinct_services AggregateFunction(uniq, String),
    distinct_regions AggregateFunction(uniq, String),
    distinct_ips AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (user, time_bucket)
TTL time_bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.cloud_user_activity_mv
TO nanosiem.cloud_user_activity_agg AS
SELECT
    user,
    toStartOfHour(timestamp) AS time_bucket,
    count() AS event_count,
    countIf(http_status_code >= 400) AS fail_count,
    countIf(change_type = 'permission_change') AS permission_change_count,
    countIf(change_type = 'delete') AS delete_count,
    countIf(mfa_used = 1) AS mfa_count,
    countIf(mfa_used = 0) AS no_mfa_count,
    uniqState(cloud_service) AS distinct_services,
    uniqState(cloud_region) AS distinct_regions,
    uniqState(src_ip) AS distinct_ips
FROM nanosiem.logs
WHERE cloud_provider != '' AND user != ''
GROUP BY user, time_bucket;

-- =============================================================================
-- Identity Resolution (IP-to-hostname/user binding via ASOF JOIN)
-- =============================================================================

-- Table: identity_observations
-- Stores temporal identity observations for IP-to-identity resolution.
-- Populated by MV from any log source with src_ip + src_host.
CREATE TABLE IF NOT EXISTS nanosiem.identity_observations
(
    observed_at DateTime64(3, 'UTC'),
    ip String,
    hostname String,
    fqdn String DEFAULT '',
    mac String DEFAULT '',
    user String DEFAULT '',
    source LowCardinality(String),
    domain LowCardinality(String) DEFAULT '',
    ip_type LowCardinality(String) DEFAULT 'private',
    namespace LowCardinality(String) DEFAULT '',
    source_priority UInt8 DEFAULT 50,
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_hostname hostname TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user user TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (ip, observed_at)
TTL observed_at + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Table: nat_candidates
-- Tracks IPs with multiple hostnames per hour (NAT gateways, VPN concentrators).
CREATE TABLE IF NOT EXISTS nanosiem.nat_candidates
(
    ip String,
    hour DateTime,
    host_count UInt32,
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (ip, hour)
TTL hour + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- Materialized View: identity_observations_mv
-- Auto-populates identity_observations from logs with src_ip + src_host (private IPs only).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.identity_observations_mv
TO nanosiem.identity_observations
AS
SELECT
    timestamp AS observed_at,
    src_ip AS ip,
    if(
        position(src_host, '.') > 0 AND position(src_host, '.corp.') > 0,
        substring(src_host, 1, position(src_host, '.') - 1),
        src_host
    ) AS hostname,
    src_host AS fqdn,
    src_mac AS mac,
    user AS user,
    source_type AS source,
    multiIf(
        position(user, '\\') > 0, substring(user, 1, position(user, '\\') - 1),
        position(src_host, '.corp.') > 0, 'corp',
        ''
    ) AS domain,
    multiIf(
        match(src_ip, '^10\\.'), 'private',
        match(src_ip, '^192\\.168\\.'), 'private',
        match(src_ip, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'), 'private',
        match(src_ip, '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'), 'vpn',
        match(src_ip, '^127\\.'), 'loopback',
        'public'
    ) AS ip_type,
    namespace AS namespace
FROM nanosiem.logs
WHERE
    src_ip != ''
    AND src_host != ''
    AND (
        match(src_ip, '^10\\.') OR
        match(src_ip, '^192\\.168\\.') OR
        match(src_ip, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    )
    AND src_ip NOT IN ('127.0.0.1', '::1', '0.0.0.0')
    AND src_host NOT IN ('localhost', '-', 'unknown', 'UNKNOWN', '');

-- Materialized View: nat_detection_mv
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.nat_detection_mv
TO nanosiem.nat_candidates
AS
SELECT
    ip,
    toStartOfHour(observed_at) AS hour,
    toUInt32(1) AS host_count
FROM nanosiem.identity_observations
GROUP BY ip, hour;

-- View: nat_candidates_view
-- Shows IPs with 3+ distinct hostnames in the last 7 days (likely NAT/VPN).
CREATE OR REPLACE VIEW nanosiem.nat_candidates_view AS
SELECT
    ip,
    hour,
    uniqExact(hostname) AS host_count
FROM nanosiem.identity_observations
WHERE observed_at >= now() - INTERVAL 7 DAY
GROUP BY ip, toStartOfHour(observed_at) AS hour
HAVING host_count >= 3;

-- =============================================================================
-- SETTINGS PROFILES (query resource limits per priority tier)
-- =============================================================================

CREATE SETTINGS PROFILE IF NOT EXISTS 'nanosiem_realtime'
SETTINGS
    max_execution_time = 30,
    max_memory_usage = 5368709120,   -- 5 GB
    max_threads = 8,
    priority = 1,
    queue_max_wait_ms = 5000;

CREATE SETTINGS PROFILE IF NOT EXISTS 'nanosiem_interactive'
SETTINGS
    max_execution_time = 300,
    max_memory_usage = 21474836480,  -- 20 GB
    max_threads = 16,
    priority = 3,
    queue_max_wait_ms = 60000;

CREATE SETTINGS PROFILE IF NOT EXISTS 'nanosiem_analytics'
SETTINGS
    max_execution_time = 3600,
    max_memory_usage = 53687091200,  -- 50 GB
    max_threads = 32,
    priority = 5,
    queue_max_wait_ms = 120000;

