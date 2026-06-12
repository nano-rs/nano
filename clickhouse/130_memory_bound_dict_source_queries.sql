-- Migration: memory-bound every ClickHouse-sourced dictionary load query
-- (NAN-1404 — Saturn total silent ingestion halt, 2026-06-10).
--
-- INCIDENT: CH-sourced dictionary loads run their source SELECT inside the
-- SAME ClickHouse server as ingestion. ip_enrichment_dict's source (repointed
-- to CH in 123, uncapped in 126) dedup-aggregates the full IPinfo Lite set
-- (~3.9M CIDR ranges) with argMax GROUP BY. On Saturn's 8GiB spec node the
-- aggregation hash table ballooned until the server-wide memory cap denied
-- the allocation (MEMORY_LIMIT_EXCEEDED ... while executing
-- AggregatingTransform), the dict went FAILED, and every insert's
-- MATERIALIZED dictGetOrDefault columns then THREW at async-insert flush —
-- Vector was already ACKed (wait_for_async_insert=0), so 36h of logs went to
-- /dev/null silently. hash_prevalence_dict CACHE updates OOMed on the same
-- mechanism. Same blast radius as NAN-1114/122/123/126; NEW trigger: the
-- load query's aggregation memory, which grows with data volume and is
-- otherwise unbounded.
--
-- FIX (code fits the spec footprint — explicitly NOT a memory bump; 8GiB
-- worked for months): bound every CH-sourced dict load query in the QUERY
-- text itself:
--   * max_bytes_before_external_group_by — when the aggregation state passes
--     this threshold it SPILLS to disk instead of growing in RAM. Empirically
--     (local CH, the real 3.9M-row ip_enrichments): unbounded peak 815MiB;
--     with spill the same query completes at ~126MiB peak. Without spill a
--     low cap fails with the exact Saturn signature (Code 241, while
--     executing AggregatingTransform).
--   * max_memory_usage — hard per-query ceiling so a pathological load can
--     never crowd ingestion out of the node again; with the spill threshold
--     set well below it, the cap should never actually be hit.
--   * max_threads = 2 — aggregation memory is per-thread hash tables and the
--     load shares the box with ingestion; 2 threads bounds both the memory
--     multiplier and CPU steal.
--
-- VALUES:
--   * Full-reload dicts (ip_enrichment, ioc_enrichment, custom_enrichment,
--     custom_ioc_enrichment, user_registry — HASHED/IP_TRIE, reload the whole
--     source every LIFETIME): spill at 1e9 (1GB), cap 2.5e9 (2.5GB). On an
--     8GiB node sharing with ~1.5GiB ingestion baseline + flush/MV transients
--     this leaves >4GiB headroom even at the (never-expected) cap.
--   * CACHE prevalence dicts (hash/domain/ip — key-pushdown miss queries,
--     normally tiny; the 512MiB cap from migration 112 stays): spill at
--     268435456 (256MB) so a miss-storm aggregation spills instead of
--     throwing at the existing 536870912 cap.
--
-- Attributes / PRIMARY KEY / LAYOUT / LIFETIME of every dictionary are
-- byte-for-byte identical to the prior definitions (122/123/125/126 +
-- init.sql) — ONLY the SETTINGS at the end of each source QUERY change — so
-- all dependent nanosiem.logs MATERIALIZED columns keep resolving unchanged.
-- ip_enrichment_dict keeps the dict-level SETTINGS(max_result_rows = 0,
-- max_result_bytes = 0) from 126 (result caps are a different limit class
-- than memory; both are needed).
--
-- The runner substitutes {clickhouse_self_*} placeholders (NAN-707). Both
-- init.sql files are kept in lockstep (guard test:
-- nanosiem-core/tests/dict_source_memory_guard.rs). Prior migrations are
-- left untouched (editing them trips ChecksumMismatch).
--
-- Idempotent: CREATE OR REPLACE DICTIONARY (atomic swap). DDL-only — no data
-- movement (NAN-1398).

-- 1. ip_enrichment_dict — THE Saturn killer. Full-reload IP_TRIE over the
--    complete IPinfo Lite set; the argMax dedup is the unbounded aggregation.
CREATE OR REPLACE DICTIONARY nanosiem.ip_enrichment_dict
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
    QUERY 'SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain FROM nanosiem.ip_enrichments GROUP BY network HAVING argMax(deleted, updated_at) = 0 SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);

-- 2. ioc_enrichment_dict — full-reload HASHED over marketplace IOC rows.
CREATE OR REPLACE DICTIONARY nanosiem.ioc_enrichment_dict
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
    GROUP BY key_value
    SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2'
))
LIFETIME(MIN 60 MAX 300)
LAYOUT(HASHED());

-- 3. custom_enrichment_dict — full-reload COMPLEX_KEY_HASHED.
CREATE OR REPLACE DICTIONARY nanosiem.custom_enrichment_dict
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
    GROUP BY key_type, key_value
    SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- 4. custom_ioc_enrichment_dict — full-reload COMPLEX_KEY_HASHED.
CREATE OR REPLACE DICTIONARY nanosiem.custom_ioc_enrichment_dict
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
    GROUP BY key_type, key_value
    SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- 5. user_registry_dict — full-reload HASHED; the argMax×15 dedup grows with
--    directory size × re-sync count (ReplacingMergeTree keeps old versions
--    until merges).
CREATE OR REPLACE DICTIONARY nanosiem.user_registry_dict
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
    QUERY 'SELECT * FROM (SELECT username_lc AS username, argMax(email, version) AS email, argMax(display_name, version) AS display_name, argMax(department, version) AS department, argMax(title, version) AS title, argMax(manager_upn, version) AS manager_upn, argMax(manager_display_name, version) AS manager_display_name, argMax(company, version) AS company, argMax(arrayStringConcat(groups, '',''), version) AS groups, argMax(account_enabled, version) AS account_enabled, argMax(account_status, version) AS account_status, argMax(mfa_enabled, version) AS mfa_enabled, argMax(employee_type, version) AS employee_type, argMax(country, version) AS country, argMax(office_location, version) AS office_location FROM nanosiem.user_registry WHERE username_lc != '''' GROUP BY username_lc) WHERE account_status != ''deleted'' SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(HASHED());

-- 6-8. Prevalence CACHE dicts — key-pushdown miss queries are normally tiny,
--      but Saturn showed their uniqMerge aggregations OOMing (Code 241 inside
--      510) when the node is under memory pressure. Keep the migration-112
--      512MiB cap; add the spill threshold below it + max_threads = 2.
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
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
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
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));

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
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));
