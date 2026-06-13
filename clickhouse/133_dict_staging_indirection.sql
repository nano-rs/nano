-- Migration: staging-table indirection for the five full-reload
-- logs-referenced ClickHouse dictionaries (NAN-1407 — insert-path
-- resilience; prevalence CACHE dicts excluded per NAN-1440, see SCOPE).
--
-- WHY: nanosiem.logs has 40+ MATERIALIZED columns calling dictGetOrDefault
-- (enriched_* / ioc_* / user_identity_* / prevalence_*). dictGetOrDefault
-- returns the default for a missing KEY, but THROWS when the dictionary
-- itself cannot load — so any single FAILED dict converts "enrichment data
-- unavailable" into ZERO ingestion platform-wide, silently under
-- wait_for_async_insert=0. We have now patched four separate TRIGGERS of
-- this class — PG source dropped (NAN-1114 → 122), PG creds rotated
-- (NAN-1117 → 123/124), ILLEGAL_AGGREGATION in the source query (NAN-1120 →
-- 125), source-query OOM (NAN-1404 → 130) — and every one was a failure of
-- the dict's COMPLEX source query. Expression-level guards don't exist:
-- dictGetOrNull / dictHas / short-circuit if() all still THROW on a FAILED
-- dict (verified on CH 26.4, NAN-1407 lab). So this migration moves the
-- fragility off the load path entirely:
--
--   1. Per dict, a plain MergeTree STAGING table holding the materialized
--      result of the old complex source query.
--   2. A REFRESHABLE MATERIALIZED VIEW (GA on our pinned CH 26.4; CH-native
--      scheduling, no app/jobs dependency) re-runs the old complex query on
--      a fixed cadence, full-replace (non-APPEND): the swap is atomic, and a
--      FAILING refresh keeps the last good staging data + surfaces the error
--      in system.view_refreshes (exception / retry / last_success_time — the
--      siem-health staleness probe reads exactly these; note 26.4 has no
--      last_refresh_result column).
--   3. The dictionary SOURCE is repointed to a trivial
--      `SELECT ... FROM <staging>` — loadable at any moment, including
--      first-load-after-restart (the fatal Saturn window: a dict that had
--      never loaded + a broken source = every insert THROWs for 36h).
--
-- Validated end-to-end on a 1-shard x 2-replica CH 26.4 rig (the Saturn
-- topology): with the refresh hard-failing, inserts keep landing with the
-- stale snapshot's enrichment, and a node restart + lazy first dict load
-- from the intact staging table succeeds.
--
-- CLUSTER SHAPE: the staging tables are deliberately PLAIN MergeTree — each
-- replica keeps an independent copy refreshed by its own MV (replicas
-- refresh independently; transient inter-replica dict skew is bounded by
-- refresh cadence + LIFETIME, no worse than today's per-replica reload
-- skew). The `nano:keep-local-engine` block-comment marker tells the
-- migration runner's cluster transform to fan the DDL out ON CLUSTER but
-- NOT convert the engine to ReplicatedMergeTree — ClickHouse REFUSES a
-- full-replace refreshable MV targeting a replicated table in a
-- non-Replicated database, so the usual conversion would abort this
-- migration on clustered tenants.
--
-- CADENCE: staleness budget = refresh cadence + dict LIFETIME (unchanged).
--   * 5 MINUTE — ip_enrichment, ioc_enrichment, custom_ioc_enrichment,
--     user_registry: identity joins and IOC matching are triage-relevant;
--     keep them near the old LIFETIME-driven freshness.
--   * 10 MINUTE — custom_enrichment: custom tags move slowly.
--
-- ⚠ SCOPE (NAN-1440): staging indirection applies to the FIVE FULL-RELOAD
-- dicts only. The three prevalence CACHE dicts (hash/domain/ip) keep their
-- migration-130 KEY-PUSHDOWN sources — CACHE layouts push the missed keys
-- into the source QUERY, so each miss is a small, memory-bounded
-- aggregation; staging them instead full-rewrote the ENTIRE aggregated
-- keyspace every 10 minutes, which does not scale. Measured on Saturn:
-- ip_prevalence_summary = 83.8M rows; the full aggregation OOMs at the
-- 512 MiB bound (Code 241 in the external-GROUP-BY merge phase — the
-- original seed below crashlooped the boot-gating migrator), and at
-- workable bounds (2.5 GB) still yields an 83.39M-row / ~1.6 GiB staging
-- table rewritten 144x/day. Accepted residual risk: a failing prevalence
-- miss query still THROWs at insert (CACHE_DICTIONARY_UPDATE_FAIL) instead
-- of degrading to stale data — bounded local-table read, surfaced by the
-- NAN-1405/1437 alarms + wait_for_async_insert=1. Section 6 below
-- re-asserts the 130 pushdown definitions (no-op for tenants coming from
-- 130; repoints any environment that ran the pre-NAN-1440 form of this
-- migration) and drops that form's prevalence staging objects.
--
-- SEEDING: each staging table is seeded with one INSERT...SELECT of the old
-- source query so an upgrading tenant's dict never observes an EMPTY staging
-- before the first refresh completes (empty would be safe — the dict loads 0
-- rows and returns defaults — but seeded preserves enrichment continuity
-- through the deploy). Each seed is guarded with
-- `WHERE (SELECT count() FROM <staging>) = 0` and skips when staging already
-- has rows: on upgrades init.sql runs FIRST (its hash changed) and creates
-- the refresh MVs, whose create-time initial refresh usually populates
-- staging before this migration's seed runs — an unguarded seed would then
-- transiently DOUBLE the staging rows (observed: 150002 vs 75001 for
-- ip_enrichment locally) until the next full-replace tick, briefly doubling
-- the IP_TRIE load footprint on exactly the memory-tight nodes NAN-1404 hit.
-- The guard also makes a partial-migration re-run idempotent. On a first
-- boot the sources are empty and the seed is a 0-row no-op either way.
--
-- The refresh queries are the old source queries VERBATIM, including the
-- NAN-1404 / migration-130 memory bounds (spill + hard cap + max_threads) —
-- the aggregation cost didn't move, only its blast radius did. Dictionary
-- attributes / PRIMARY KEY / LAYOUT / LIFETIME are byte-for-byte identical
-- to 130: this change is invisible to every dictGet caller.
-- ip_enrichment_dict keeps the dict-level SETTINGS(max_result_rows = 0,
-- max_result_bytes = 0) from 126 — the staging read still streams ~3.9M rows
-- to the dict loader, which the default profile's result caps would reject.
--
-- The runner substitutes {clickhouse_self_*} placeholders (NAN-707). Both
-- init.sql files are kept in lockstep (guard test:
-- nanosiem-core/tests/dict_source_memory_guard.rs). Prior migrations are
-- left untouched (editing them trips ChecksumMismatch).
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE MATERIALIZED VIEW IF NOT
-- EXISTS + CREATE OR REPLACE DICTIONARY (atomic swap).

-- ============================================================================
-- 1. ip_enrichment_dict — THE Saturn killer (IP_TRIE over IPinfo Lite).
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichment_dict_staging
(
    network String,
    country String,
    country_code String,
    continent String,
    continent_code String,
    asn String,
    as_name String,
    as_domain String
)
ENGINE = MergeTree /* nano:keep-local-engine */
ORDER BY network;

INSERT INTO nanosiem.ip_enrichment_dict_staging
SELECT * FROM (
    SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain
    FROM nanosiem.ip_enrichments
    GROUP BY network
    HAVING argMax(deleted, updated_at) = 0
)
WHERE (SELECT count() FROM nanosiem.ip_enrichment_dict_staging) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_enrichment_dict_refresh
REFRESH EVERY 5 MINUTE TO nanosiem.ip_enrichment_dict_staging AS
SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain
FROM nanosiem.ip_enrichments
GROUP BY network
HAVING argMax(deleted, updated_at) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

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
    QUERY 'SELECT network, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_enrichment_dict_staging'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);

-- ============================================================================
-- 2. ioc_enrichment_dict — marketplace IOC feeds (HASHED).
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.ioc_enrichment_dict_staging
(
    ioc_value String,
    ioc_type String,
    source_id String,
    threat_type String,
    malware String,
    confidence_level Int32,
    tags String
)
ENGINE = MergeTree /* nano:keep-local-engine */
ORDER BY ioc_value;

INSERT INTO nanosiem.ioc_enrichment_dict_staging
SELECT * FROM (
    SELECT
        key_value AS ioc_value,
        anyLast(key_type) AS ioc_type,
        anyLast(enrichment_name) AS source_id,
        anyLast(threat_type) AS threat_type,
        anyLast(malware) AS malware,
        toInt32(anyLast(confidence)) AS confidence_level,
        arrayStringConcat(groupUniqArrayArray(tags), ',') AS tags
    FROM (
        SELECT * FROM nanosiem.custom_enrichment_results
        WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
        ORDER BY confidence DESC
    )
    GROUP BY key_value
)
WHERE (SELECT count() FROM nanosiem.ioc_enrichment_dict_staging) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ioc_enrichment_dict_refresh
REFRESH EVERY 5 MINUTE TO nanosiem.ioc_enrichment_dict_staging AS
SELECT
    key_value AS ioc_value,
    anyLast(key_type) AS ioc_type,
    anyLast(enrichment_name) AS source_id,
    anyLast(threat_type) AS threat_type,
    anyLast(malware) AS malware,
    toInt32(anyLast(confidence)) AS confidence_level,
    arrayStringConcat(groupUniqArrayArray(tags), ',') AS tags
FROM (
    SELECT * FROM nanosiem.custom_enrichment_results
    WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
    ORDER BY confidence DESC
)
GROUP BY key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

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
    QUERY 'SELECT ioc_value, ioc_type, source_id, threat_type, malware, confidence_level, tags FROM nanosiem.ioc_enrichment_dict_staging'
))
LIFETIME(MIN 60 MAX 300)
LAYOUT(HASHED());

-- ============================================================================
-- 3. custom_enrichment_dict — user-defined non-IOC enrichments
--    (COMPLEX_KEY_HASHED).
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_dict_staging
(
    key_type String,
    key_value String,
    tags Array(String),
    risk_score UInt8,
    enrichment_names Array(String)
)
ENGINE = MergeTree /* nano:keep-local-engine */
ORDER BY (key_type, key_value);

INSERT INTO nanosiem.custom_enrichment_dict_staging
SELECT * FROM (
    SELECT
        key_type,
        key_value,
        groupUniqArrayArray(tags) as tags,
        max(coalesce(risk_score, 0)) as risk_score,
        groupUniqArray(enrichment_name) as enrichment_names
    FROM nanosiem.custom_enrichment_results
    WHERE expires_at > now() AND is_ioc = 0
    GROUP BY key_type, key_value
)
WHERE (SELECT count() FROM nanosiem.custom_enrichment_dict_staging) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.custom_enrichment_dict_refresh
REFRESH EVERY 10 MINUTE TO nanosiem.custom_enrichment_dict_staging AS
SELECT
    key_type,
    key_value,
    groupUniqArrayArray(tags) as tags,
    max(coalesce(risk_score, 0)) as risk_score,
    groupUniqArray(enrichment_name) as enrichment_names
FROM nanosiem.custom_enrichment_results
WHERE expires_at > now() AND is_ioc = 0
GROUP BY key_type, key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

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
    QUERY 'SELECT key_type, key_value, tags, risk_score, enrichment_names FROM nanosiem.custom_enrichment_dict_staging'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- ============================================================================
-- 4. custom_ioc_enrichment_dict — user-created IOC enrichments
--    (COMPLEX_KEY_HASHED).
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.custom_ioc_enrichment_dict_staging
(
    key_type String,
    key_value String,
    threat_type String,
    malware String,
    confidence UInt8,
    tags Array(String),
    enrichment_names Array(String)
)
ENGINE = MergeTree /* nano:keep-local-engine */
ORDER BY (key_type, key_value);

INSERT INTO nanosiem.custom_ioc_enrichment_dict_staging
SELECT * FROM (
    SELECT
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
)
WHERE (SELECT count() FROM nanosiem.custom_ioc_enrichment_dict_staging) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.custom_ioc_enrichment_dict_refresh
REFRESH EVERY 5 MINUTE TO nanosiem.custom_ioc_enrichment_dict_staging AS
SELECT
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
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

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
    QUERY 'SELECT key_type, key_value, threat_type, malware, confidence, tags, enrichment_names FROM nanosiem.custom_ioc_enrichment_dict_staging'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);

-- ============================================================================
-- 5. user_registry_dict — identity directory feed (HASHED). The argMax x15
--    dedup grows with directory size x re-sync count.
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.user_registry_dict_staging
(
    username String,
    email String,
    display_name String,
    department String,
    title String,
    manager_upn String,
    manager_display_name String,
    company String,
    groups String,
    account_enabled UInt8,
    account_status String,
    mfa_enabled UInt8,
    employee_type String,
    country String,
    office_location String
)
ENGINE = MergeTree /* nano:keep-local-engine */
ORDER BY username;

INSERT INTO nanosiem.user_registry_dict_staging
SELECT * FROM (SELECT username_lc AS username, argMax(email, version) AS email, argMax(display_name, version) AS display_name, argMax(department, version) AS department, argMax(title, version) AS title, argMax(manager_upn, version) AS manager_upn, argMax(manager_display_name, version) AS manager_display_name, argMax(company, version) AS company, argMax(arrayStringConcat(groups, ','), version) AS groups, argMax(account_enabled, version) AS account_enabled, argMax(account_status, version) AS account_status, argMax(mfa_enabled, version) AS mfa_enabled, argMax(employee_type, version) AS employee_type, argMax(country, version) AS country, argMax(office_location, version) AS office_location FROM nanosiem.user_registry WHERE username_lc != '' GROUP BY username_lc) WHERE account_status != 'deleted' AND (SELECT count() FROM nanosiem.user_registry_dict_staging) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.user_registry_dict_refresh
REFRESH EVERY 5 MINUTE TO nanosiem.user_registry_dict_staging AS
SELECT * FROM (SELECT username_lc AS username, argMax(email, version) AS email, argMax(display_name, version) AS display_name, argMax(department, version) AS department, argMax(title, version) AS title, argMax(manager_upn, version) AS manager_upn, argMax(manager_display_name, version) AS manager_display_name, argMax(company, version) AS company, argMax(arrayStringConcat(groups, ','), version) AS groups, argMax(account_enabled, version) AS account_enabled, argMax(account_status, version) AS account_status, argMax(mfa_enabled, version) AS mfa_enabled, argMax(employee_type, version) AS employee_type, argMax(country, version) AS country, argMax(office_location, version) AS office_location FROM nanosiem.user_registry WHERE username_lc != '' GROUP BY username_lc) WHERE account_status != 'deleted'
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

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
    QUERY 'SELECT username, email, display_name, department, title, manager_upn, manager_display_name, company, groups, account_enabled, account_status, mfa_enabled, employee_type, country, office_location FROM nanosiem.user_registry_dict_staging'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(HASHED());


-- ============================================================================
-- 6. Prevalence CACHE dicts (hash/domain/ip) — KEY-PUSHDOWN, NOT staged
--    (NAN-1440; see the SCOPE note in the header). The definitions below are
--    byte-equivalent to migration 130 and to both init.sql files: a no-op
--    swap for tenants upgrading from 130, and a repoint-back for any
--    environment that ran the pre-NAN-1440 form of this migration (whose
--    staging objects are dropped afterwards). CACHE misses push the missed
--    keys into the QUERY below, so each load is a small aggregation bounded
--    by the migration-112/130 limits (512 MiB cap, 256 MiB spill, 2
--    threads).
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

-- Clean up the pre-NAN-1440 prevalence staging objects (refresh MVs first —
-- a live refresh holds its target table). No-ops (IF EXISTS) on tenants
-- upgrading straight from 130, which never had them.
DROP VIEW IF EXISTS nanosiem.hash_prevalence_dict_refresh;
DROP VIEW IF EXISTS nanosiem.domain_prevalence_dict_refresh;
DROP VIEW IF EXISTS nanosiem.ip_prevalence_dict_refresh;
DROP TABLE IF EXISTS nanosiem.hash_prevalence_dict_staging;
DROP TABLE IF EXISTS nanosiem.domain_prevalence_dict_staging;
DROP TABLE IF EXISTS nanosiem.ip_prevalence_dict_staging;
