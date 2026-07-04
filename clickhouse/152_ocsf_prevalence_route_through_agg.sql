-- =============================================================================
-- 152: route the OCSF prevalence branch MVs through *_prevalence_agg
--      (NAN-1661 — OCSF agg-layer bypass)
-- =============================================================================
--
-- The seven ocsf_*_prevalence_summary_*_mv views (clickhouse/ocsf/init.sql)
-- wrote DIRECTLY into the entity-keyed *_prevalence_summary tables, BYPASSING
-- the hourly *_prevalence_agg tables. Every explorer / rare / new / export /
-- single / bulk / daily-heatmap / scatter surface reads *_prevalence_agg, so on
-- OCSF-profile tenants all of those returned "never seen" — even though the
-- summary-sourced prevalence dicts worked (which masked the bug):
--   dictGetOrDefault('domain_prevalence_dict','host_count','accounts.google.com')
-- returned 251 while the agg-table query returned 0 rows.
--
-- Fix (Option A — the safe/reversible one; the alternative was repointing the
-- Rust agg readers at the summary tables under the OCSF profile, but the
-- summary tables lack the time_bucket / direction / parent_domain columns the
-- scatter/heatmap queries need, and it would have spread OCSF-awareness through
-- the query generators): retarget the seven OCSF branch MVs at the shared
-- *_prevalence_agg tables, EXACTLY like the UDM per-branch MVs
-- (clickhouse/init.sql / 129_prevalence_mv_split.sql). The already-existing
-- chained *_prevalence_summary_mv views (agg -> summary) then fan the agg
-- states into the summary tables via MV chaining, so ONE write path now feeds
-- BOTH the agg-reading surfaces AND the summary-sourced dicts.
--
-- The MV NAMES ARE UNCHANGED (they keep the historical *_prevalence_summary_*
-- names, misleading as that now is) so
-- nanosiem-core/tests/aggregation_mv_schema_guard.rs keeps pinning them and so
-- this migration and clickhouse/ocsf/init.sql stay in lockstep.
--
-- NO backfill: the agg tables cold-start from now (the OCSF direct-write path
-- has no pre-existing agg history, and a MATERIALIZE/INSERT…SELECT over
-- ocsf_logs inside the boot-gating migrator would be a multi-TB aggregation —
-- forbidden, NAN-1398/1404). Historical summary rows written by the old direct
-- MVs remain and keep the dicts warm; agg-reading surfaces become correct for
-- data ingested from the migration forward.
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): these MVs read the same ocsf_logs
-- columns as before (src/dst endpoint host+ip, file/process hashes, query/url
-- hostnames, timestamp) — the nanosiem_ingest column grants are unchanged.
--
-- Statements touching nanosiem.ocsf_logs carry the `nano:skip-if-unknown-table`
-- marker: ocsf_logs only exists on NANO_SCHEMA_PROFILE=ocsf deployments, and
-- UDM-only deployments must not fail this migration.
--
-- Keep in lockstep with clickhouse/ocsf/init.sql (fresh bootstraps);
-- nanosiem-core/tests/aggregation_mv_schema_guard.rs pins that lockstep.
--
-- The *_prevalence_agg tables and the chained agg -> summary MVs
-- (hash/domain/ip_prevalence_summary_mv) already exist on every deployment —
-- clickhouse/init.sql (NAN-365) creates them at bootstrap and migrations run
-- after it — so this migration only swaps the seven OCSF branch MVs.
-- clickhouse/ocsf/init.sql additionally re-declares those agg tables + chained
-- MVs IF NOT EXISTS so a fresh OCSF bootstrap is self-sufficient.

-- ---------------------------------------------------------------------------
-- Swap the seven OCSF branch MVs: drop the summary-writing versions, recreate
-- them writing into *_prevalence_agg. DROP VIEW IF EXISTS is a no-op on tenants
-- that never had them; the CREATEs read ocsf_logs and carry the skip marker.
-- ---------------------------------------------------------------------------

-- Hash prevalence (file + process hashes) -> hash_prevalence_agg.
DROP VIEW IF EXISTS nanosiem.ocsf_hash_prevalence_summary_file_hash_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_file_hash_mv /* nano:skip-if-unknown-table */
TO nanosiem.hash_prevalence_agg
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
    lower(`file.hashes.sha256`) AS file_hash,
    multiIf(length(`file.hashes.sha256`) = 32, 'md5', length(`file.hashes.sha256`) = 40, 'sha1', length(`file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`file.hashes.sha256` != '') AND ((length(`file.hashes.sha256`) = 32) OR (length(`file.hashes.sha256`) = 40) OR (length(`file.hashes.sha256`) = 64)) AND match(`file.hashes.sha256`, '^[a-fA-F0-9]+$')
GROUP BY file_hash, hash_type, time_bucket;

DROP VIEW IF EXISTS nanosiem.ocsf_hash_prevalence_summary_process_hash_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_process_hash_mv /* nano:skip-if-unknown-table */
TO nanosiem.hash_prevalence_agg
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
    lower(`process.file.hashes.sha256`) AS file_hash,
    multiIf(length(`process.file.hashes.sha256`) = 32, 'md5', length(`process.file.hashes.sha256`) = 40, 'sha1', length(`process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`process.file.hashes.sha256` != '') AND ((length(`process.file.hashes.sha256`) = 32) OR (length(`process.file.hashes.sha256`) = 40) OR (length(`process.file.hashes.sha256`) = 64)) AND match(`process.file.hashes.sha256`, '^[a-fA-F0-9]+$') AND ((`file.hashes.sha256` = '') OR (lower(`file.hashes.sha256`) != lower(`process.file.hashes.sha256`)))
GROUP BY file_hash, hash_type, time_bucket;

-- Domain prevalence (dst_endpoint.hostname / query.hostname / url.hostname)
-- -> domain_prevalence_agg.
DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_dest_host_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_dest_host_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_agg
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
    lower(`dst_endpoint.hostname`) AS domain,
    if(length(splitByChar('.', `dst_endpoint.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`dst_endpoint.hostname` != '') AND (position(`dst_endpoint.hostname`, '.') > 0) AND (NOT match(`dst_endpoint.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`dst_endpoint.hostname`, ':') > 0)) AND match(`dst_endpoint.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `dst_endpoint.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `dst_endpoint.hostname`)[-1], '^[0-9]+$')) AND (length(`dst_endpoint.hostname`) <= 253)
    AND (lower(splitByChar('.', `dst_endpoint.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_query_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_query_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_agg
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
    lower(`query.hostname`) AS domain,
    if(length(splitByChar('.', `query.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`query.hostname` != '') AND (position(`query.hostname`, '.') > 0) AND (NOT match(`query.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`query.hostname`, ':') > 0)) AND match(`query.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `query.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `query.hostname`)[-1], '^[0-9]+$')) AND (length(`query.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`query.hostname`)))
    AND (lower(splitByChar('.', `query.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_url_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_url_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_agg
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
    lower(`url.hostname`) AS domain,
    if(length(splitByChar('.', `url.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`url.hostname` != '') AND (position(`url.hostname`, '.') > 0) AND (NOT match(`url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND match(`url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `url.hostname`)[-1], '^[0-9]+$')) AND (length(`url.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`url.hostname`))) AND ((`query.hostname` = '') OR (lower(`query.hostname`) != lower(`url.hostname`)))
    AND (lower(splitByChar('.', `url.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

-- IP prevalence (dst_endpoint.ip / src_endpoint.ip) -> ip_prevalence_agg.
DROP VIEW IF EXISTS nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv /* nano:skip-if-unknown-table */
TO nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` String,
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `dst_endpoint.ip` AS ip,
    'dest' AS direction,
    if(
        match(`dst_endpoint.ip`, '^10\\.') OR
        match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`dst_endpoint.ip`, '^192\\.168\\.') OR
        match(`dst_endpoint.ip`, '^127\\.') OR
        match(`dst_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.ip` != ''
  AND match(`dst_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`dst_endpoint.ip`, '^127\\.')
  AND NOT match(`dst_endpoint.ip`, '^169\\.254\\.')
GROUP BY ip, direction, is_private, time_bucket;

DROP VIEW IF EXISTS nanosiem.ocsf_ip_prevalence_summary_src_ip_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_src_ip_mv /* nano:skip-if-unknown-table */
TO nanosiem.ip_prevalence_agg
(
    `ip` String,
    `direction` String,
    `is_private` UInt8,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `src_endpoint.ip` AS ip,
    'src' AS direction,
    if(
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^127\\.') OR
        match(`src_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`dst_endpoint.hostname` != '', `dst_endpoint.hostname`, if(`dst_endpoint.ip` != '', `dst_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `src_endpoint.ip` != ''
  AND match(`src_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`src_endpoint.ip`, '^127\\.')
  AND NOT match(`src_endpoint.ip`, '^169\\.254\\.')
  AND `src_endpoint.ip` != `dst_endpoint.ip`
GROUP BY ip, direction, is_private, time_bucket;
