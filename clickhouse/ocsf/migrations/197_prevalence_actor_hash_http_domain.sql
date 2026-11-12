-- =============================================================================
-- OCSF/197: prevalence for parent/actor process hashes and HTTP URL hosts
-- (NAN-5271 #23)
-- =============================================================================
-- The OCSF prevalence producers and the MATERIALIZED prevalence_* columns
-- ignored two populated fields:
--   * actor.process.file.hashes.sha256 (the parent / initiating process on
--     Sysmon-style process, file, network and registry classes), so parent
--     binaries never got a host count and prevalence_process_hash was 65535
--     ("not applicable") on every row that only carried the actor hash;
--   * http_request.url.hostname (HTTP Activity 4002 and proxy classes), so
--     HTTP rows had no domain prevalence at all (measured locally: 196,463
--     HTTP rows, none with a domain host count). The MATERIALIZED
--     prevalence_dest_domain also never looked at the URL or DNS query host.
--
-- What this does:
--   1. Four NEW producer views (CREATE ... IF NOT EXISTS), one per value, never
--      a UNION ALL body (NAN-1393): branch views into *_prevalence_agg and
--      source-attributed views into *_prevalence_source_agg. Each skips a value
--      an existing producer already counts on the same row, so total_count is
--      not doubled. Existing producer bodies (152/170/196) are NOT modified.
--   2. MODIFY COLUMN on the two MATERIALIZED columns: prevalence_process_hash
--      falls back to the actor process hash; prevalence_dest_domain falls back
--      to http_request.url.hostname, then url.hostname, then query.hostname.
--      A row that already had a process hash or a non-IP dst_endpoint.hostname
--      keeps the exact same lookup. Changing a MATERIALIZED expression is a
--      metadata-only ALTER: existing parts are not rewritten (no mutation).
--
-- NO BACKFILL. Rows written before the upgrade keep their stored prevalence_*
-- values and are not replayed into the aggregates; parent hashes and HTTP
-- hosts build up from new events and are fully covered once the prevalence
-- window has rolled past the upgrade. Rebuilding history is an operator task.
--
-- NO INGEST GRANT CHANGE: the four views are `SQL SECURITY DEFINER` with
-- `DEFINER = CURRENT_USER` (the migrator's admin user), like ocsf_logs_raw_mv.
-- ClickHouse then runs their SELECT with the definer's privileges, not the
-- inserting user's, so nanosiem_ingest needs no SELECT on
-- `http_request.url.hostname` and its users.xml / Helm users.json / k8s grants
-- are unchanged. This matters for ordering: users.xml grants are declarative
-- (a SQL GRANT here fails 495 ACCESS_STORAGE_READONLY), and on `helm upgrade`
-- the migrate hook runs BEFORE the ClickHouseCluster CR carrying a new grant
-- is applied. A legacy (invoker) view reading an ungranted column would fail
-- EVERY nanosiem_ingest insert into ocsf_logs_raw with ACCESS_DENIED until the
-- operator reconciled, and for good after a failed or rolled-back upgrade.
-- The two MATERIALIZED columns need no grant either (default expressions are
-- not SELECT-checked). The definer does not widen nanosiem_ingest: it still
-- cannot SELECT the column itself.
--
-- Bodies are byte-identical to clickhouse/ocsf/init.sql (fresh installs get
-- them from the overlay; IF NOT EXISTS and MODIFY COLUMN to the same
-- expression are then no-ops). tests/ocsf_prevalence_actor_http_guard.rs pins
-- the two together. The migrator adds ON CLUSTER.

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_actor_process_hash_mv
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
DEFINER = CURRENT_USER SQL SECURITY DEFINER
AS SELECT
    lower(`actor.process.file.hashes.sha256`) AS file_hash,
    multiIf(length(`actor.process.file.hashes.sha256`) = 32, 'md5', length(`actor.process.file.hashes.sha256`) = 40, 'sha1', length(`actor.process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`actor.process.file.hashes.sha256` != '') AND ((length(`actor.process.file.hashes.sha256`) = 32) OR (length(`actor.process.file.hashes.sha256`) = 40) OR (length(`actor.process.file.hashes.sha256`) = 64)) AND match(`actor.process.file.hashes.sha256`, '^[a-fA-F0-9]+$') AND ((`file.hashes.sha256` = '') OR (lower(`file.hashes.sha256`) != lower(`actor.process.file.hashes.sha256`))) AND ((`process.file.hashes.sha256` = '') OR (lower(`process.file.hashes.sha256`) != lower(`actor.process.file.hashes.sha256`)))
GROUP BY file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_http_url_mv
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
DEFINER = CURRENT_USER SQL SECURITY DEFINER
AS SELECT
    lower(`http_request.url.hostname`) AS domain,
    if(length(splitByChar('.', `http_request.url.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`http_request.url.hostname` != '') AND (position(`http_request.url.hostname`, '.') > 0) AND (NOT match(`http_request.url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`http_request.url.hostname`, ':') > 0)) AND match(`http_request.url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `http_request.url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `http_request.url.hostname`)[-1], '^[0-9]+$')) AND (length(`http_request.url.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`http_request.url.hostname`))) AND ((`query.hostname` = '') OR (lower(`query.hostname`) != lower(`http_request.url.hostname`))) AND ((`url.hostname` = '') OR (lower(`url.hostname`) != lower(`http_request.url.hostname`)))
    AND (lower(splitByChar('.', `http_request.url.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_source_ocsf_actor_process_mv
TO nanosiem.hash_prevalence_source_agg
DEFINER = CURRENT_USER SQL SECURITY DEFINER
AS SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(`actor.process.file.hashes.sha256`) AS file_hash,
    multiIf(length(`actor.process.file.hashes.sha256`) = 32, 'md5', length(`actor.process.file.hashes.sha256`) = 40, 'sha1',
            length(`actor.process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `actor.process.file.hashes.sha256` != ''
  AND length(`actor.process.file.hashes.sha256`) IN (32, 40, 64)
  AND match(`actor.process.file.hashes.sha256`, '^[a-fA-F0-9]+$')
  AND lower(`actor.process.file.hashes.sha256`) != lower(`file.hashes.sha256`)
  AND lower(`actor.process.file.hashes.sha256`) != lower(`process.file.hashes.sha256`)
GROUP BY schema_profile, source_type, file_hash, hash_type, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_source_ocsf_http_url_mv
TO nanosiem.domain_prevalence_source_agg
DEFINER = CURRENT_USER SQL SECURITY DEFINER
AS SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(`http_request.url.hostname`) AS domain,
    if(length(splitByChar('.', `http_request.url.hostname`)) > 2, 1, 0) AS is_subdomain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`http_request.url.hostname` != '') AND (position(`http_request.url.hostname`, '.') > 0) AND (NOT match(`http_request.url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`http_request.url.hostname`, ':') > 0)) AND match(`http_request.url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `http_request.url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `http_request.url.hostname`)[-1], '^[0-9]+$')) AND (length(`http_request.url.hostname`) <= 253)
  AND lower(`http_request.url.hostname`) != lower(`dst_endpoint.hostname`)
  AND lower(`http_request.url.hostname`) != lower(`query.hostname`)
  AND lower(`http_request.url.hostname`) != lower(`url.hostname`)
  AND lower(splitByChar('.', `http_request.url.hostname`)[-1]) NOT IN
      ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa')
GROUP BY schema_profile, source_type, domain, is_subdomain, time_bucket;

ALTER TABLE nanosiem.ocsf_logs
    MODIFY COLUMN `prevalence_process_hash` UInt16 MATERIALIZED if(if(`process.file.hashes.sha256` != '', `process.file.hashes.sha256`, `actor.process.file.hashes.sha256`) != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', if(`process.file.hashes.sha256` != '', `process.file.hashes.sha256`, `actor.process.file.hashes.sha256`), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.ocsf_logs
    MODIFY COLUMN `prevalence_dest_domain` UInt16 MATERIALIZED if(multiIf(`dst_endpoint.hostname` != '' AND NOT match(`dst_endpoint.hostname`, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), `dst_endpoint.hostname`, `http_request.url.hostname` != '', `http_request.url.hostname`, `url.hostname` != '', `url.hostname`, `query.hostname`) != '' AND NOT match(multiIf(`dst_endpoint.hostname` != '' AND NOT match(`dst_endpoint.hostname`, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), `dst_endpoint.hostname`, `http_request.url.hostname` != '', `http_request.url.hostname`, `url.hostname` != '', `url.hostname`, `query.hostname`), '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(multiIf(`dst_endpoint.hostname` != '' AND NOT match(`dst_endpoint.hostname`, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), `dst_endpoint.hostname`, `http_request.url.hostname` != '', `http_request.url.hostname`, `url.hostname` != '', `url.hostname`, `query.hostname`)), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);
