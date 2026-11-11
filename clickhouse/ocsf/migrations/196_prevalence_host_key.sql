-- =============================================================================
-- OCSF/196: prevalence MVs count hosts from the class-correct host field
-- (NAN-5271 lane A)
-- =============================================================================
-- The nine OCSF prevalence producers keyed "which host saw this" on
-- src_endpoint.hostname, then src_endpoint.ip, then the literal 'unknown'.
-- Endpoint classes (Sysmon file 1001, process 1007, module 1005, registry
-- 201001/201002) leave src_endpoint.* empty and carry the host in
-- device.hostname, so every endpoint row landed on the single host 'unknown':
-- every file/process hash had host_count = 1 (measured locally: 355 of 355
-- hashes; the top process hash is really on ~500 hosts). That broke rare-hash
-- hunting, prevalence-filtered detections, the MATERIALIZED prevalence_*
-- columns (fed by the dictionaries over these aggregates) and the shadow
-- investigation prevalence step.
--
-- Fix: insert src_host_unified (src_endpoint.hostname else device.hostname)
-- before 'unknown'. Only rows that previously fell through to 'unknown' change
-- key; every row that already had a src_endpoint hostname or IP keeps exactly
-- the same key, so network-class counts are unchanged. src_endpoint.ip stays
-- ahead of device.hostname on purpose: on proxy/firewall classes device is the
-- reporting appliance, and keying on it would collapse every client into one
-- host. src_host_unified is used instead of `device.hostname` because it is
-- already in nanosiem_ingest's column-scoped SELECT grant (users.d and the
-- deploy templates), so direct OCSF writers need no grant change.
--
-- The direction='src' branch of the IP producers counts DESTINATION hosts
-- (mirrors UDM) and is not changed.
--
-- NO BACKFILL. Aggregate rows already written keep their old 'unknown' host
-- state; uniq states merge, so a hash's host_count over a window spanning the
-- upgrade is (true hosts seen after the upgrade) + 1 for the old 'unknown'
-- bucket, and becomes fully correct once pre-upgrade buckets age out of the
-- prevalence window. Rebuilding history is an operator task, never boot work.
--
-- MODIFY QUERY (no DROP + CREATE) so no insert ever runs without the MVs; it
-- takes the SELECT directly, no `AS` (NAN-1727). The migrator adds ON CLUSTER.
-- Bodies are byte-identical to clickhouse/ocsf/init.sql (fresh installs get
-- them from the overlay; this migration then re-applies the same query, a
-- no-op), and tests/ocsf_prevalence_host_key_guard.rs pins the two together.
-- Re-running is safe: MODIFY QUERY to the same body is idempotent.

ALTER TABLE nanosiem.ocsf_hash_prevalence_summary_file_hash_mv
MODIFY QUERY SELECT
    lower(`file.hashes.sha256`) AS file_hash,
    multiIf(length(`file.hashes.sha256`) = 32, 'md5', length(`file.hashes.sha256`) = 40, 'sha1', length(`file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`file.hashes.sha256` != '') AND ((length(`file.hashes.sha256`) = 32) OR (length(`file.hashes.sha256`) = 40) OR (length(`file.hashes.sha256`) = 64)) AND match(`file.hashes.sha256`, '^[a-fA-F0-9]+$')
GROUP BY file_hash, hash_type, time_bucket;

ALTER TABLE nanosiem.ocsf_hash_prevalence_summary_process_hash_mv
MODIFY QUERY SELECT
    lower(`process.file.hashes.sha256`) AS file_hash,
    multiIf(length(`process.file.hashes.sha256`) = 32, 'md5', length(`process.file.hashes.sha256`) = 40, 'sha1', length(`process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`process.file.hashes.sha256` != '') AND ((length(`process.file.hashes.sha256`) = 32) OR (length(`process.file.hashes.sha256`) = 40) OR (length(`process.file.hashes.sha256`) = 64)) AND match(`process.file.hashes.sha256`, '^[a-fA-F0-9]+$') AND ((`file.hashes.sha256` = '') OR (lower(`file.hashes.sha256`) != lower(`process.file.hashes.sha256`)))
GROUP BY file_hash, hash_type, time_bucket;

ALTER TABLE nanosiem.ocsf_domain_prevalence_summary_dest_host_mv
MODIFY QUERY SELECT
    lower(`dst_endpoint.hostname`) AS domain,
    if(length(splitByChar('.', `dst_endpoint.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`dst_endpoint.hostname` != '') AND (position(`dst_endpoint.hostname`, '.') > 0) AND (NOT match(`dst_endpoint.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`dst_endpoint.hostname`, ':') > 0)) AND match(`dst_endpoint.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `dst_endpoint.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `dst_endpoint.hostname`)[-1], '^[0-9]+$')) AND (length(`dst_endpoint.hostname`) <= 253)
    AND (lower(splitByChar('.', `dst_endpoint.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

ALTER TABLE nanosiem.ocsf_domain_prevalence_summary_query_mv
MODIFY QUERY SELECT
    lower(`query.hostname`) AS domain,
    if(length(splitByChar('.', `query.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`query.hostname` != '') AND (position(`query.hostname`, '.') > 0) AND (NOT match(`query.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`query.hostname`, ':') > 0)) AND match(`query.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `query.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `query.hostname`)[-1], '^[0-9]+$')) AND (length(`query.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`query.hostname`)))
    AND (lower(splitByChar('.', `query.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

ALTER TABLE nanosiem.ocsf_domain_prevalence_summary_url_mv
MODIFY QUERY SELECT
    lower(`url.hostname`) AS domain,
    if(length(splitByChar('.', `url.hostname`)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`url.hostname` != '') AND (position(`url.hostname`, '.') > 0) AND (NOT match(`url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND match(`url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `url.hostname`)[-1], '^[0-9]+$')) AND (length(`url.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`url.hostname`))) AND ((`query.hostname` = '') OR (lower(`query.hostname`) != lower(`url.hostname`)))
    AND (lower(splitByChar('.', `url.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;

ALTER TABLE nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv
MODIFY QUERY SELECT
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
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.ip` != ''
  AND match(`dst_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`dst_endpoint.ip`, '^127\\.')
  AND NOT match(`dst_endpoint.ip`, '^169\\.254\\.')
GROUP BY ip, direction, is_private, time_bucket;

ALTER TABLE nanosiem.hash_prevalence_source_ocsf_mv
MODIFY QUERY SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(hash_value) AS file_hash,
    multiIf(length(hash_value) = 32, 'md5', length(hash_value) = 40, 'sha1',
            length(hash_value) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
                 if(`src_endpoint.ip` != '', `src_endpoint.ip`,
                    if(src_host_unified != '', src_host_unified, 'unknown')))) AS host_count,
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

ALTER TABLE nanosiem.domain_prevalence_source_ocsf_mv
MODIFY QUERY SELECT
    'ocsf' AS schema_profile,
    lower(trimBoth(source_type)) AS source_type,
    lower(domain_value) AS domain,
    if(length(splitByChar('.', domain_value)) > 2, 1, 0) AS is_subdomain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`,
                 if(`src_endpoint.ip` != '', `src_endpoint.ip`,
                    if(src_host_unified != '', src_host_unified, 'unknown')))) AS source_host_count,
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

ALTER TABLE nanosiem.ip_prevalence_source_ocsf_mv
MODIFY QUERY SELECT
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
        if(`src_endpoint.ip` != '', `src_endpoint.ip`,
           if(src_host_unified != '', src_host_unified, 'unknown')))),
    (if(`src_endpoint.ip` != `dst_endpoint.ip`, `src_endpoint.ip`, ''), 'src',
     if(`dst_endpoint.hostname` != '', `dst_endpoint.hostname`,
        if(`dst_endpoint.ip` != '', `dst_endpoint.ip`, 'unknown')))
] AS ip_tuple
WHERE ip != ''
  AND match(ip, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(ip, '^127\\.')
  AND NOT match(ip, '^169\\.254\\.')
GROUP BY schema_profile, source_type, ip, direction, is_private, time_bucket;
