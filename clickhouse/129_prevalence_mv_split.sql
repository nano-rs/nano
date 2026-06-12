-- =============================================================================
-- 129: split the prevalence MV family's UNION ALL bodies (NAN-1393)
-- =============================================================================
--
-- ClickHouse attaches a materialized view's insert trigger ONLY to the FIRST
-- SELECT of a UNION ALL body — the exact mechanism that killed
-- entity_time_range_mv's src_host branch (migration 128 / NAN-1386). The
-- prevalence MV family shipped with the same shape, so on BOTH profiles only
-- the first branch of each MV ever fired:
--
--   UDM (clickhouse/init.sql):
--     ip_prevalence_mv      — dest_ip fired; src_ip branch DEAD
--     domain_prevalence_mv  — dest_host fired; query (DNS) + url_domain DEAD
--     hash_prevalence_mv    — file_hash fired; process_hash branch DEAD
--   OCSF (clickhouse/ocsf/init.sql):
--     ocsf_ip_prevalence_summary_mv     — src_endpoint.ip branch DEAD
--     ocsf_domain_prevalence_summary_mv — query.hostname + url.hostname DEAD
--     ocsf_hash_prevalence_summary_mv   — process.file.hashes.sha256 DEAD
--
-- Fix: drop each UNION ALL view and create one MV per branch, all writing to
-- the SAME target table (the AggregatingMergeTree targets merge uniq states
-- across producers, so no reader/table changes are needed). Branch bodies are
-- copied verbatim from the UNION ALL branches, including the cross-branch
-- dedup filters (e.g. the query branch still skips rows whose query equals
-- dest_host, so a single event never counts one domain twice).
--
-- process_hash_prevalence_mv (archived migration 055) was a standalone
-- workaround bolted on when process hashes were observed missing — i.e. a
-- symptom of this very bug. It is dropped here and replaced by
-- hash_prevalence_process_hash_mv, which carries the ORIGINAL branch's
-- semantics that 055 lacked: lower(process_hash) (the prevalence_process_hash
-- MATERIALIZED column and the readers look hashes up lowercased, so verbatim
-- uppercase hashes could never match), sha1 (length 40) support, and the
-- dedup-vs-file_hash filter. Keeping both MVs would double total_count for
-- every process-hash event.
--
-- The dedup filter is written with a table-qualified `logs.file_hash`: the
-- branch's `lower(process_hash) AS file_hash` alias SHADOWS the real
-- file_hash column inside WHERE (ClickHouse substitutes the alias
-- expression, NAN-1034), turning the unqualified original
-- `(file_hash = '') OR (lower(file_hash) != lower(process_hash))` into an
-- always-false predicate — the original branch would have dropped every row
-- even if its trigger had fired. Verified on CH 26.4 that the qualified form
-- resolves the real column both in a plain SELECT and at MV insert-push time.
--
-- NO backfill of the starved branches (NAN-1398): an INSERT…SELECT over logs /
-- ocsf_logs inside the boot-gating migrator is a multi-TB aggregation on
-- production tenants — it would fail the migration and crashloop the API
-- (NAN-800 fails fast on a behind schema). The dead branches never wrote a
-- row, so production has zero existing rows for them; prevalence on those
-- entities cold-starts from the new MVs, which is its current state anyway.
-- If historical prevalence ever matters, run it as a chunked background job —
-- never in the migration path.
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): ClickHouse checks the INSERTING
-- user's column-level SELECT on nanosiem.ocsf_logs for every column an MV
-- over it reads. The per-branch OCSF MVs below read exactly the columns the
-- old UNION ALL bodies read (timestamp, src/dst_endpoint.ip,
-- src/dst_endpoint.hostname, query.hostname, url.hostname,
-- file.hashes.sha256, process.file.hashes.sha256) — all already granted to
-- nanosiem_ingest in clickhouse/users.d/nanosiem-users.xml and the deploy
-- templates. No grant change required.
--
-- Statements reading nanosiem.ocsf_logs carry the `nano:skip-if-unknown-table`
-- marker: the table only exists on NANO_SCHEMA_PROFILE=ocsf deployments and
-- UDM-only deployments must not fail this migration.
--
-- Keep in lockstep with clickhouse/init.sql + clickhouse/ocsf/init.sql
-- (fresh bootstraps) — nanosiem-core/tests/aggregation_mv_schema_guard.rs
-- enforces equivalence.

-- ============================================================================
-- PART 1 — UDM side (clickhouse/init.sql counterparts)
-- ============================================================================

DROP VIEW IF EXISTS nanosiem.ip_prevalence_mv;
DROP VIEW IF EXISTS nanosiem.domain_prevalence_mv;
DROP VIEW IF EXISTS nanosiem.hash_prevalence_mv;
DROP VIEW IF EXISTS nanosiem.process_hash_prevalence_mv;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_dest_ip_mv TO nanosiem.ip_prevalence_agg AS
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
GROUP BY ip, direction, is_private, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_src_ip_mv TO nanosiem.ip_prevalence_agg AS
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

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_dest_host_mv TO nanosiem.domain_prevalence_agg
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
    AND (lower(splitByChar('.', dest_host)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY
    domain,
    is_subdomain,
    time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_query_mv TO nanosiem.domain_prevalence_agg
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
    time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_url_domain_mv TO nanosiem.domain_prevalence_agg
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
    time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_file_hash_mv TO nanosiem.hash_prevalence_agg
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
    time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_process_hash_mv TO nanosiem.hash_prevalence_agg
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
    lower(process_hash) AS file_hash,
    multiIf(length(process_hash) = 32, 'md5', length(process_hash) = 40, 'sha1', length(process_hash) = 64, 'sha256', 'unknown') AS hash_type,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (process_hash != '') AND ((length(process_hash) = 32) OR (length(process_hash) = 40) OR (length(process_hash) = 64)) AND match(process_hash, '^[a-fA-F0-9]+$') AND ((logs.file_hash = '') OR (lower(logs.file_hash) != lower(process_hash)))
GROUP BY
    process_hash,
    hash_type,
    time_bucket;

-- ============================================================================
-- PART 2 — OCSF side (clickhouse/ocsf/init.sql counterparts)
-- ============================================================================

DROP VIEW IF EXISTS nanosiem.ocsf_ip_prevalence_summary_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_hash_prevalence_summary_mv;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv /* nano:skip-if-unknown-table */
TO nanosiem.ip_prevalence_summary
(
    `ip` String,
    `is_private` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `dst_endpoint.ip` AS ip,
    if(
        match(`dst_endpoint.ip`, '^10\\.') OR
        match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`dst_endpoint.ip`, '^192\\.168\\.') OR
        match(`dst_endpoint.ip`, '^127\\.') OR
        match(`dst_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.ip` != ''
  AND match(`dst_endpoint.ip`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')
  AND NOT match(`dst_endpoint.ip`, '^127\\.')
  AND NOT match(`dst_endpoint.ip`, '^169\\.254\\.')
GROUP BY ip, is_private;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_ip_prevalence_summary_src_ip_mv /* nano:skip-if-unknown-table */
TO nanosiem.ip_prevalence_summary
(
    `ip` String,
    `is_private` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    `src_endpoint.ip` AS ip,
    if(
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^127\\.') OR
        match(`src_endpoint.ip`, '^169\\.254\\.'),
        1, 0
    ) AS is_private,
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
GROUP BY ip, is_private;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_dest_host_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_summary
(
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6),
    `last_seen` DateTime64(6),
    `total_count` UInt64
)
AS SELECT
    lower(`dst_endpoint.hostname`) AS domain,
    if(length(splitByChar('.', `dst_endpoint.hostname`)) > 2, 1, 0) AS is_subdomain,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`dst_endpoint.hostname` != '') AND (position(`dst_endpoint.hostname`, '.') > 0) AND (NOT match(`dst_endpoint.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`dst_endpoint.hostname`, ':') > 0)) AND match(`dst_endpoint.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `dst_endpoint.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `dst_endpoint.hostname`)[-1], '^[0-9]+$')) AND (length(`dst_endpoint.hostname`) <= 253)
    AND (lower(splitByChar('.', `dst_endpoint.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_query_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_summary
(
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6),
    `last_seen` DateTime64(6),
    `total_count` UInt64
)
AS SELECT
    lower(`query.hostname`) AS domain,
    if(length(splitByChar('.', `query.hostname`)) > 2, 1, 0) AS is_subdomain,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`query.hostname` != '') AND (position(`query.hostname`, '.') > 0) AND (NOT match(`query.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND (NOT (position(`query.hostname`, ':') > 0)) AND match(`query.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `query.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `query.hostname`)[-1], '^[0-9]+$')) AND (length(`query.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`query.hostname`)))
    AND (lower(splitByChar('.', `query.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_domain_prevalence_summary_url_mv /* nano:skip-if-unknown-table */
TO nanosiem.domain_prevalence_summary
(
    `domain` String,
    `is_subdomain` UInt8,
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6),
    `last_seen` DateTime64(6),
    `total_count` UInt64
)
AS SELECT
    lower(`url.hostname`) AS domain,
    if(length(splitByChar('.', `url.hostname`)) > 2, 1, 0) AS is_subdomain,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`url.hostname` != '') AND (position(`url.hostname`, '.') > 0) AND (NOT match(`url.hostname`, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$')) AND match(`url.hostname`, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') AND (length(splitByChar('.', `url.hostname`)[-1]) >= 2) AND (NOT match(splitByChar('.', `url.hostname`)[-1], '^[0-9]+$')) AND (length(`url.hostname`) <= 253) AND ((`dst_endpoint.hostname` = '') OR (lower(`dst_endpoint.hostname`) != lower(`url.hostname`))) AND ((`query.hostname` = '') OR (lower(`query.hostname`) != lower(`url.hostname`)))
    AND (lower(splitByChar('.', `url.hostname`)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_file_hash_mv /* nano:skip-if-unknown-table */
TO nanosiem.hash_prevalence_summary
(
    `file_hash` String,
    `hash_type` String,
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6),
    `last_seen` DateTime64(6),
    `total_count` UInt64
)
AS SELECT
    `file.hashes.sha256` AS file_hash,
    multiIf(length(`file.hashes.sha256`) = 32, 'md5', length(`file.hashes.sha256`) = 40, 'sha1', length(`file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`file.hashes.sha256` != '') AND ((length(`file.hashes.sha256`) = 32) OR (length(`file.hashes.sha256`) = 40) OR (length(`file.hashes.sha256`) = 64)) AND match(`file.hashes.sha256`, '^[a-fA-F0-9]+$')
GROUP BY file_hash, hash_type;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_hash_prevalence_summary_process_hash_mv /* nano:skip-if-unknown-table */
TO nanosiem.hash_prevalence_summary
(
    `file_hash` String,
    `hash_type` String,
    `host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6),
    `last_seen` DateTime64(6),
    `total_count` UInt64
)
AS SELECT
    `process.file.hashes.sha256` AS file_hash,
    multiIf(length(`process.file.hashes.sha256`) = 32, 'md5', length(`process.file.hashes.sha256`) = 40, 'sha1', length(`process.file.hashes.sha256`) = 64, 'sha256', 'unknown') AS hash_type,
    uniqState(if(`src_endpoint.hostname` != '', `src_endpoint.hostname`, if(`src_endpoint.ip` != '', `src_endpoint.ip`, 'unknown'))) AS host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.ocsf_logs
WHERE (`process.file.hashes.sha256` != '') AND ((length(`process.file.hashes.sha256`) = 32) OR (length(`process.file.hashes.sha256`) = 40) OR (length(`process.file.hashes.sha256`) = 64)) AND match(`process.file.hashes.sha256`, '^[a-fA-F0-9]+$') AND ((`file.hashes.sha256` = '') OR (`file.hashes.sha256` != `process.file.hashes.sha256`))
GROUP BY file_hash, hash_type;
