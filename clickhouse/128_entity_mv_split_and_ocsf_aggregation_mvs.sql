-- =============================================================================
-- 128: split entity_time_range_mv UNION ALL + OCSF-side aggregation MVs
--      (NAN-1386 / G13b + NAN-1385 / G13)
-- =============================================================================
--
-- PART 1 (NAN-1386, profile-independent — broken under BOTH UDM and OCSF):
-- ClickHouse attaches a materialized view's insert trigger ONLY to the FIRST
-- SELECT of a UNION ALL body. `entity_time_range_mv` was defined as
-- src_ip-branch UNION ALL src_host-branch, so the src_host branch NEVER fired
-- (empirically: 14,841 src_ip rows, 0 src_host rows in the agg), and the
-- asset-view reader additionally queries an entity_type='user' partition that
-- no branch ever wrote. Fix: drop the UNION ALL view and create one MV per
-- entity branch (src_ip / src_host / user), all writing to the same
-- entity_time_range_agg target. Backfill the two dead partitions from `logs`.
--
-- PART 2 (NAN-1385): every aggregation MV read FROM nanosiem.logs only, so
-- data that exists solely in nanosiem.ocsf_logs (the direct-write / no-Vector
-- ingestion path) never reached entity first/last-seen, identity observations
-- (and therefore NAT detection, which chains off identity_observations),
-- cloud Users activity, or per-source log telemetry. Fix: OCSF-side
-- counterpart MVs reading ocsf_logs into the SAME target tables, following
-- the ocsf_*_prevalence_summary_mv pattern (clickhouse/ocsf/init.sql).
--
-- Column mapping (OCSF -> UDM concept):
--   src_endpoint.ip     -> src_ip          (lowercased at ingest, like UDM)
--   src_host_unified    -> src_host        (src_endpoint.hostname else
--                                           device.hostname; both lower()'d
--                                           at ingest — no extra lower())
--   user_unified        -> user            (user.name else actor.user.name;
--                                           both lower()'d at ingest)
--   src_endpoint.mac    -> src_mac         (lower()'d at ingest)
--   source_type         -> source_type     (falls back to metadata.product.name
--                                           — THE OCSF source identifier — for
--                                           direct writers that omit it)
--   api.service.name    -> cloud_service
--   cloud.provider/region -> cloud_provider/cloud_region
--   http_response.code  -> http_status_code
--   is_mfa              -> mfa_used
--   activity_id = 4     -> change_type = 'delete' (lossy enum mapping, mirrors
--                          SearchService::change_type_activity_id; scoped to
--                          class_uid = 6003 / API Activity, where the change
--                          semantics live — activity_id 4 means other things
--                          on other classes. UDM 'permission_change' is
--                          unrepresentable in OCSF -> permission_change_count
--                          is 0 on the OCSF lane)
--   status_id = 2       -> failure (OCSF-native; OR'd with http_response.code
--                          >= 400 to cover HTTP-shaped classes)
--
-- Backfill decisions:
--   * UDM src_host/user entity partitions: backfilled from `logs` over a
--     BOUNDED 30-day window (full 90-day TTL window would block the one-shot
--     migrator for minutes at 50-100GB/day scale; first_seen for hostnames
--     and users is therefore bounded at migration time minus 30d and accrues
--     correctly from the live MVs going forward). One-hour headroom cutoff
--     (one time_bucket) mirrors migration 116's gap so rows arriving between
--     the new MVs' creation and this scan can't double-count.
--   * src_ip partition is NOT backfilled — that branch always fired; a
--     backfill would double event_count.
--   * ocsf_logs history is NOT backfilled — under the current Vector
--     dual-write every ocsf_logs row also exists in `logs` and was already
--     aggregated by the UDM-side MVs; an OCSF backfill would double-count
--     all of it. Direct-write (the path these MVs exist for) has no
--     pre-existing production history. NOTE: the same dual-write means
--     Vector-lane events are counted by BOTH MV sets going forward — same
--     accepted transitional behavior as the shipped
--     ocsf_*_prevalence_summary_mv family (uniq states merge exactly;
--     event/sum counts double only while dual-write is in place, only on
--     OCSF-profile deployments).
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): ClickHouse checks the INSERTING
-- user's column-level SELECT on nanosiem.ocsf_logs for every column an MV
-- over it reads. The column lists below are mirrored into the nanosiem_ingest
-- grants in clickhouse/users.d/nanosiem-users.xml,
-- deploy/k8s/clickhouse/clickhouse.yaml and
-- deploy/k8s/{rackspace,aws}-db/clickhouse.yaml.tpl — keep them in lockstep.
--
-- Statements touching nanosiem.ocsf_logs carry the `nano:skip-if-unknown-table`
-- marker: the table only exists on NANO_SCHEMA_PROFILE=ocsf deployments and
-- UDM-only deployments must not fail this migration.
--
-- Keep in lockstep with clickhouse/init.sql + clickhouse/ocsf/init.sql
-- (fresh bootstraps).

-- ============================================================================
-- PART 1 — split the UNION ALL entity MV (NAN-1386)
-- ============================================================================

DROP VIEW IF EXISTS nanosiem.entity_time_range_mv;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_time_range_src_ip_mv
TO nanosiem.entity_time_range_agg AS
SELECT
    'src_ip' AS entity_type,
    src_ip AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.logs
WHERE src_ip != ''
GROUP BY entity_type, entity_value, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_time_range_src_host_mv
TO nanosiem.entity_time_range_agg AS
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

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_time_range_user_mv
TO nanosiem.entity_time_range_agg AS
SELECT
    'user' AS entity_type,
    lower(user) AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.logs
WHERE user != ''
GROUP BY entity_type, entity_value, time_bucket;

-- NO backfill of the starved src_host/user partitions (NAN-1398): a 30-day
-- INSERT…SELECT over logs inside the boot-gating migrator is a multi-TB
-- aggregation on production tenants — it would fail the migration and
-- crashloop the API (NAN-800 fails fast on a behind schema). Those branches
-- were dead since inception, so production has zero existing rows for them;
-- the feature cold-starts from the new MVs, which is its current state anyway.
-- If historical first/last-seen ever matters, run it as a chunked background
-- job — never in the migration path.

-- ============================================================================
-- PART 2 — OCSF-side aggregation MVs (NAN-1385)
-- ============================================================================

-- Payload-size column for the per-source telemetry rollup. The UDM lane sums
-- length(message) + length(metadata); the OCSF analog of "the stored payload"
-- is the `event` JSON itself. Materialized so the rollup MV reads a plain
-- UInt64 — granting the INSERT-only nanosiem_ingest user SELECT on `event`
-- (raw log content) would defeat the NAN-1384 least-privilege contract, and
-- MATERIALIZED-column expressions are exempt from the MV-push SELECT check.
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD COLUMN IF NOT EXISTS `event_bytes` UInt64 MATERIALIZED length(toString(event)) CODEC(T64, LZ4);

-- Entity first/last-seen (src_ip / src_host / user), one MV per branch.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_src_ip_mv /* nano:skip-if-unknown-table */
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'src_ip' AS entity_type,
    `src_endpoint.ip` AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE `src_endpoint.ip` != ''
GROUP BY entity_type, entity_value, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_src_host_mv /* nano:skip-if-unknown-table */
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'src_host' AS entity_type,
    src_host_unified AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE src_host_unified != ''
GROUP BY entity_type, entity_value, time_bucket;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_time_range_user_mv /* nano:skip-if-unknown-table */
TO nanosiem.entity_time_range_agg
(
    `entity_type` String,
    `entity_value` String,
    `time_bucket` DateTime('UTC'),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'user' AS entity_type,
    lower(user_unified) AS entity_value,
    toStartOfHour(timestamp) AS time_bucket,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE user_unified != ''
GROUP BY entity_type, entity_value, time_bucket;

-- Identity observations (feeds resolve_identity, lateral movement, and — via
-- the chained nat_detection_mv on identity_observations — NAT detection; MV
-- chaining fires downstream MVs on MV-pushed inserts, so no OCSF-specific NAT
-- MV is needed). Filters and derivations mirror identity_observations_mv.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_identity_observations_mv /* nano:skip-if-unknown-table */
TO nanosiem.identity_observations
(
    `observed_at` DateTime64(3, 'UTC'),
    `ip` String,
    `hostname` String,
    `fqdn` String,
    `mac` String,
    `user` String,
    `source` LowCardinality(String),
    `domain` LowCardinality(String),
    `ip_type` LowCardinality(String)
)
AS SELECT
    timestamp AS observed_at,
    `src_endpoint.ip` AS ip,
    if(
        position(src_host_unified, '.') > 0 AND position(src_host_unified, '.corp.') > 0,
        substring(src_host_unified, 1, position(src_host_unified, '.') - 1),
        src_host_unified
    ) AS hostname,
    src_host_unified AS fqdn,
    `src_endpoint.mac` AS mac,
    user_unified AS user,
    if(source_type != '' AND source_type != 'unknown', lower(source_type),
       if(`metadata.product.name` != '', lower(`metadata.product.name`), 'unknown')) AS source,
    multiIf(
        position(user_unified, '\\') > 0, substring(user_unified, 1, position(user_unified, '\\') - 1),
        position(src_host_unified, '.corp.') > 0, 'corp',
        ''
    ) AS domain,
    multiIf(
        match(`src_endpoint.ip`, '^10\\.'), 'private',
        match(`src_endpoint.ip`, '^192\\.168\\.'), 'private',
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'), 'private',
        match(`src_endpoint.ip`, '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'), 'vpn',
        match(`src_endpoint.ip`, '^127\\.'), 'loopback',
        'public'
    ) AS ip_type
FROM nanosiem.ocsf_logs
WHERE
    `src_endpoint.ip` != ''
    AND src_host_unified != ''
    AND (
        match(`src_endpoint.ip`, '^10\\.') OR
        match(`src_endpoint.ip`, '^192\\.168\\.') OR
        match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
    )
    AND `src_endpoint.ip` NOT IN ('127.0.0.1', '::1', '0.0.0.0')
    AND src_host_unified NOT IN ('localhost', '-', 'unknown', '');

-- Cloud Users activity. The agg's `user` join key must carry the SAME values
-- the cloud surface's profile-resolved user column (user_unified) produces, so
-- it is written verbatim (not lowercased) — exactly like the UDM lane writes
-- `user` verbatim.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_cloud_user_activity_mv /* nano:skip-if-unknown-table */
TO nanosiem.cloud_user_activity_agg
(
    `user` String,
    `time_bucket` DateTime,
    `event_count` UInt64,
    `fail_count` UInt64,
    `permission_change_count` UInt64,
    `delete_count` UInt64,
    `mfa_count` UInt64,
    `no_mfa_count` UInt64,
    `distinct_services` AggregateFunction(uniq, String),
    `distinct_regions` AggregateFunction(uniq, String),
    `distinct_ips` AggregateFunction(uniq, String)
)
AS SELECT
    user_unified AS user,
    toStartOfHour(timestamp) AS time_bucket,
    count() AS event_count,
    countIf(`http_response.code` >= 400 OR status_id = 2) AS fail_count,
    toUInt64(0) AS permission_change_count,
    countIf(class_uid = 6003 AND activity_id = 4) AS delete_count,
    countIf(is_mfa = 1) AS mfa_count,
    countIf(is_mfa = 0) AS no_mfa_count,
    uniqState(toString(`api.service.name`)) AS distinct_services,
    uniqState(toString(`cloud.region`)) AS distinct_regions,
    uniqState(`src_endpoint.ip`) AS distinct_ips
FROM nanosiem.ocsf_logs
WHERE `cloud.provider` != '' AND user_unified != ''
GROUP BY user, time_bucket;

-- Per-source 5-minute telemetry rollup (source health / EPS / GB-day).
-- Direct writers that omit source_type land as their OCSF source identifier
-- (metadata.product.name) instead of a single opaque 'unknown' bucket.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_logs_per_source_5m_mv /* nano:skip-if-unknown-table */
TO nanosiem.logs_per_source_5m
(
    `source_type` LowCardinality(String),
    `bucket_start` DateTime,
    `events` UInt64,
    `bytes` UInt64,
    `last_event_at` DateTime64(6, 'UTC'),
    `first_event_at` DateTime64(6, 'UTC')
)
AS SELECT
    if(source_type != '' AND source_type != 'unknown', lower(source_type),
       if(`metadata.product.name` != '', lower(`metadata.product.name`), 'unknown')) AS source_type,
    toStartOfFiveMinute(timestamp) AS bucket_start,
    count() AS events,
    sum(event_bytes) AS bytes,
    max(timestamp) AS last_event_at,
    min(timestamp) AS first_event_at
FROM nanosiem.ocsf_logs
GROUP BY source_type, bucket_start;
