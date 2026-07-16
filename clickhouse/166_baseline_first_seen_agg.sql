-- =============================================================================
-- 166: materialized per-day first-seen aggregate for `| baseline` (NAN-1888)
-- =============================================================================
--
-- `| baseline`'s new-to-entity half (`entity_dimension_firsts`) scans raw
-- `logs` across the whole `[incident_start - 7d, incident_end]` lookback,
-- ARRAY JOINed over dimensions. `logs` is `ORDER BY (source_type, timestamp,
-- src_host, ...)`, so `lower(src_host) = ?` prunes nothing — measured on a
-- 2B-row Saturn tenant: ~33.5s cold for a 1h search (two ~100M-row scans),
-- and the cost scales with the LOOKBACK, not the search window. This
-- migration adds an entity-keyed day-grain aggregate so the same question is
-- a keyed lookup, exactly like `entity_time_range_agg` already does for the
-- coverage half (which stays as-is).
--
-- Table shape (per lane): one row per (entity, dimension, value, day) with
-- the exact min timestamp and summed event count. `ORDER BY (entity_type,
-- entity_value, dim, val, day)` makes the read a sort-key prefix lookup.
-- Day grain keeps it ~2 orders smaller than hourly while preserving the
-- exact `first_seen` (SimpleAggregateFunction(min) over the full-precision
-- timestamp — only the WINDOW EDGES are day-granular, and the read path's
-- coverage gate falls back to the raw scan when the agg can't cover the
-- lookback).
--
-- TWO tables, one per schema lane (UDM `logs` -> entity_dimension_day_agg;
-- OCSF `ocsf_logs` -> ocsf_entity_dimension_day_agg). This deliberately
-- DIVERGES from migration 128's shared-target `entity_time_range_agg`: the
-- reader (`entity_dimension_firsts`) is profile-keyed — it must see exactly
-- what the active profile's raw scan over `logs_table_key(profile)` would
-- see, or parity breaks and Vector's transitional dual-write double-counts
-- every event in BOTH lanes. Mirrors how the raw path picks its logs table.
--
-- MV anchoring follows `baseline::dimensions_for` (nanosiem-core) — the
-- read path relies on it, DO NOT widen without updating
-- `agg_dimension_set()` in search/service/asset.rs:
--   * host  (actor):  dims process_name / dest_ip, entity = lower(src_host).
--   * host  (assoc):  dim user, from BOTH the src_host and dest_host sides
--     ("a new user appeared on this host" is true whichever side the host is
--     on). The dest-side MV excludes rows where dest_host == src_host so the
--     pair sums to exactly what the raw `(src OR dest)` predicate counts.
--   * user  (whole footprint, agg_aligned=false): dims src_host / src_ip /
--     process_name, from `user` / `src_user` / `dest_user`, deduped the same
--     way so multi-column matches count once per distinct entity value.
--   * ip    (assoc, PRIVATE RFC1918 ONLY): dims src_host / dest_port / user
--     from both ip sides. Public-IP entities are intentionally excluded
--     (unbounded cardinality — parity with entity_time_range_agg's size
--     budget); the READ PATH routes public-IP entities to the raw scan, so
--     they lose no correctness, only the fast path. The gate uses the same
--     throw-free match() regexes as identity_observations_mv — NOT
--     isIPAddressInRange(), which THROWS on a malformed value and would fail
--     the whole ingest insert from inside the MV.
--
-- Baked-in filters (mirror the raw scan so the agg never stores junk peers):
-- `lower(source_type) != 'audit'` + val hygiene (`trimBoth(val) != ''`,
-- `val != '-'`, `val != '0'`, `lower(val) != 'null'`).
--
-- ONE MV PER ENTITY BRANCH (NAN-1386): ClickHouse attaches an MV's insert
-- trigger only to the FIRST SELECT of a UNION ALL body — never merge these
-- into one view. The dim fan-out WITHIN a branch uses the same ARRAY JOIN
-- tuple list as the raw `entity_dimension_firsts` scan (one SELECT, safe).
--
-- NO backfill here (NAN-1398): an INSERT...SELECT over the logs history
-- inside the boot-gating migrator is a multi-TB aggregation on production
-- tenants. Run scripts/backfill-entity-dimension-day-agg.sh (bounded,
-- per-day, recoverable) out of band; the read path stays on the raw scan
-- until an operator flips NANOSIEM_BASELINE_AGG_ENABLED on after a
-- verified-complete backfill (P1-2). The backfill records a completion marker
-- per (lane, day) in entity_dimension_day_agg_backfill_progress (below) so a
-- rerun after a mid-day failure produces a COMPLETE, non-double-counted day
-- (P1-3): an unmarked day is cleared and rebuilt, a marked day is skipped.
-- Only CLOSED days are backfilled — the current day is MV-only, never
-- backfilled, so the backfill can't race live ingest and inflate event_count
-- (P1-4).
--
-- day-grain edges (P1-1): the read path drops values first-seen at/after the
-- search window's exclusive `end` (a HAVING), so a same-boundary-day-later
-- value is never surfaced as new. Residual, accepted for the storage win:
-- `event_count` on the two boundary days can include a few occurrences just
-- outside the window — first_seen (which the new/known split keys on) is
-- exact; only the volume count is approximate at the edges.
--
-- ⚠ INGEST-CREDENTIAL COUPLING (NAN-1384): the OCSF MVs below read
-- `process_name_unified` and `dst_endpoint.port` from nanosiem.ocsf_logs —
-- both added to the nanosiem_ingest column-scoped SELECT grant in
-- clickhouse/users.d/nanosiem-users.xml, deploy/k8s/clickhouse/clickhouse.yaml
-- and deploy/k8s/{rackspace,aws}-db/clickhouse.yaml.tpl. Keep in lockstep.
-- No SELECT grant is needed on the agg tables themselves: MV *target* pushes
-- aren't grant-checked and nothing chains off them (NAN-1787 rule).
--
-- Statements touching nanosiem.ocsf_logs carry `nano:skip-if-unknown-table`:
-- the table only exists on NANO_SCHEMA_PROFILE=ocsf deployments. The OCSF
-- twin agg TABLE is created unconditionally — it is self-contained, and the
-- reader resolves it whenever the active profile is OCSF; an empty table
-- degrades gracefully through the coverage gate, an unknown table is a 500.
--
-- Keep in lockstep with clickhouse/init.sql + clickhouse/ocsf/init.sql
-- (fresh bootstraps) and scripts/backfill-entity-dimension-day-agg.sh.

-- ============================================================================
-- PART 0 — backfill progress marker (P1-3, lane-agnostic)
-- ============================================================================
-- One row per (lane, day) the backfill has COMPLETED. The script writes it
-- only after all branches for that (lane, day) have inserted, and skips a
-- (lane, day) ONLY when its marker exists — so a rerun after a mid-day crash
-- re-clears and rebuilds the unmarked day instead of leaving it missing
-- branches. ReplacingMergeTree keyed on (lane, day): a re-completed day just
-- overwrites its marker (idempotent). Tiny table — never TTL'd; it is the
-- backfill's durable ledger.
CREATE TABLE IF NOT EXISTS nanosiem.entity_dimension_day_agg_backfill_progress
(
    `lane` LowCardinality(String),   -- 'udm' | 'ocsf'
    `day` Date,
    `completed_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(completed_at)
ORDER BY (lane, day);

-- ============================================================================
-- PART 1 — UDM lane
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.entity_dimension_day_agg
(
    `entity_type` LowCardinality(String),  -- 'host' | 'user' | 'ip'
    `entity_value` String,                  -- lower()ed (ips are ingest-lowercased)
    `dim` LowCardinality(String),           -- UDM field name of the dimension
    `val` String,                            -- dimension value, VERBATIM casing
    `day` Date,
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `event_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_entity_value entity_value TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (entity_type, entity_value, dim, val, day)
TTL day + toIntervalDay(120)
SETTINGS index_granularity = 8192;

-- host, actor-anchored dims (process_name / dest_ip) + the src side of the
-- bi-directional user dim — all share the src_host entity anchor.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_host_src_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'host' AS entity_type,
    lower(src_host) AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
ARRAY JOIN
    [('process_name', toString(process_name)),
     ('dest_ip', toString(dest_ip)),
     ('user', toString(user))] AS d
WHERE src_host != ''
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- host, dest side of the user dim. Skips rows whose dest_host IS the
-- src_host (case-insensitively) — the src-side MV already counted those, and
-- the raw `(lower(src_host) = ? OR lower(dest_host) = ?)` predicate matches
-- such a row ONCE.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_host_dest_user_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'host' AS entity_type,
    lower(dest_host) AS entity_value,
    'user' AS dim,
    toString(user) AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
WHERE dest_host != ''
  AND lower(dest_host) != lower(src_host)
  AND lower(source_type) != 'audit'
  AND trimBoth(user) != '' AND user != '-' AND user != '0' AND lower(user) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- user, whole account footprint (matches the raw path's agg_aligned=false
-- predicate `user OR src_user OR dest_user`): one MV per user column, the
-- src_user/dest_user branches deduped against the earlier columns so a row
-- matching several columns with the SAME value counts once, like the OR.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_user_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'user' AS entity_type,
    lower(user) AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
ARRAY JOIN
    [('src_host', toString(src_host)),
     ('src_ip', toString(src_ip)),
     ('process_name', toString(process_name))] AS d
WHERE user != ''
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_src_user_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'user' AS entity_type,
    lower(src_user) AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
ARRAY JOIN
    [('src_host', toString(src_host)),
     ('src_ip', toString(src_ip)),
     ('process_name', toString(process_name))] AS d
WHERE src_user != ''
  AND lower(src_user) != lower(user)
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_dest_user_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'user' AS entity_type,
    lower(dest_user) AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
ARRAY JOIN
    [('src_host', toString(src_host)),
     ('src_ip', toString(src_ip)),
     ('process_name', toString(process_name))] AS d
WHERE dest_user != ''
  AND lower(dest_user) != lower(user)
  AND lower(dest_user) != lower(src_user)
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- ip, association dims from the src side. PRIVATE (RFC1918) entities only —
-- throw-free match() regexes, see header. src_ip/dest_ip are
-- ingest-lowercased (LOWERCASE_NORMALIZED_FIELDS), stored raw like the
-- entity_time_range_agg src_ip branch.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_ip_src_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'ip' AS entity_type,
    src_ip AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
ARRAY JOIN
    [('src_host', toString(src_host)),
     ('dest_port', toString(dest_port)),
     ('user', toString(user))] AS d
WHERE src_ip != ''
  AND (match(src_ip, '^10\\.') OR match(src_ip, '^192\\.168\\.') OR match(src_ip, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'))
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- ip, dest side; skips rows whose dest_ip IS the src_ip (the src-side MV
-- counted those; the raw OR predicate matches such a row once).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.entity_dimension_day_ip_dest_mv
TO nanosiem.entity_dimension_day_agg AS
SELECT
    'ip' AS entity_type,
    dest_ip AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.logs
ARRAY JOIN
    [('src_host', toString(src_host)),
     ('dest_port', toString(dest_port)),
     ('user', toString(user))] AS d
WHERE dest_ip != ''
  AND dest_ip != src_ip
  AND (match(dest_ip, '^10\\.') OR match(dest_ip, '^192\\.168\\.') OR match(dest_ip, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'))
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- ============================================================================
-- PART 2 — OCSF lane (twin table + MVs over ocsf_logs, *_unified columns)
-- ============================================================================

CREATE TABLE IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` LowCardinality(String),
    `entity_value` String,
    `dim` LowCardinality(String),
    `val` String,
    `day` Date,
    `first_seen` SimpleAggregateFunction(min, DateTime64(6, 'UTC')),
    `event_count` SimpleAggregateFunction(sum, UInt64),
    INDEX idx_entity_value entity_value TYPE bloom_filter GRANULARITY 4
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (entity_type, entity_value, dim, val, day)
TTL day + toIntervalDay(120)
SETTINGS index_granularity = 8192;

-- src_host_unified / dst_endpoint.hostname / user_unified / both ips are
-- already lower()'d at ingest (see 128 / ocsf/init.sql) — no extra lower()
-- except the defensive one on user_unified, matching
-- ocsf_entity_time_range_user_mv. dims carry the UDM-SEMANTIC names the
-- profile-keyed reader passes; vals stay verbatim (process_name_unified is
-- not ingest-lowercased, same as the raw scan's toString()).
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_host_src_mv /* nano:skip-if-unknown-table */
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'host' AS entity_type,
    src_host_unified AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('process_name', toString(process_name_unified)),
     ('dest_ip', toString(`dst_endpoint.ip`)),
     ('user', toString(user_unified))] AS d
WHERE src_host_unified != ''
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_host_dest_user_mv /* nano:skip-if-unknown-table */
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'host' AS entity_type,
    `dst_endpoint.hostname` AS entity_value,
    'user' AS dim,
    toString(user_unified) AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
WHERE `dst_endpoint.hostname` != ''
  AND `dst_endpoint.hostname` != src_host_unified
  AND lower(source_type) != 'audit'
  AND trimBoth(user_unified) != '' AND user_unified != '-' AND user_unified != '0' AND lower(user_unified) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

-- OCSF has no src_user/dest_user mapping, so the whole user footprint IS
-- user_unified — one branch, matching what the raw scan's profile-resolved
-- predicate collapses to under OCSF.
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_user_mv /* nano:skip-if-unknown-table */
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'user' AS entity_type,
    lower(user_unified) AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('src_host', toString(src_host_unified)),
     ('src_ip', toString(`src_endpoint.ip`)),
     ('process_name', toString(process_name_unified))] AS d
WHERE user_unified != ''
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_ip_src_mv /* nano:skip-if-unknown-table */
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'ip' AS entity_type,
    `src_endpoint.ip` AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('src_host', toString(src_host_unified)),
     ('dest_port', toString(`dst_endpoint.port`)),
     ('user', toString(user_unified))] AS d
WHERE `src_endpoint.ip` != ''
  AND (match(`src_endpoint.ip`, '^10\\.') OR match(`src_endpoint.ip`, '^192\\.168\\.') OR match(`src_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'))
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ocsf_entity_dimension_day_ip_dest_mv /* nano:skip-if-unknown-table */
TO nanosiem.ocsf_entity_dimension_day_agg
(
    `entity_type` String,
    `entity_value` String,
    `dim` String,
    `val` String,
    `day` Date,
    `first_seen` DateTime64(6, 'UTC'),
    `event_count` UInt64
)
AS SELECT
    'ip' AS entity_type,
    `dst_endpoint.ip` AS entity_value,
    d.1 AS dim,
    d.2 AS val,
    toDate(timestamp) AS day,
    min(timestamp) AS first_seen,
    count() AS event_count
FROM nanosiem.ocsf_logs
ARRAY JOIN
    [('src_host', toString(src_host_unified)),
     ('dest_port', toString(`dst_endpoint.port`)),
     ('user', toString(user_unified))] AS d
WHERE `dst_endpoint.ip` != ''
  AND `dst_endpoint.ip` != `src_endpoint.ip`
  AND (match(`dst_endpoint.ip`, '^10\\.') OR match(`dst_endpoint.ip`, '^192\\.168\\.') OR match(`dst_endpoint.ip`, '^172\\.(1[6-9]|2[0-9]|3[01])\\.'))
  AND lower(source_type) != 'audit'
  AND trimBoth(d.2) != '' AND d.2 != '-' AND d.2 != '0' AND lower(d.2) != 'null'
GROUP BY entity_type, entity_value, dim, val, day;
