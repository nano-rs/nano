-- NAN-4988: durable ingest-watchdog journal and CPU workload isolation.
--
-- Workloads are created before the CPU resource. Until the resource exists the
-- workload setting is inert, which lets an upgrading admin session (whose
-- implicit workload is `default`) create the hierarchy without a missing-
-- workload window. `default` must be a leaf: ClickHouse rejects queries linked
-- to a scheduler node that has children. Once `cpu` exists, ingest receives a
-- hard four-thread cap;
-- siblings share CPU with weighted-fair scheduling instead of one workload
-- monopolising every worker thread.

CREATE WORKLOAD IF NOT EXISTS nano SETTINGS scheduler = 'fair';
CREATE WORKLOAD IF NOT EXISTS default IN nano SETTINGS weight = 4;
CREATE WORKLOAD IF NOT EXISTS ingest IN nano
SETTINGS max_concurrent_threads = 4, weight = 10;
CREATE WORKLOAD IF NOT EXISTS interactive IN nano
SETTINGS weight = 4;
CREATE WORKLOAD IF NOT EXISTS background IN nano
SETTINGS weight = 1;
CREATE RESOURCE IF NOT EXISTS cpu (MASTER THREAD, WORKER THREAD);

-- Vector writes through a Null landing table instead of holding any privilege
-- on the stored UDM log table.  The admin-owned DEFINER MV is the only bridge
-- to `logs`; retries still deduplicate at the landing-table insert boundary.
-- `AS logs` deliberately keeps the accepted input contract identical to the
-- current UDM schema, including MATERIALIZED dictionary expressions.
CREATE TABLE IF NOT EXISTS nanosiem.logs_ingest AS nanosiem.logs
ENGINE = Null;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.logs_ingest_mv
TO nanosiem.logs
DEFINER = CURRENT_USER
SQL SECURITY DEFINER
AS SELECT * FROM nanosiem.logs_ingest;

-- OCSF Vector deployments dual-write the same event through
-- ocsf_logs_raw.  Vector's dedicated user intentionally has no INSERT or
-- SELECT privilege on the stored ocsf_logs table, so this existing bridge
-- must cross that trust boundary as the migration owner just like the UDM
-- bridge above.  Existing OCSF installations have the view at migration time;
-- fresh OCSF installs create it later from clickhouse/ocsf/init.sql, where the
-- same DEFINER contract is declared.  UDM-only installs skip this statement.
ALTER TABLE nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */
MODIFY SQL SECURITY DEFINER DEFINER = CURRENT_USER;

-- One row per state transition, never per 30-second sample. There is
-- deliberately no TTL: a manual stop is durable control state and must remain
-- authoritative across arbitrarily long jobs/ClickHouse restarts.
CREATE TABLE IF NOT EXISTS nanosiem.ingest_watchdog_journal
(
    `event_id` UUID,
    `transition_id` UUID,
    `event_time` DateTime64(3, 'UTC'),
    `node` String,
    `action` LowCardinality(String),
    `phase` LowCardinality(String),
    `mode` LowCardinality(String),
    `reason` String,
    `pending_async_inserts` UInt64,
    `oldest_flush_age_seconds` UInt64,
    `running_queries` UInt64,
    `memory_usage_bytes` UInt64,
    `memory_limit_bytes` UInt64,
    `refreshes_running` UInt64,
    `disabled_views` Array(String),
    `owned_views` Array(String),
    `hot_streak` UInt16,
    `calm_streak` UInt16
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (node, event_time, event_id)
SETTINGS index_granularity = 8192;

-- Current per-replica coverage is separate from the transition journal.  The
-- coordinator writes one row for every configured replica on every pass,
-- including an explicit unreachable row, so degraded coverage cannot look
-- like a calm cluster in SIEM Health.
CREATE TABLE IF NOT EXISTS nanosiem.ingest_watchdog_replica_status
(
    `observed_at` DateTime64(3, 'UTC'),
    `node` String,
    `replica` String,
    `endpoint` String,
    `reachable` Bool,
    `error` String,
    `hot` Bool,
    `pending_async_inserts` UInt64,
    `oldest_flush_age_seconds` UInt64,
    `running_queries` UInt64,
    `memory_usage_bytes` UInt64,
    `memory_limit_bytes` UInt64,
    `refreshes_running` UInt64,
    `disabled_views` Array(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (node, replica, observed_at)
TTL toDateTime(observed_at) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;
