-- Migration: eviction audit archive (NAN-5447).
--
-- WHY THIS EXISTS
-- ---------------
-- The platform audit trail is stored in the event tables (`source_type =
-- 'audit'` rows of `logs` and, on OCSF installs, `ocsf_logs`). The
-- disk-pressure evictor frees space by dropping whole daily partitions. Before
-- it drops a partition that holds audit rows it copies them here, verifies
-- that every row arrived, and only then runs `DROP PARTITION`. If the copy or
-- the check fails, nothing of that day is dropped and SIEM Health raises
-- `storage:clickhouse:audit_archive_failed`.
--
-- SHAPE
-- -----
-- The audit reader's columns (nanosiem-core/src/audit/query.rs), as written by
-- nanosiem-core/src/audit/archive.rs. `origin_table` is the event table a row
-- came from. The audit reader adds this table to its reads whenever it holds
-- rows in the requested window, for the origins the active profile shows
-- (`logs` on UDM; `ocsf_logs` and `logs` on OCSF). Rows from tables the reader
-- never shows (`ocsf_logs_legacy_v179`, `ocsf_logs` on a UDM install) are kept
-- here under their own origin.
--
-- RETENTION
-- ---------
-- 365 days from the event time, the `logs` default (046 / init.sql). The
-- evictor never drops this table (it is not one of its daily tables). Audit
-- rows are small: a year of them is a few hundred MB on a busy install.
--
-- CLUSTERS
-- --------
-- Listed in `dual_pool::DISTRIBUTED_TABLES`: on a sharded cluster the
-- reconciler creates `audit_archive_distributed` and reads route through it.
-- The evictor writes the LOCAL table on whichever shard its connection lands
-- (like `search_job_results`).

CREATE TABLE IF NOT EXISTS nanosiem.audit_archive
(
    `origin_table` LowCardinality(String),
    `id` String,
    `timestamp` DateTime64(6, 'UTC') CODEC(Delta(8), ZSTD(3)),
    `user` String DEFAULT '' CODEC(ZSTD(1)),
    `action` LowCardinality(String) DEFAULT '',
    `source` LowCardinality(String) DEFAULT '',
    `src_ip` String DEFAULT '' CODEC(ZSTD(1)),
    `user_agent` String DEFAULT '' CODEC(ZSTD(1)),
    `status` LowCardinality(String) DEFAULT '',
    `message` String CODEC(ZSTD(3)),
    `metadata` String CODEC(ZSTD(3)),
    `archived_at` DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, origin_table, id)
TTL toDateTime(timestamp) + toIntervalDay(365)
SETTINGS ttl_only_drop_parts = 1;
