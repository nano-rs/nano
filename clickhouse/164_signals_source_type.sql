-- =============================================================================
-- 164: signals source_type provenance column (NAN-1809 C5 — per-source RBAC)
-- =============================================================================
--
-- Per-source RBAC scoping (NAN-1789/NAN-1809) must be able to filter SIGNAL
-- reads by the source_type of the matched log — today a viewer denied a source
-- can still see every real-time signal that source produced. This migration adds
-- the provenance column to the signals table:
--
--   source_type LowCardinality(String) DEFAULT 'unknown'
--
-- 'unknown' mirrors the `logs.source_type` sentinel: every pre-existing signal
-- row, and every row written by a real-time MV whose projection predates this
-- column, materializes as 'unknown' (an MV's `TO` insert matches columns by
-- NAME; absent columns take the target DEFAULT). Scope enforcement treats
-- 'unknown' as its own source_type — deny-lists name concrete sources, so
-- legacy rows stay visible to unrestricted viewers and are never mis-attributed
-- to a denied source.
--
-- ADD COLUMN with DEFAULT and ADD INDEX are both metadata-only (instant, no
-- rewrite of existing parts) — safe inside the boot migrator's memory budget.
-- No backfill: historical signals keep the 'unknown' sentinel permanently
-- (backfilling would require re-joining logs by matched_log_id — out of scope).
--
-- CODE ONLY / NO MV ROLLOUT: the real-time MV generator
-- (nanosiem-core/src/detection/materialized_view.rs) now projects the base
-- table's `source_type` into new DDL, but EXISTING per-rule MVs keep their old
-- projection (their inserts fill 'unknown' via the DEFAULT) until a separate,
-- supervised drop/recreate rollout. This migration intentionally does not touch
-- any mv_rt_detection_* view.
--
-- Cluster note: signals IS in DISTRIBUTED_TABLES, so
-- deploy/scripts/init-clickhouse-cluster.sh rewrites these ALTERs to the local
-- table with ON CLUSTER, and the boot migrator's reconcile_distributed_columns
-- pass (nanosiem-core/src/db/clickhouse_migrate/distributed.rs) propagates the
-- new column to `signals_distributed` automatically — no manual wrapper edit
-- here (NAN-1652 drift rule). Schema-agnostic: the signals table is shared
-- by the UDM and OCSF profiles, so this one migration covers both. Fresh
-- installs get the column + index at CREATE time from clickhouse/init.sql;
-- IF NOT EXISTS makes both ALTERs a no-op there.
-- =============================================================================

ALTER TABLE nanosiem.signals ADD COLUMN IF NOT EXISTS source_type
    LowCardinality(String) DEFAULT 'unknown' AFTER matched_log_id;

ALTER TABLE nanosiem.signals ADD INDEX IF NOT EXISTS idx_source_type
    source_type TYPE set(100) GRANULARITY 4;
