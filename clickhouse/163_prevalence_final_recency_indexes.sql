-- =============================================================================
-- 163: recency minmax skip indexes on *_prevalence_final (NAN-1762 — P2-B)
-- =============================================================================
--
-- NAN-1762 repoints the rare/new EXPLORER off `*_prevalence_summary`
-- (`uniqMerge(host_count)` — OOM'd at 30d, hence the NAN-1729 <=7d IP gate) onto
-- the pre-finalized `*_prevalence_final` tables (migration 160), read per entity
-- via `argMax(col, version)`. The explorer pushes the recency predicate BELOW the
-- `GROUP BY entity` (`WHERE last_seen >= cutoff` for rare, `first_seen >= since`
-- for new), so a granule-pruning minmax on those columns lets ClickHouse skip
-- whole granules of out-of-window entities before aggregating — the exact
-- treatment migration 155 gave `*_prevalence_summary`.
--
-- SCOPE OF THE WIN (be honest — same caveat as 155(b)): `*_prevalence_final` is
-- ORDER BY entity, so first_seen/last_seen scatter across granules and granule
-- pruning is partial (part-level min/max already prunes recent-vs-old parts for
-- free). The win is real for sub-30d windows (local: a 24h `last_seen` filter
-- pruned 77/78 granules where recent data concentrates), and NIL at 30d — the
-- 30d TTL bounds every row to the last 30d, so a 30d cutoff prunes nothing. The
-- 30d full-universe `GROUP BY` is instead bounded by the query's
-- FINAL_AGG_SETTINGS (external group-by spill past 1 GiB, 2.5 GiB hard cap; see
-- prevalence/repository.rs), NOT by this index. The index is added anyway because
-- it is metadata-only/free and makes the sub-30d pruning an explicit contract.
--
-- ADD INDEX is metadata-only (instant). We do NOT emit `MATERIALIZE INDEX` here:
-- ip_prevalence_final is ~119M rows on Saturn and a boot migration runs with
-- ~8 GiB — a full materialize would stall/OOM the migrator (the migration-155
-- rule). New parts get the indexes automatically; backfilling existing parts is a
-- separate, opt-in, out-of-band ops step, monitored via system.mutations
-- (interrupt/resume-safe — per-part progress is tracked):
--     ALTER TABLE nanosiem.hash_prevalence_final   MATERIALIZE INDEX idx_first_seen;
--     ALTER TABLE nanosiem.hash_prevalence_final   MATERIALIZE INDEX idx_last_seen;
--     ALTER TABLE nanosiem.domain_prevalence_final MATERIALIZE INDEX idx_first_seen;
--     ALTER TABLE nanosiem.domain_prevalence_final MATERIALIZE INDEX idx_last_seen;
--     ALTER TABLE nanosiem.ip_prevalence_final     MATERIALIZE INDEX idx_first_seen;
--     ALTER TABLE nanosiem.ip_prevalence_final     MATERIALIZE INDEX idx_last_seen;
--
-- Cluster note: `*_prevalence_final` are keep-local (NOT in DISTRIBUTED_TABLES),
-- so deploy/scripts/init-clickhouse-cluster.sh gives these ALTERs `ON CLUSTER`
-- only (bare table name preserved) — identical to how it handles the
-- *_prevalence_summary ALTERs in migration 155. Schema-agnostic: the final tables
-- are the shared prevalence universe (same DDL for UDM and OCSF), so this one
-- migration covers both. Fresh installs get the indexes at CREATE time from
-- clickhouse/init.sql; `ADD INDEX IF NOT EXISTS` makes this ALTER a no-op there.
-- =============================================================================

ALTER TABLE nanosiem.hash_prevalence_final ADD INDEX IF NOT EXISTS idx_first_seen
    first_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.hash_prevalence_final ADD INDEX IF NOT EXISTS idx_last_seen
    last_seen TYPE minmax GRANULARITY 1;

ALTER TABLE nanosiem.domain_prevalence_final ADD INDEX IF NOT EXISTS idx_first_seen
    first_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.domain_prevalence_final ADD INDEX IF NOT EXISTS idx_last_seen
    last_seen TYPE minmax GRANULARITY 1;

ALTER TABLE nanosiem.ip_prevalence_final ADD INDEX IF NOT EXISTS idx_first_seen
    first_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ip_prevalence_final ADD INDEX IF NOT EXISTS idx_last_seen
    last_seen TYPE minmax GRANULARITY 1;
