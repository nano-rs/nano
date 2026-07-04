-- NAN-1691 (P2-A/B): granule-pruning skip indexes for prevalence hunts.
--
-- Two unrelated prevalence read paths full-scan today:
--
-- (a) logs.prevalence_* range hunts. `| where prevalence_dest_ip < N`
--     (rare/new hunts, and the detection-filter `prevalence_min < N`) land on
--     the MATERIALIZED UInt16 prevalence columns. Those columns carry NO skip
--     index, so the predicate is evaluated only AFTER the full projection is
--     read. Saturn EXPLAIN indexes=1 for `prevalence_dest_ip < 5` over 1d:
--     the predicate never appears in the index list — all 8228 timestamp-
--     surviving granules (~67M rows) are read, then filtered in the engine.
--     A minmax skip index prunes any granule-group whose stored min >= N.
--     These columns co-mingle real host_counts (small) with the 65535
--     "not-applicable" sentinel (empty file_hash/dest_ip/etc.), so the win is
--     structural: logs is ORDER BY (source_type, timestamp, ...), and whole
--     source_types are uniformly 65535 for a given prevalence column. Measured
--     on Saturn (1d, prevalence_dest_ip): 85% of rows are 65535, and the
--     source_types windows_event / apache_access / aws_cloudtrail / findings /
--     audit are min=max=65535 (~29% of the window) — every one of their
--     granule-groups prunes for any `< N` rare hunt, plus the 65535-dominated
--     bulk of windows_sysmon. GRANULARITY 1 (per 8192-row granule) maximizes
--     the sysmon-block win; the index is 4 bytes/granule (negligible).
--     NOTE: this index serves the DIRECT-column predicate form
--     (`prevalence_dest_ip < N`). The dictGet WHERE-pushdown FILTER form
--     (dictGetOrDefault(...) <= N) prunes via the CACHE dict, not this index.
--
-- (b) *_prevalence_summary first_seen/last_seen recency (explorer rare/new
--     7d/30d). These SimpleAggregateFunction(min/max, DateTime64) columns are
--     read as plain DateTime64. The explicit minmax adds GRANULE-level pruning.
--     ⚠️ EXPECT-LITTLE (measured, be honest before tuning against this):
--     CH 26.4 ALREADY part-prunes these — Saturn EXPLAIN for
--     `last_seen >= now()-7d` and `first_seen >= now()-7d` both show a
--     "Statistics" node pruning 13537 -> ~4717 granules (~65%) at PART level
--     with NO explicit index (part min/max is maintained automatically; TTL is
--     on last_seen). The explicit granule minmax can only prune WITHIN the
--     surviving recent parts, and those are ORDER BY (entity) — first_seen /
--     last_seen scatter across granules, so granule-level pruning is limited.
--     It is added anyway because it is free (metadata-only) and makes the
--     pruning an explicit, version-independent contract rather than relying on
--     undocumented automatic part statistics. The real structural win (a
--     projection / table ORDER BY on last_seen, or a time partition) is a
--     separate, heavier follow-up that needs a rewrite + backfill — out of
--     scope for an ADD-INDEX migration.
--
-- ADD INDEX is metadata-only (instant). We deliberately DO NOT emit
-- `MATERIALIZE INDEX` here: logs is ~1.77B rows and a boot migration runs with
-- ~8GiB — a full materialize would OOM/stall the migrator. The indexes apply
-- to NEW parts automatically. Backfilling existing parts is a SEPARATE, opt-in
-- ops step, run out of band and monitored via system.mutations (safe to
-- interrupt/resume — per-part progress is tracked):
--     ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_prevalence_dest_ip;
--     ... (one per index) ...
--
-- Cluster note: `logs` is in DISTRIBUTED_TABLES, so
-- deploy/scripts/init-clickhouse-cluster.sh rewrites these ALTERs to
-- `nanosiem.logs_local ON CLUSTER` automatically; the *_prevalence_summary
-- tables are NOT distributed and get `ON CLUSTER` only (bare name preserved).
-- Nothing profile-specific: the *_prevalence_summary tables are the shared,
-- schema-agnostic prevalence universe (identical DDL in init.sql and
-- ocsf/init.sql), so this one migration covers UDM and OCSF deployments. The
-- OCSF log table (nanosiem.ocsf_logs) is created by the ocsf/init.sql overlay
-- AFTER migrations run: FRESH OCSF bootstraps get the matching prevalence
-- minmax indexes straight from that CREATE TABLE (see clickhouse/ocsf/init.sql).
-- EXISTING OCSF deployments (ocsf_logs created by an earlier overlay, before the
-- CREATE-time indexes existed) get them via the `nano:skip-if-unknown-table`-
-- marked ALTERs in section (c) below. ClickHouse has no `ALTER TABLE IF EXISTS`,
-- so the marker lets the runner skip those statements where ocsf_logs is absent
-- — UDM-only deployments, and the fresh-OCSF ordering where ocsf_logs doesn't
-- exist yet at migration time (the CREATE-time indexes cover that case instead).

-- (a) logs prevalence_* range-hunt minmax (GRANULARITY 1)
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_prevalence_file_hash
    prevalence_file_hash TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_prevalence_process_hash
    prevalence_process_hash TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_prevalence_dest_domain
    prevalence_dest_domain TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_prevalence_dest_ip
    prevalence_dest_ip TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_prevalence_min
    prevalence_min TYPE minmax GRANULARITY 1;

-- (b) *_prevalence_summary recency minmax (GRANULARITY 1)
ALTER TABLE nanosiem.hash_prevalence_summary ADD INDEX IF NOT EXISTS idx_first_seen
    first_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.hash_prevalence_summary ADD INDEX IF NOT EXISTS idx_last_seen
    last_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.domain_prevalence_summary ADD INDEX IF NOT EXISTS idx_first_seen
    first_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.domain_prevalence_summary ADD INDEX IF NOT EXISTS idx_last_seen
    last_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ip_prevalence_summary ADD INDEX IF NOT EXISTS idx_first_seen
    first_seen TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ip_prevalence_summary ADD INDEX IF NOT EXISTS idx_last_seen
    last_seen TYPE minmax GRANULARITY 1;

-- (c) ocsf_logs prevalence_* range-hunt minmax (GRANULARITY 1) — OCSF parity
--     with the UDM logs indexes in (a). Same column set: ocsf_logs materializes
--     prevalence_file_hash / prevalence_process_hash / prevalence_dest_domain /
--     prevalence_dest_ip / prevalence_min identically to UDM logs (see
--     clickhouse/ocsf/init.sql). The `nano:skip-if-unknown-table` marker makes
--     the runner skip these when ocsf_logs is absent (UDM-only deploys, and the
--     fresh-OCSF ordering where the CREATE-time indexes apply instead). ADD
--     INDEX only — backfilling existing parts (MATERIALIZE INDEX) is the same
--     separate, opt-in ops step described for the UDM indexes above.
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_prevalence_file_hash prevalence_file_hash TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_prevalence_process_hash prevalence_process_hash TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_prevalence_dest_domain prevalence_dest_domain TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_prevalence_dest_ip prevalence_dest_ip TYPE minmax GRANULARITY 1;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_prevalence_min prevalence_min TYPE minmax GRANULARITY 1;
