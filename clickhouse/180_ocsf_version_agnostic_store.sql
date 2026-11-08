-- =============================================================================
-- 180: move the OCSF 1.8 store aside, keep every row (NAN-4903)
-- =============================================================================
-- clickhouse/ocsf/init.sql now defines a version-agnostic `ocsf_logs`
-- (docs/design/OCSF-CLICKHOUSE.md): promoted columns are plain columns written by
-- `ocsf_logs_raw_mv`, the full OCSF object is stored in `event JSON`, vendor
-- spill in `unmapped JSON`. The 1.8 shape (EPHEMERAL `event`, MATERIALIZED
-- promotions, `time_dt`) cannot be ALTERed into it, and the overlay uses
-- CREATE ... IF NOT EXISTS, so the old objects must be out of the way before it
-- runs (numbered migrations run before the overlay).
--
-- NOTHING THAT HOLDS DATA IS DROPPED. The only data-bearing object is the
-- MergeTree `ocsf_logs`; it is RENAMEd to `ocsf_logs_legacy_v179` (metadata
-- only; parts, TTL and replicas stay as they are). The legacy rows age out
-- under their own 365-day TTL, and an operator can copy them into the new store
-- with scripts/ocsf-legacy-backfill.py (idempotent, day by day — never at boot).
--
-- What is dropped holds no data and is recreated by the overlay right after:
--   * the ingest MVs and their ENGINE=Null landing tables;
--   * the Distributed wrapper (the migrator recreates it for the new store);
--   * the 21 MVs that read `ocsf_logs`. A RENAME carries MV source bindings
--     with the table (measured on 26.10), so left alone they would keep reading
--     the frozen legacy table. Their TO tables (prevalence, entity, identity,
--     cloud, telemetry aggregates) keep their data; only the triggers go.
-- The 21 names are pinned to the overlay by tests/ocsf_manifest_ddl_consistency.rs.
--
-- Fresh installs and UDM-only deployments: every DROP is IF EXISTS and the
-- RENAME carries the skip-if-unknown-table marker, so this is a no-op. A rerun
-- after a partial failure is safe for the same reasons. On explicit clusters
-- the migrator adds ON CLUSTER to every statement; the new `ocsf_logs` uses its
-- own ZooKeeper path (`nano:zk-path-name`) because the legacy replicas keep the
-- old one.
--
-- Ingest gap: events that reach `ocsf_logs_raw` between this migration and the
-- overlay (seconds, during the migrator run) have no MV and are discarded —
-- same as any OCSF schema change; run the migrator before starting Vector.

DROP VIEW IF EXISTS nanosiem.ocsf_logs_native_raw_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_logs_raw_mv;
DROP VIEW IF EXISTS nanosiem.domain_prevalence_source_ocsf_mv;
DROP VIEW IF EXISTS nanosiem.hash_prevalence_source_ocsf_mv;
DROP VIEW IF EXISTS nanosiem.ip_prevalence_source_ocsf_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_cloud_user_activity_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_dest_host_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_query_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_domain_prevalence_summary_url_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_dimension_day_host_dest_user_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_dimension_day_host_src_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_dimension_day_ip_dest_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_dimension_day_ip_src_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_dimension_day_user_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_time_range_src_host_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_time_range_src_ip_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_entity_time_range_user_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_hash_prevalence_summary_file_hash_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_hash_prevalence_summary_process_hash_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_identity_observations_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_ip_prevalence_summary_dest_ip_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_ip_prevalence_summary_src_ip_mv;
DROP VIEW IF EXISTS nanosiem.ocsf_logs_per_source_5m_mv;
DROP TABLE IF EXISTS nanosiem.ocsf_logs_distributed;
DROP TABLE IF EXISTS nanosiem.ocsf_logs_native_raw;
DROP TABLE IF EXISTS nanosiem.ocsf_logs_raw;

RENAME TABLE nanosiem.ocsf_logs TO nanosiem.ocsf_logs_legacy_v179 /* nano:skip-if-unknown-table */;
