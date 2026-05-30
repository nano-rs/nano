-- NAN-1112: drop the legacy PG-backed IOC store and the orphan
-- enrichment_sources rows that drove it.
--
-- The canonical IOC store has been ClickHouse `custom_enrichment_results`
-- since the marketplace + Deno migration; the PG `ioc_enrichments`
-- table (created in 031_ioc_enrichments.sql) was written to by the now-
-- deleted `EnrichmentService::sync_threatfox` / `sync_tor_exit_nodes`
-- engine methods. The `enrichment_sources` rows for `threatfox` and
-- `tor_exit_nodes` were the scheduler's dispatch hooks for those
-- methods — both gone in this PR. See `project_iocs_canonical_storage_is_clickhouse`
-- memory + NAN-1111 / NAN-1112 PR descriptions for the architectural
-- rationale.
--
-- Idempotent on every step so re-running this migration (or running it
-- against a tenant that already cleared the rows manually) is a no-op.
--
-- Open-init baseline (`migrations/postgres-open/000_open_init.sql`)
-- still creates `ioc_enrichments`, `ioc_enrichments_staging`, the
-- `ioc_type` enum, and the 4 IOC stored functions. They're left in
-- place because this migration always runs after the baseline, so
-- new open-core tenants land in the right end-state after init+196.
-- The [Baseline seed migrations must carry forward later cleanups]
-- rule applies to NEW baselines that resurrect previously-deleted
-- state, not to old baselines being mirrored by a forward migration.
-- If the open-init is ever reseeded (e.g., 000_open_init_v2.sql),
-- the IOC objects should NOT be re-introduced.

-- 1. Drop the orphan dispatch rows. The `ioc_enrichments.source_id`
--    FK has `ON DELETE CASCADE`, so this also wipes any leftover IOC
--    rows for these sources (idempotent; the rows may already be empty
--    or expired). IPinfo Lite's `ipinfo_lite` row stays — that's the
--    one pre-built source still in active use.
DELETE FROM enrichment_sources
WHERE id IN ('threatfox', 'tor_exit_nodes');

-- 2. Drop the stored functions from 031_ioc_enrichments.sql. PG's
--    `DROP TABLE ... CASCADE` only follows catalog dependencies
--    (views, FKs); function *bodies* that reference the table by name
--    are not catalog dependencies, so the functions would otherwise
--    survive and fail at call time with "relation does not exist".
--    No Rust caller invokes any of these post-NAN-1112; deleting them
--    here keeps the schema clean for future migration audits.
--
--    Note: these are all `ioc_*` symbols — IPinfo Lite's parallel
--    `ip_*` schema (`ip_enrichments_staging`, `lookup_ip`,
--    `lookup_ips_bulk`) is unaffected.
DROP FUNCTION IF EXISTS swap_ioc_enrichment_staging(TEXT);
DROP FUNCTION IF EXISTS cleanup_expired_iocs();
DROP FUNCTION IF EXISTS lookup_ioc(TEXT, ioc_type);
DROP FUNCTION IF EXISTS lookup_iocs_bulk(TEXT[]);

-- 3. Drop the two IOC tables. CASCADE follows real catalog dependents
--    (views, FK constraints from other tables). The indexes from 031
--    are dropped automatically with the table.
DROP TABLE IF EXISTS ioc_enrichments_staging CASCADE;
DROP TABLE IF EXISTS ioc_enrichments CASCADE;

-- 4. Drop the `ioc_type` enum, now unreachable from both Rust (the
--    `IocType` enum was deleted in this PR) and any surviving function.
DROP TYPE IF EXISTS ioc_type;
