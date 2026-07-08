-- Migration: deliver the NAN-1728 (C2) enrichment-dict version-dedup to EXISTING
-- installs (NAN-1755, F1 from the deploy-readiness audit).
--
-- WHY
-- ---
-- NAN-1728 (C2) rewrote three enrichment dict-refresh MV bodies to collapse each
-- ReplacingMergeTree base key to its latest version with an inner
-- `argMax(<col>, version)` subquery BEFORE the outer per-key aggregation:
--   * ioc_enrichment_dict_refresh        (marketplace IOC feed)
--   * custom_enrichment_dict_refresh     (user non-IOC enrichments)
--   * custom_ioc_enrichment_dict_refresh (user IOC enrichments)
-- (ip_enrichment_dict_refresh already dedups via `argMax(..., updated_at)` in its
-- GROUP BY, so its projection did NOT change and it is intentionally excluded.)
--
-- That rewrite landed ONLY in clickhouse/init.sql, where the four MVs are created
-- `CREATE MATERIALIZED VIEW IF NOT EXISTS`. On an EXISTING install init.sql
-- re-runs (it is hash-tracked) but `IF NOT EXISTS` no-ops the already-present MVs,
-- so the new deduped body reaches FRESH installs only. Meanwhile the migrator's
-- post-reconcile `repoint_dict_refresh_mvs_distributed` step (distributed.rs)
-- reads the LIVE (old, un-deduped) MV body and swaps only its FROM to the
-- `_distributed` wrapper. Net on an existing enterprise 3x2 cluster: cross-shard
-- reads get enabled WITHOUT the version-collapse that makes them correct — the
-- same base key at different ReplacingMergeTree versions across shards (per-shard
-- merges never collapse cross-shard) is read un-deduped, so ioc_enrichment_dict /
-- custom_*_dict can serve a stale version or, on an `is_marketplace` flip,
-- double-classify a key. Those values are stamped into the nanosiem.logs
-- ioc_*/enriched_* MATERIALIZED columns at ingest -> degraded enrichment.
-- (Single-shard installs are unaffected in practice — one shard's merges collapse
-- duplicate versions eventually.) This restores the distributed.rs:602 invariant
-- ("the dedup projection can never drift from init.sql") for existing installs,
-- whose MV came from the PREVIOUS init.sql.
--
-- FIX
-- ---
-- Re-issue the three MV bodies via `ALTER TABLE <mv> MODIFY QUERY <SELECT>` (SELECT
-- directly, NOT `AS SELECT` — NAN-1727), byte-matching init.sql's current deduped
-- bodies. Delivery mechanics (identical to migration 156):
--   * Read the LOCAL base `nanosiem.custom_enrichment_results`, exactly as init.sql
--     does — refreshable MVs validate FROM eagerly and the `_distributed` wrapper
--     does not exist when this migration runs. On a cluster the post-migration
--     `repoint_dict_refresh_mvs_distributed` step (clickhouse_migrator.rs runs it
--     LAST, after every numbered migration + init.sql + ensure_distributed_tables)
--     then swaps FROM -> `custom_enrichment_results_distributed`, now preserving
--     the dedup because the live body it reads is this new one. Single-node keeps
--     reading local.
--   * The cluster transform adds `ON CLUSTER` automatically; `ensure_distributed_
--     ddl_timeout` deliberately skips `MODIFY QUERY` (a baked-in SETTINGS timeout
--     would corrupt the stored MV query), so no timeout is appended.
-- Idempotent: on a fresh install (or on re-run) this re-sets the identical body —
-- a harmless no-op. The bodies below are copied verbatim from init.sql; keep them
-- in lockstep with init.sql on any future edit.
-- =============================================================================

-- 1. Marketplace IOC feed dict (is_marketplace = 1)
ALTER TABLE nanosiem.ioc_enrichment_dict_refresh
MODIFY QUERY SELECT
    key_value AS ioc_value,
    anyLast(key_type) AS ioc_type,
    anyLast(enrichment_name) AS source_id,
    anyLast(threat_type) AS threat_type,
    anyLast(malware) AS malware,
    toInt32(anyLast(confidence)) AS confidence_level,
    arrayStringConcat(groupUniqArrayArray(tags), ',') AS tags
FROM (
    SELECT * FROM (
        SELECT enrichment_name, key_type, key_value,
               argMax(threat_type, version) AS threat_type,
               argMax(malware, version) AS malware,
               argMax(confidence, version) AS confidence,
               argMax(tags, version) AS tags,
               argMax(is_ioc, version) AS is_ioc,
               argMax(is_marketplace, version) AS is_marketplace,
               argMax(expires_at, version) AS expires_at
        FROM nanosiem.custom_enrichment_results
        GROUP BY namespace, enrichment_name, key_type, key_value
    )
    WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
    ORDER BY confidence DESC
)
GROUP BY key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

-- 2. User non-IOC enrichment dict (is_ioc = 0)
ALTER TABLE nanosiem.custom_enrichment_dict_refresh
MODIFY QUERY SELECT
    key_type,
    key_value,
    groupUniqArrayArray(tags) as tags,
    max(coalesce(risk_score, 0)) as risk_score,
    groupUniqArray(enrichment_name) as enrichment_names
FROM (
    SELECT enrichment_name, key_type, key_value,
           argMax(tags, version) AS tags,
           argMax(risk_score, version) AS risk_score,
           argMax(is_ioc, version) AS is_ioc,
           argMax(expires_at, version) AS expires_at
    FROM nanosiem.custom_enrichment_results
    GROUP BY namespace, enrichment_name, key_type, key_value
)
WHERE expires_at > now() AND is_ioc = 0
GROUP BY key_type, key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

-- 3. User IOC enrichment dict (is_ioc = 1, is_marketplace = 0)
ALTER TABLE nanosiem.custom_ioc_enrichment_dict_refresh
MODIFY QUERY SELECT
    key_type,
    key_value,
    anyLast(threat_type) as threat_type,
    anyLast(malware) as malware,
    anyLast(confidence) as confidence,
    groupUniqArrayArray(tags) as tags,
    groupUniqArray(enrichment_name) as enrichment_names
FROM (
    SELECT * FROM (
        SELECT enrichment_name, key_type, key_value,
               argMax(threat_type, version) AS threat_type,
               argMax(malware, version) AS malware,
               argMax(confidence, version) AS confidence,
               argMax(tags, version) AS tags,
               argMax(is_ioc, version) AS is_ioc,
               argMax(is_marketplace, version) AS is_marketplace,
               argMax(expires_at, version) AS expires_at
        FROM nanosiem.custom_enrichment_results
        GROUP BY namespace, enrichment_name, key_type, key_value
    )
    WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 0
    ORDER BY confidence DESC
)
GROUP BY key_type, key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;
