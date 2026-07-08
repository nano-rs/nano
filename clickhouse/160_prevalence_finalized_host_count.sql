-- =============================================================================
-- 160: prevalence finalized-host_count tables (NAN-1732 — P2-D phase 1)
-- =============================================================================
--
-- WHY
-- ---
-- The hash/domain/ip prevalence CACHE dicts source host_count from
-- *_prevalence_summary via `GROUP BY entity, uniqMerge(host_count)` on EVERY
-- cache-miss batch. Saturn-measured: 254 GiB / 16.1B rows read in 3h (4,438
-- loads) on the shared ingest node — memory-bounded (not an outage) but real
-- read-IO pressure competing with ingestion. Post-NAN-1728 the dict reads the
-- *_distributed summary, so each miss now fans the uniqMerge across shards.
--
-- FIX (phased): pre-finalize the masked host_count into a small per-entity table
-- so the dict + rare/new explorer read a point-lookup instead of re-aggregating
-- the 80M-row summary. This migration lands PHASE 1 — the finalized tables and
-- their maintenance MVs — WITHOUT repointing the dict/explorer (that is phase 2,
-- after this soaks and existing installs are backfilled). Landing phase 1 alone
-- is a pure additive no-op for read behavior: nothing reads *_prevalence_final
-- yet.
--
-- DESIGN (mirrors the NAN-1728 enrichment dict-refresh pattern, with two
-- prevalence-specific deviations noted below):
--
--   *_prevalence_final: a `keep-local-engine` ReplacingMergeTree(version) holding
--   the FINALIZED, masked UInt16 host_count — byte-identical to what the dict
--   SOURCE computes today (validated: 0 mismatches vs the live dict across 513
--   hashes / 631,029 IPs / 333 domains on local). Kept per-shard-local (marker
--   below) so the refresh MV can APPEND to it (a full-replace refreshable MV is
--   refused onto a Replicated target; and prevalence can't full-replace anyway —
--   see deviation 1).
--
--   *_prevalence_final_refresh: `REFRESH EVERY 10 MINUTE APPEND`. Reads the LOCAL
--   summary at init (refreshable-MV DDL validates its FROM eagerly and the
--   *_distributed wrapper does not exist until ensure_distributed_tables runs
--   AFTER migrations); the migrator's post-reconcile
--   `repoint_dict_refresh_mvs_distributed` step then MODIFY-QUERYs the FROM to
--   *_prevalence_summary_distributed on clusters (this MV is registered in
--   distributed.rs DICT_REFRESH_MV_BASES; repoint_from_table rewrites EVERY
--   base-table reference, so both the outer FROM and the GLOBAL IN subquery below
--   go distributed). Single-node keeps reading local (complete on one shard).
--
-- DEVIATION 1 vs enrichment (APPEND, not full-replace): the enrichment staging
-- refreshes are small-data full-replaces. Prevalence can't — a full recompute of
-- the 80M-row summary OOMs at 4 GiB (the NAN-1404 trap). So the refresh is
-- bounded to the RECENT working set (`last_seen >= now()-40m`, > the 10m cadence)
-- and APPENDs; ReplacingMergeTree(version) dedups an entity's successive
-- finalizations (read side takes argMax(...,version)). Entities that go quiet
-- keep their last finalized value. History (entities never active in a 40m
-- window since install) is seeded by a one-time chunked backfill run out-of-band
-- (bounded per-query; NOT in this migration — no backfills in boot migrations).
--
-- DEVIATION 2 vs enrichment (two-step GLOBAL IN keying): on the *_distributed
-- summary a naive `WHERE last_seen >= cutoff` before the GROUP BY UNDERCOUNTS —
-- an entity recent on shard A but last active on shard B two hours ago has its
-- shard-B partial dropped, so uniqMerge sees only shard A's hosts (validated on
-- the 2-shard otel_test cluster: naive => 1, truth => 2). The fix finds recent
-- entity KEYS first, then aggregates ALL their partials: `WHERE entity GLOBAL IN
-- (SELECT entity ... WHERE last_seen >= cutoff)`. GLOBAL IN (not plain IN) is
-- required — a plain distributed IN subquery is denied (Code 288,
-- distributed_product_mode=deny). On single-node GLOBAL IN degrades to a local
-- IN over the ~1-row-per-entity summary — same result, no-op.
--
-- Memory bounds match the dict SOURCE (migration-130 / NAN-1404): 512 MiB cap,
-- 256 MiB spill, 2 threads. A failing refresh keeps the last good *_final data
-- and surfaces in system.view_refreshes (the siem-health staleness probe)
-- instead of killing ingestion.
-- =============================================================================

-- ── hash ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nanosiem.hash_prevalence_final
(
    file_hash String,
    host_count UInt16,
    first_seen DateTime64(6),
    last_seen DateTime64(6),
    total_occurrences UInt64,
    version DateTime64(6)
)
ENGINE = ReplacingMergeTree(version) /* nano:keep-local-engine */
ORDER BY file_hash
-- 30d retention parity with *_prevalence_summary: inactive entities expire in
-- sync; the refresh resets last_seen (hence the TTL) for active ones.
TTL toDateTime(last_seen) + toIntervalDay(30);

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.hash_prevalence_final_refresh
REFRESH EVERY 10 MINUTE APPEND TO nanosiem.hash_prevalence_final AS
SELECT file_hash,
       if(uniqMerge(host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(host_count)))) AS host_count,
       min(first_seen) AS first_seen,
       max(last_seen) AS last_seen,
       toUInt64(sum(total_count)) AS total_occurrences,
       now64(6) AS version
FROM nanosiem.hash_prevalence_summary
WHERE file_hash GLOBAL IN (
    SELECT file_hash FROM nanosiem.hash_prevalence_summary
    WHERE last_seen >= now64(6) - INTERVAL 40 MINUTE
)
GROUP BY file_hash
SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2;

-- ── domain ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_final
(
    domain String,
    host_count UInt16,
    first_seen DateTime64(6),
    last_seen DateTime64(6),
    total_occurrences UInt64,
    version DateTime64(6)
)
ENGINE = ReplacingMergeTree(version) /* nano:keep-local-engine */
ORDER BY domain
-- 30d retention parity with *_prevalence_summary: inactive entities expire in
-- sync; the refresh resets last_seen (hence the TTL) for active ones.
TTL toDateTime(last_seen) + toIntervalDay(30);

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_final_refresh
REFRESH EVERY 10 MINUTE APPEND TO nanosiem.domain_prevalence_final AS
SELECT domain,
       if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count,
       min(first_seen) AS first_seen,
       max(last_seen) AS last_seen,
       toUInt64(sum(total_count)) AS total_occurrences,
       now64(6) AS version
FROM nanosiem.domain_prevalence_summary
WHERE domain GLOBAL IN (
    SELECT domain FROM nanosiem.domain_prevalence_summary
    WHERE last_seen >= now64(6) - INTERVAL 40 MINUTE
)
GROUP BY domain
SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2;

-- ── ip (WHERE is_private = 0, mirroring the ip dict SOURCE) ──────────────────
CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_final
(
    ip String,
    host_count UInt16,
    first_seen DateTime64(6),
    last_seen DateTime64(6),
    total_occurrences UInt64,
    version DateTime64(6)
)
ENGINE = ReplacingMergeTree(version) /* nano:keep-local-engine */
ORDER BY ip
-- 30d retention parity with *_prevalence_summary: inactive entities expire in
-- sync; the refresh resets last_seen (hence the TTL) for active ones.
TTL toDateTime(last_seen) + toIntervalDay(30);

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_prevalence_final_refresh
REFRESH EVERY 10 MINUTE APPEND TO nanosiem.ip_prevalence_final AS
SELECT ip,
       if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count,
       min(first_seen) AS first_seen,
       max(last_seen) AS last_seen,
       toUInt64(sum(total_count)) AS total_occurrences,
       now64(6) AS version
FROM nanosiem.ip_prevalence_summary
WHERE is_private = 0 AND ip GLOBAL IN (
    SELECT ip FROM nanosiem.ip_prevalence_summary
    WHERE is_private = 0 AND last_seen >= now64(6) - INTERVAL 40 MINUTE
)
GROUP BY ip
SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2;
