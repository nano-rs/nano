-- Migration 184 (NAN-4948): nano's signed platform feed bundle on ClickHouse.
--
-- WHY: every install now loads IPinfo Lite, ThreatFox and the Tor exit list
-- from ONE signed bundle nano publishes (nanosiem-core
-- platform_enrichment::consumer), instead of pulling each vendor. A load
-- writes millions of rows in several INSERT blocks, which ClickHouse commits
-- independently. A failure part-way must never mix with the last good
-- install, and a new install must replace the old one at once (including
-- indicators the new bundle dropped).
--
-- DESIGN (active generation per feed, same shape as migration 182):
-- 1. Each install writes every feed under its own generation key
--    `platform_feed/<feed>/<sequence>`: ip_enrichments.source_id for IPinfo,
--    custom_enrichment_results.namespace for the IOC feeds (marketplace rows,
--    is_marketplace = 1, so they stamp the ioc_* columns).
-- 2. After the last data block the consumer inserts ONE block into
--    nanosiem.platform_feed_commits, one row per feed. A feed's ACTIVE
--    generation is argMax(storage_key, (sequence, committed_at)) for its
--    feed_id. An empty storage_key withdraws the feed (expired, or an
--    operator's own IPinfo token owns geo/ASN).
-- 3. Readers see a platform row only when its key is its feed's active
--    generation: platform_feed = 0 OR <key> GLOBAL IN
--    (SELECT argMax(storage_key, (sequence, committed_at)) FROM
--    nanosiem.platform_feed_commits GROUP BY feed_id). OWNERSHIP is the new
--    `platform_feed` UInt8 column (DEFAULT 0), set to 1 only by the loader,
--    never the name: rows that existed before this migration (including any
--    tenant namespace that happens to start with `platform_feed/`) get 0, so
--    they can never be hidden by the predicate or deleted by reclaim (which
--    is scoped to platform_feed = 1). No rename or refusal of existing data
--    is needed; the consumer logs a count of such rows at start-up.
-- 4. Every commit row carries the install `receipt` (signed descriptor
--    included). ClickHouse is the durable record of what is active; the
--    PostgreSQL platform_feed_state cache is repaired from the latest receipt
--    before any accept, expiry or reclaim decision, and max(revision) per
--    feed is the per-feed rollback fence. This migration applies
--    it to the two dictionary refresh views the platform rows feed
--    (ip_enrichment_dict_refresh, ioc_enrichment_dict_refresh); the Rust
--    readers of custom_enrichment_results apply the same predicate through
--    enrichment::ioc::committed_rows_predicate. Non-platform rows (native
--    IPinfo sync, air-gap imports, marketplace and custom enrichments, IOC
--    lists) are unaffected. GLOBAL IN keeps it valid on clusters, where the
--    migrator's post-reconcile step repoints the base tables in these bodies
--    to their _distributed wrappers (DICT_REFRESH_MV_BASES /
--    DISTRIBUTED_TABLES).
--
-- ORDER MATTERS and init.sql is NOT edited: ClickHouse analyzes the SELECT of
-- a `CREATE MATERIALIZED VIEW IF NOT EXISTS` against the live schema even when
-- the view exists, and the migrator runs init.sql BEFORE numbered migrations,
-- so an init.sql MV body naming `platform_feed` would abort every upgraded
-- install before this migration could add the column. Instead this migration
-- adds the columns, then the commits table, then re-issues the two bodies via
-- MODIFY QUERY (SELECT directly, no AS: NAN-1727). Fresh installs get the old
-- bodies from init.sql and this migration upgrades them, so both paths end on
-- the same query text (scripts/tests/platform-feed-ch-upgrade.sh; guard:
-- nanosiem-core/tests/dict_source_memory_guard.rs, MVS_REDEFINED_BY_184).
-- Idempotent: ADD COLUMN / CREATE TABLE IF NOT EXISTS, and MODIFY QUERY
-- re-sets the same body.

ALTER TABLE nanosiem.custom_enrichment_results ADD COLUMN IF NOT EXISTS platform_feed UInt8 DEFAULT 0;

ALTER TABLE nanosiem.ip_enrichments ADD COLUMN IF NOT EXISTS platform_feed UInt8 DEFAULT 0;

CREATE TABLE IF NOT EXISTS nanosiem.platform_feed_commits
(
    sequence UInt64,
    feed_id LowCardinality(String),
    storage_key String,
    revision Int64,
    hard_expiry DateTime64(3),
    committed_at DateTime64(3) DEFAULT now64(3),
    receipt String DEFAULT ''
)
ENGINE = MergeTree
ORDER BY (feed_id, sequence);

ALTER TABLE nanosiem.ip_enrichment_dict_refresh
MODIFY QUERY SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain
FROM nanosiem.ip_enrichments
WHERE platform_feed = 0 OR source_id GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id)
GROUP BY network
HAVING argMax(deleted, updated_at) = 0
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;

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
        WHERE platform_feed = 0 OR namespace GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id)
        GROUP BY namespace, enrichment_name, key_type, key_value
    )
    WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
    ORDER BY confidence DESC
)
GROUP BY key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;
