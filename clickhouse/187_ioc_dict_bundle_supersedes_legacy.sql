-- Migration 187 (NAN-4959, IOC parity): once nano's signed platform feed
-- bundle has committed a ThreatFox or Tor generation, legacy marketplace IOC
-- rows stop feeding ioc_enrichment_dict.
--
-- WHY: ThreatFox and the Tor exit list come only from the bundle (like IPinfo
-- Lite, migration 186). Before NAN-4959 a marketplace `threatfox` /
-- `tor-exit-nodes` Deno install (enterprise) fetched abuse.ch / the Tor list
-- directly, and the air-gap IOC import landed signed-but-unfenced NDJSON; both
-- wrote marketplace IOC rows with platform_feed = 0 and a 30-day expiry, and
-- migration 184 admits every platform_feed = 0 row. Two sources for one feed
-- meant duplicate or conflicting verdicts (anyLast + tag union per key), an
-- indicator the bundle delisted kept stamping for up to 30 days, and a
-- replayed old air-gap IOC bundle re-added delisted indicators with a fresh
-- expiry. NAN-4959 retires those writers (install / run refused, PG 312
-- disables existing installs, the air-gap IOC arm is refused).
--
-- WHAT: a platform_feed = 0 row is admitted only while NO threatfox /
-- tor_exit_nodes generation has been committed (a non-empty storage_key in
-- nanosiem.platform_feed_commits). This dictionary only ever serves
-- is_marketplace = 1 rows (outer filter), so user custom enrichments and IOC
-- lists, which feed the custom IOC dictionaries, are unaffected. The raw
-- is_marketplace column cannot be named in this WHERE: the inner SELECT's
-- `argMax(is_marketplace, version) AS is_marketplace` alias shadows it
-- (ILLEGAL_AGGREGATION); the Rust readers' predicate does name it. The switch rides the bundle's activation (commit, then
-- view refresh + dictionary reload); nothing is deleted, and a later
-- withdrawal (hard expiry) does not bring legacy rows back. The Rust readers
-- apply the same rule (platform_enrichment::state::ioc_visible_predicate).
--
-- Body otherwise identical to migration 184's (same settings). Both
-- subqueries name nanosiem.platform_feed_commits so the cluster post-reconcile
-- step (DICT_REFRESH_MV_BASES) repoints them to the _distributed wrapper.
-- MODIFY QUERY takes the SELECT directly (no AS, NAN-1727). Idempotent.
-- init.sql is NOT edited.

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
        WHERE (platform_feed = 0 AND 'ioc' GLOBAL NOT IN (SELECT 'ioc' FROM nanosiem.platform_feed_commits WHERE feed_id IN ('threatfox', 'tor_exit_nodes') AND storage_key != '')) OR (platform_feed = 1 AND namespace GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id))
        GROUP BY namespace, enrichment_name, key_type, key_value
    )
    WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
    ORDER BY confidence DESC
)
GROUP BY key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;
