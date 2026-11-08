-- Migration 186 (NAN-4959): once nano's signed platform feed bundle has
-- committed an IPinfo Lite generation, legacy IP rows stop feeding the IP
-- dictionaries.
--
-- WHY: IPinfo Lite is served only from the bundle (NAN-4959 removed the
-- native bring-your-own sync and retired the air-gap ip_enrichment import).
-- Rows those paths wrote stay in nanosiem.ip_enrichments with
-- platform_feed = 0 (source_id 'ipinfo_lite', 'airgap_ip_enrichment'), and
-- migration 184's predicate admits every platform_feed = 0 row
-- unconditionally. argMax(updated_at) only resolves the SAME network, so a
-- stale legacy /24 kept winning IP_TRIE longest-prefix match over a corrected
-- bundle /23, and a network the bundle dropped stayed in the dictionary
-- forever. A replayed old air-gap IP bundle could override the signed feed
-- the same way.
--
-- WHAT: platform_feed = 0 rows are admitted only while NO ipinfo_lite
-- generation has ever been committed (a non-empty storage_key in
-- nanosiem.platform_feed_commits). An install keeps its legacy geo/ASN until
-- the bundle's first IPinfo commit, and from that commit on the bundle alone
-- supplies it. The switch rides the bundle's own activation protocol: the
-- consumer commits the generation, then refreshes this view and reloads the
-- dictionaries (loader::activate), so the legacy rows leave in the same step
-- the bundle's rows arrive. Nothing is deleted (forward-only, no data
-- deletion in a boot migration); the rows simply stop being read. A later
-- withdrawal (hard expiry) does NOT bring stale legacy data back.
--
-- Platform rows keep 184's rule (only the active generation of each feed).
-- The body and settings are migration 185's (NAN-4957 split the dictionary onto this
-- staging view); this migration MUST apply after 185. Both subqueries name
-- nanosiem.platform_feed_commits so the cluster post-reconcile step
-- (DICT_REFRESH_MV_BASES) repoints them to the _distributed wrapper with the
-- rest of the body. MODIFY QUERY takes the SELECT directly (no AS, NAN-1727).
-- Idempotent: re-running re-sets the same body. init.sql is NOT edited.

ALTER TABLE nanosiem.ip_enrichment_dict_refresh
MODIFY QUERY SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain
FROM nanosiem.ip_enrichments
WHERE (platform_feed = 0 AND 'ipinfo_lite' GLOBAL NOT IN (SELECT feed_id FROM nanosiem.platform_feed_commits WHERE storage_key != '')) OR (platform_feed = 1 AND source_id GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id))
GROUP BY network
HAVING argMax(deleted, updated_at) = 0
SETTINGS max_bytes_before_external_group_by = 268435456, max_memory_usage = 1500000000, max_threads = 2, min_insert_block_size_rows = 262144, min_insert_block_size_bytes = 67108864, max_insert_block_size = 262144;
