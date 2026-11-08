-- Migration 182 (NAN-4902 lane G): atomic code-free IOC list publications.
--
-- WHY: an IOC list publication writes up to ~50k rows into
-- custom_enrichment_results in several INSERT blocks, which ClickHouse commits
-- independently. A failure part-way must not leave readers with a mixed set,
-- and a delete must not withdraw part of a list.
--
-- DESIGN (active version per list):
-- 1. Each publication writes the list's COMPLETE live set under its own
--    storage namespace `ioc_list/<version>`. The version is in the
--    ReplacingMergeTree key, so rows of different publications never collapse
--    into each other (an uncommitted publication can never physically replace
--    the committed one on insert or merge).
-- 2. After the last data block, the API inserts ONE row (atomic) into
--    nanosiem.ioc_list_commits. A list's ACTIVE version is the highest committed
--    version for its list_id. A delete commits an empty withdrawal version.
-- 3. Readers see an IOC list row only when it belongs to its list's active
--    version: NOT startsWith(namespace, 'ioc_list/') OR version GLOBAL IN
--    (SELECT max(version) FROM nanosiem.ioc_list_commits GROUP BY list_id).
--    This migration applies it to custom_ioc_enrichment_dict_refresh (the
--    ingest-stamping path); the Rust readers (ioc in feed(), threat-intel
--    lookup, retro-hunt candidates, feed picker, the publisher's own diff)
--    apply the same predicate. Superseded and failed versions are invisible at
--    once and are deleted best-effort afterwards. No tombstones are needed.
--    GLOBAL IN keeps it valid on clusters, where the migrator's post-reconcile
--    step repoints BOTH base tables in this body to their _distributed
--    wrappers (DICT_REFRESH_MV_BASES / DISTRIBUTED_TABLES).
--
-- The MV body is delivered as a MODIFY QUERY (SELECT directly, no AS:
-- NAN-1727) and byte-matches clickhouse/init.sql (guard:
-- nanosiem-core/tests/dict_source_memory_guard.rs, MVS_REDEFINED_BY_182).
-- No ioc_list rows exist before this feature, so other namespaces are
-- unaffected. Idempotent.

CREATE TABLE IF NOT EXISTS nanosiem.ioc_list_commits
(
    version UInt32,
    list_id UUID,
    list_name String,
    action LowCardinality(String),
    committed_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY version;

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
        WHERE NOT startsWith(namespace, 'ioc_list/') OR version GLOBAL IN (SELECT max(version) FROM nanosiem.ioc_list_commits GROUP BY list_id)
        GROUP BY namespace, enrichment_name, key_type, key_value
    )
    WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 0
    ORDER BY confidence DESC
)
GROUP BY key_type, key_value
SETTINGS max_bytes_before_external_group_by = 1000000000, max_memory_usage = 2500000000, max_threads = 2;
