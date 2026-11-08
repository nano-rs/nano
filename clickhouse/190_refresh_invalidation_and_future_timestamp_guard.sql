-- =============================================================================
-- 190: durable refresh activation + UDM future timestamp provenance
--        (NAN-4977 / NAN-4939)
-- =============================================================================
-- The refresh declarations are parsed before SQL execution and committed to
-- nanosiem._migration_refreshes only after every statement succeeds. They also
-- activate query changes delivered by 182/184/186/187 on installations where
-- ALTER ... MODIFY QUERY invalidated the in-memory snapshot but no later
-- SYSTEM REFRESH VIEW + dictionary reload occurred.
--
-- nano:refresh-view nanosiem.ip_enrichment_dict_refresh reload=ip_geo_pair
-- nano:refresh-view nanosiem.ioc_enrichment_dict_refresh reload=nanosiem.ioc_enrichment_dict
-- nano:refresh-view nanosiem.custom_ioc_enrichment_dict_refresh reload=nanosiem.custom_ioc_enrichment_dict

-- New UDM events clamp far-future timestamps in Vector and retain the sender's
-- value here. This ADD is metadata-only: old parts read the empty default. No
-- data rewrite or backfill belongs in a boot migration; the explicit operator
-- repair command handles pre-existing rows.
ALTER TABLE nanosiem.logs
    ADD COLUMN IF NOT EXISTS `original_timestamp` String DEFAULT '' CODEC(ZSTD(1))
    AFTER `timestamp`;
