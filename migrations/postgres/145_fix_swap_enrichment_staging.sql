-- Fix swap_enrichment_staging to handle duplicate networks in staging table.
-- Uses DISTINCT ON to deduplicate (source_id, network) rows before inserting
-- into production, preventing unique constraint violations when concurrent
-- scheduler cycles insert overlapping data into staging.

CREATE OR REPLACE FUNCTION public.swap_enrichment_staging(p_source_id text) RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_count BIGINT;
BEGIN
    -- Get count from staging
    SELECT COUNT(*) INTO v_count FROM ip_enrichments_staging WHERE source_id = p_source_id;

    -- Delete old data for this source from production
    DELETE FROM ip_enrichments WHERE source_id = p_source_id;

    -- Move data from staging to production, deduplicating by (source_id, network)
    -- to prevent unique constraint violations from concurrent staging inserts
    INSERT INTO ip_enrichments (source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain, extra, created_at)
    SELECT DISTINCT ON (source_id, network)
           source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain, extra, created_at
    FROM ip_enrichments_staging
    WHERE source_id = p_source_id
    ORDER BY source_id, network, created_at DESC;

    -- Clear staging table for this source
    DELETE FROM ip_enrichments_staging WHERE source_id = p_source_id;

    RETURN v_count;
END;
$$;
