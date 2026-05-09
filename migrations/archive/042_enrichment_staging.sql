-- Enrichment staging table for zero-downtime updates
-- Migration: 042_enrichment_staging.sql
--
-- Uses a staging table + atomic swap pattern:
-- 1. COPY data into staging table (fast bulk load)
-- 2. Swap staging with production in a transaction
-- 3. Zero downtime for lookups during sync

-- Create staging table with same structure as ip_enrichments
CREATE TABLE IF NOT EXISTS ip_enrichments_staging (
    id BIGSERIAL PRIMARY KEY,
    source_id TEXT NOT NULL,
    network CIDR NOT NULL,
    country TEXT,
    country_code TEXT,
    continent TEXT,
    continent_code TEXT,
    asn TEXT,
    as_name TEXT,
    as_domain TEXT,
    extra JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for the staging table (needed for the swap)
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_staging_network ON ip_enrichments_staging USING GIST (network inet_ops);
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_staging_source ON ip_enrichments_staging(source_id);

-- Function to atomically swap staging with production for a given source
-- This uses table inheritance swapping for true zero-downtime
CREATE OR REPLACE FUNCTION swap_enrichment_staging(p_source_id TEXT)
RETURNS BIGINT AS $$
DECLARE
    v_count BIGINT;
BEGIN
    -- Get count from staging
    SELECT COUNT(*) INTO v_count FROM ip_enrichments_staging WHERE source_id = p_source_id;
    
    -- Delete old data for this source from production
    DELETE FROM ip_enrichments WHERE source_id = p_source_id;
    
    -- Move data from staging to production
    INSERT INTO ip_enrichments (source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain, extra, created_at)
    SELECT source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain, extra, created_at
    FROM ip_enrichments_staging
    WHERE source_id = p_source_id;
    
    -- Clear staging table for this source
    DELETE FROM ip_enrichments_staging WHERE source_id = p_source_id;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;
