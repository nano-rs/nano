-- Enrichment sources and IP enrichment data (Hybrid approach)
-- Migration: 009_enrichments.sql
--
-- This implements a hybrid enrichment strategy:
-- 1. Lookup tables store enrichment data (IPinfo, etc.)
-- 2. Logs table gets enrichment columns populated at ingest time
-- 3. Fast indexed queries on enriched fields
-- 4. Point-in-time accuracy (IP ownership when event occurred)

-- ============================================================================
-- PART 1: Add enrichment columns to logs table
-- ============================================================================

-- Source IP enrichment fields
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_country TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_country_code TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_continent TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_continent_code TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_asn TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_as_name TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_src_as_domain TEXT;

-- Destination IP enrichment fields
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_country TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_country_code TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_continent TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_continent_code TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_asn TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_as_name TEXT;
ALTER TABLE logs ADD COLUMN IF NOT EXISTS enriched_dest_as_domain TEXT;

-- Indexes for fast enrichment field queries
CREATE INDEX IF NOT EXISTS idx_logs_enriched_src_country_code ON logs (enriched_src_country_code);
CREATE INDEX IF NOT EXISTS idx_logs_enriched_src_asn ON logs (enriched_src_asn);
CREATE INDEX IF NOT EXISTS idx_logs_enriched_dest_country_code ON logs (enriched_dest_country_code);
CREATE INDEX IF NOT EXISTS idx_logs_enriched_dest_asn ON logs (enriched_dest_asn);

-- Composite indexes for common enrichment queries
CREATE INDEX IF NOT EXISTS idx_logs_enriched_src_country_asn ON logs (enriched_src_country_code, enriched_src_asn);
CREATE INDEX IF NOT EXISTS idx_logs_enriched_dest_country_asn ON logs (enriched_dest_country_code, enriched_dest_asn);

-- ============================================================================
-- PART 2: Enrichment lookup tables
-- ============================================================================

-- Enrichment sources registry (tracks what enrichment data we have)
CREATE TABLE IF NOT EXISTS enrichment_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,  -- 'ipinfo_lite', 'maxmind_geo', 'threat_intel', etc.
    description TEXT,
    download_url TEXT,
    last_sync_at TIMESTAMPTZ,
    last_sync_status TEXT,      -- 'success', 'failed', 'in_progress'
    last_sync_error TEXT,
    record_count BIGINT DEFAULT 0,
    file_hash TEXT,             -- To detect if file changed
    config JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- IP enrichment lookup table (CIDR-based)
-- Uses PostgreSQL's native CIDR type for efficient IP range queries
CREATE TABLE IF NOT EXISTS ip_enrichments (
    id BIGSERIAL PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES enrichment_sources(id) ON DELETE CASCADE,
    network CIDR NOT NULL,          -- CIDR like '1.0.128.0/18'
    country TEXT,
    country_code TEXT,
    continent TEXT,
    continent_code TEXT,
    asn TEXT,
    as_name TEXT,
    as_domain TEXT,
    extra JSONB DEFAULT '{}',       -- For additional fields from other sources
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source_id, network)
);

-- Index for efficient IP lookups using the <<= operator
-- This allows queries like: WHERE '8.8.8.8'::inet <<= network
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_network ON ip_enrichments USING GIST (network inet_ops);

-- Index for source lookups
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_source ON ip_enrichments(source_id);

-- Index for country-based queries
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_country ON ip_enrichments(country_code);

-- Index for ASN-based queries  
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_asn ON ip_enrichments(asn);

-- Insert default IPinfo Lite source (disabled until configured with token)
INSERT INTO enrichment_sources (id, name, source_type, description, enabled)
VALUES (
    'ipinfo_lite',
    'IPinfo Lite',
    'ipinfo_lite',
    'Free IP geolocation and ASN data from IPinfo. Provides country, continent, and ASN information for IP addresses.',
    false
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- PART 3: Helper function for IP enrichment lookup
-- ============================================================================

-- Function to lookup IP enrichment (returns first matching record)
CREATE OR REPLACE FUNCTION lookup_ip_enrichment(ip_addr TEXT)
RETURNS TABLE (
    country TEXT,
    country_code TEXT,
    continent TEXT,
    continent_code TEXT,
    asn TEXT,
    as_name TEXT,
    as_domain TEXT
) AS $$
BEGIN
    -- Handle NULL or empty IP
    IF ip_addr IS NULL OR ip_addr = '' THEN
        RETURN;
    END IF;
    
    RETURN QUERY
    SELECT 
        e.country,
        e.country_code,
        e.continent,
        e.continent_code,
        e.asn,
        e.as_name,
        e.as_domain
    FROM ip_enrichments e
    JOIN enrichment_sources s ON e.source_id = s.id
    WHERE ip_addr::inet <<= e.network
      AND s.enabled = true
    ORDER BY masklen(e.network) DESC  -- Most specific match first
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;
