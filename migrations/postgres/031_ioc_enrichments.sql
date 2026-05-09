-- IOC (Indicators of Compromise) enrichment tables
-- Migration: 031_ioc_enrichments.sql
--
-- Supports threat intelligence feeds like ThreatFox (abuse.ch)
-- Generic schema supports multiple IOC sources with confidence scoring
-- Short TTL (5-7 days) for IOC expiration since threat intel ages quickly

-- ============================================================================
-- PART 1: Register ThreatFox as enrichment source
-- ============================================================================

INSERT INTO enrichment_sources (id, name, source_type, description, enabled, config)
VALUES (
    'threatfox',
    'ThreatFox',
    'ioc_feed',
    'Free IOC database from abuse.ch providing malware and botnet indicators including IPs, domains, URLs, and file hashes.',
    false,
    '{
        "sync_interval_hours": 6,
        "auto_sync_enabled": false,
        "ttl_days": 7,
        "api_endpoint": "https://threatfox-api.abuse.ch/api/v1/",
        "ioc_query_days": 7
    }'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- PART 2: IOC type enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE ioc_type AS ENUM ('ip', 'domain', 'url', 'md5_hash', 'sha256_hash');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- PART 3: Main IOC enrichments table
-- ============================================================================

CREATE TABLE IF NOT EXISTS ioc_enrichments (
    id BIGSERIAL PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES enrichment_sources(id) ON DELETE CASCADE,

    -- IOC Value (normalized - lowercase, no port numbers)
    ioc_value TEXT NOT NULL,
    ioc_type ioc_type NOT NULL,

    -- Original value before parsing (for URLs/ip:port formats)
    original_value TEXT,

    -- Threat Intelligence metadata
    threat_type TEXT,                     -- e.g., "botnet_cc", "payload_delivery"
    threat_type_desc TEXT,                -- Human-readable description
    malware TEXT,                         -- Malware family name (e.g., "Cobalt Strike")
    malware_alias TEXT,                   -- Alternative names
    malware_printable TEXT,               -- Display-friendly name
    confidence_level INT CHECK (confidence_level >= 0 AND confidence_level <= 100),

    -- Timestamps from source
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,

    -- TTL Management - IOCs expire and get cleaned up
    expires_at TIMESTAMPTZ NOT NULL,

    -- Additional metadata
    tags TEXT[] DEFAULT '{}',
    reference_url TEXT,
    reporter TEXT,
    extra JSONB DEFAULT '{}',

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One IOC value per source per type
    UNIQUE(source_id, ioc_type, ioc_value)
);

-- ============================================================================
-- PART 4: Indexes for fast lookups
-- ============================================================================

-- Primary lookup: by IOC value (most common query)
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_enrichments(ioc_value);

-- Lookup by type and value (for type-specific queries)
CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_enrichments(ioc_type, ioc_value);

-- Source-based queries
CREATE INDEX IF NOT EXISTS idx_ioc_source ON ioc_enrichments(source_id);

-- TTL cleanup - find expired IOCs efficiently
CREATE INDEX IF NOT EXISTS idx_ioc_expires ON ioc_enrichments(expires_at);

-- Confidence-based queries: WHERE ioc_confidence > 80
CREATE INDEX IF NOT EXISTS idx_ioc_confidence ON ioc_enrichments(confidence_level);

-- Threat type queries
CREATE INDEX IF NOT EXISTS idx_ioc_threat_type ON ioc_enrichments(threat_type);

-- Malware family queries
CREATE INDEX IF NOT EXISTS idx_ioc_malware ON ioc_enrichments(malware);

-- GIN index for tags array searches
CREATE INDEX IF NOT EXISTS idx_ioc_tags ON ioc_enrichments USING GIN(tags);

-- Composite index for IOC lookups (filtering by expires_at done at query time)
CREATE INDEX IF NOT EXISTS idx_ioc_active_lookup ON ioc_enrichments(ioc_value, ioc_type, expires_at);

-- ============================================================================
-- PART 5: Staging table for zero-downtime updates
-- ============================================================================

CREATE TABLE IF NOT EXISTS ioc_enrichments_staging (
    id BIGSERIAL PRIMARY KEY,
    source_id TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    ioc_type ioc_type NOT NULL,
    original_value TEXT,
    threat_type TEXT,
    threat_type_desc TEXT,
    malware TEXT,
    malware_alias TEXT,
    malware_printable TEXT,
    confidence_level INT,
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    tags TEXT[] DEFAULT '{}',
    reference_url TEXT,
    reporter TEXT,
    extra JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_staging_source ON ioc_enrichments_staging(source_id);

-- ============================================================================
-- PART 6: Atomic swap function (zero-downtime update)
-- ============================================================================

CREATE OR REPLACE FUNCTION swap_ioc_enrichment_staging(p_source_id TEXT)
RETURNS BIGINT AS $$
DECLARE
    v_count BIGINT;
BEGIN
    -- Delete old data for this source from production
    DELETE FROM ioc_enrichments WHERE source_id = p_source_id;

    -- Move data from staging to production (deduplicate, keeping highest confidence)
    INSERT INTO ioc_enrichments (
        source_id, ioc_value, ioc_type, original_value,
        threat_type, threat_type_desc, malware, malware_alias, malware_printable,
        confidence_level, first_seen_at, last_seen_at, expires_at,
        tags, reference_url, reporter, extra, created_at
    )
    SELECT DISTINCT ON (source_id, ioc_type, ioc_value)
        source_id, ioc_value, ioc_type, original_value,
        threat_type, threat_type_desc, malware, malware_alias, malware_printable,
        confidence_level, first_seen_at, last_seen_at, expires_at,
        tags, reference_url, reporter, extra, created_at
    FROM ioc_enrichments_staging
    WHERE source_id = p_source_id
    ORDER BY source_id, ioc_type, ioc_value, confidence_level DESC;

    -- Get actual inserted count (after deduplication)
    GET DIAGNOSTICS v_count = ROW_COUNT;

    -- Clear staging table for this source
    DELETE FROM ioc_enrichments_staging WHERE source_id = p_source_id;

    -- Update the enrichment source record count with actual deduplicated count
    UPDATE enrichment_sources
    SET record_count = v_count,
        updated_at = NOW()
    WHERE id = p_source_id;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PART 7: TTL cleanup function
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_expired_iocs()
RETURNS BIGINT AS $$
DECLARE
    v_deleted BIGINT;
BEGIN
    DELETE FROM ioc_enrichments WHERE expires_at < NOW();
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PART 8: Single IOC lookup function
-- ============================================================================

CREATE OR REPLACE FUNCTION lookup_ioc(
    p_value TEXT,
    p_type ioc_type DEFAULT NULL
)
RETURNS TABLE (
    source_id TEXT,
    ioc_value TEXT,
    ioc_type ioc_type,
    threat_type TEXT,
    malware TEXT,
    confidence_level INT,
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    tags TEXT[]
) AS $$
BEGIN
    -- Handle NULL or empty value
    IF p_value IS NULL OR p_value = '' THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        ie.source_id,
        ie.ioc_value,
        ie.ioc_type,
        ie.threat_type,
        ie.malware,
        ie.confidence_level,
        ie.first_seen_at,
        ie.last_seen_at,
        ie.tags
    FROM ioc_enrichments ie
    JOIN enrichment_sources es ON ie.source_id = es.id
    WHERE ie.ioc_value = lower(p_value)
      AND (p_type IS NULL OR ie.ioc_type = p_type)
      AND es.enabled = true
      AND ie.expires_at > NOW()
    ORDER BY ie.confidence_level DESC NULLS LAST
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PART 9: Bulk IOC lookup function (for batch enrichment)
-- ============================================================================

CREATE OR REPLACE FUNCTION lookup_iocs_bulk(p_values TEXT[])
RETURNS TABLE (
    lookup_value TEXT,
    source_id TEXT,
    ioc_type ioc_type,
    threat_type TEXT,
    malware TEXT,
    confidence_level INT,
    tags TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT ON (v.val)
        v.val as lookup_value,
        ie.source_id,
        ie.ioc_type,
        ie.threat_type,
        ie.malware,
        ie.confidence_level,
        ie.tags
    FROM unnest(p_values) AS v(val)
    LEFT JOIN ioc_enrichments ie ON ie.ioc_value = lower(v.val)
    LEFT JOIN enrichment_sources es ON ie.source_id = es.id
    WHERE (ie.id IS NULL) OR (es.enabled = true AND ie.expires_at > NOW())
    ORDER BY v.val, ie.confidence_level DESC NULLS LAST;
END;
$$ LANGUAGE plpgsql;
