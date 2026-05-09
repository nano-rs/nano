-- Enrichment Cache Table
-- Caches enrichment results from external providers to avoid redundant API calls
-- Used by the AI Alert Agent for efficient artifact enrichment

CREATE TABLE IF NOT EXISTS enrichment_cache (
    id SERIAL PRIMARY KEY,
    artifact VARCHAR(512) NOT NULL,
    artifact_type VARCHAR(50) NOT NULL,  -- 'hash_md5', 'hash_sha256', 'domain', 'ip', 'url'
    provider_id VARCHAR(50) NOT NULL REFERENCES agent_enrichment_providers(id) ON DELETE CASCADE,
    result JSONB NOT NULL,
    cached_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(artifact, artifact_type, provider_id)
);

-- Index for efficient cache lookups (includes expires_at for filtering at query time)
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_lookup 
ON enrichment_cache(artifact, artifact_type, provider_id, expires_at);

-- Index for cleanup of expired entries
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires 
ON enrichment_cache(expires_at);

-- Index for provider-specific queries
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_provider 
ON enrichment_cache(provider_id);

-- Comments for documentation
COMMENT ON TABLE enrichment_cache IS 'Cache for enrichment results from external threat intelligence providers';
COMMENT ON COLUMN enrichment_cache.artifact IS 'The artifact value being enriched (hash, domain, IP, URL)';
COMMENT ON COLUMN enrichment_cache.artifact_type IS 'Type of artifact: hash_md5, hash_sha256, hash_sha1, domain, ip, url';
COMMENT ON COLUMN enrichment_cache.provider_id IS 'Reference to the enrichment provider that produced this result';
COMMENT ON COLUMN enrichment_cache.result IS 'JSON result from the enrichment provider';
COMMENT ON COLUMN enrichment_cache.expires_at IS 'When this cache entry expires (TTL varies by provider)';

-- Function to clean up expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_enrichment_cache()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM enrichment_cache
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_enrichment_cache IS 'Removes expired entries from the enrichment cache';
