-- Migration: Prevalence Tracking Schema
-- Description: Adds ClickHouse schema for real-time prevalence tracking of file hashes and domains
-- 
-- This migration documents the ClickHouse schema changes and adds PostgreSQL settings
-- for prevalence tracking configuration.
--
-- ClickHouse Schema (applied via clickhouse/prevalence_tracking.sql):
-- - hash_prevalence_agg: AggregatingMergeTree table for hash prevalence
-- - hash_prevalence_mv: Materialized view aggregating from logs table
-- - domain_prevalence_agg: AggregatingMergeTree table for domain prevalence
-- - domain_prevalence_mv: Materialized view aggregating from logs table

-- ============================================================================
-- Prevalence Settings Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS prevalence_settings (
    id TEXT PRIMARY KEY DEFAULT 'default',
    
    -- Rarity threshold: number of unique hosts below which an artifact is considered rare
    rarity_threshold INTEGER NOT NULL DEFAULT 3,
    
    -- Enable/disable tracking per artifact type
    enable_hash_tracking BOOLEAN NOT NULL DEFAULT true,
    enable_domain_tracking BOOLEAN NOT NULL DEFAULT true,
    
    -- Data retention period in days (for ClickHouse TTL)
    retention_days INTEGER NOT NULL DEFAULT 90,
    
    -- Cache TTL for prevalence query results in seconds
    cache_ttl_seconds INTEGER NOT NULL DEFAULT 60,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure only one settings row exists
CREATE UNIQUE INDEX IF NOT EXISTS idx_prevalence_settings_singleton 
    ON prevalence_settings ((id = 'default'));

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_prevalence_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevalence_settings_updated_at ON prevalence_settings;
CREATE TRIGGER prevalence_settings_updated_at
    BEFORE UPDATE ON prevalence_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_prevalence_settings_updated_at();

-- Insert default settings row
INSERT INTO prevalence_settings (id) VALUES ('default')
ON CONFLICT (id) DO NOTHING;
