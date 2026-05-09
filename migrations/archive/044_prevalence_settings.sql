-- Prevalence Settings Schema
-- Migration: 044_prevalence_settings.sql
--
-- Adds prevalence tracking configuration to system_settings
-- Requirements: 8.1, 8.2, 8.3, 8.4

-- ============================================================================
-- Add prevalence settings columns to system_settings
-- ============================================================================

-- Rarity threshold: number of hosts below which an artifact is considered "rare"
-- Default: 3 hosts (Requirement 8.1)
ALTER TABLE system_settings 
ADD COLUMN IF NOT EXISTS prevalence_rarity_threshold INTEGER NOT NULL DEFAULT 3
CHECK (prevalence_rarity_threshold >= 1 AND prevalence_rarity_threshold <= 1000);

-- Enable/disable hash tracking (Requirement 8.2)
ALTER TABLE system_settings 
ADD COLUMN IF NOT EXISTS prevalence_enable_hash_tracking BOOLEAN NOT NULL DEFAULT true;

-- Enable/disable domain tracking (Requirement 8.2)
ALTER TABLE system_settings 
ADD COLUMN IF NOT EXISTS prevalence_enable_domain_tracking BOOLEAN NOT NULL DEFAULT true;

-- Retention period in days (Requirement 8.3)
ALTER TABLE system_settings 
ADD COLUMN IF NOT EXISTS prevalence_retention_days INTEGER NOT NULL DEFAULT 90
CHECK (prevalence_retention_days >= 1 AND prevalence_retention_days <= 365);

-- Cache TTL in seconds (Requirement 8.4)
ALTER TABLE system_settings 
ADD COLUMN IF NOT EXISTS prevalence_cache_ttl_seconds INTEGER NOT NULL DEFAULT 60
CHECK (prevalence_cache_ttl_seconds >= 0 AND prevalence_cache_ttl_seconds <= 3600);

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON COLUMN system_settings.prevalence_rarity_threshold IS 
    'Number of hosts below which an artifact is considered rare (default: 3)';

COMMENT ON COLUMN system_settings.prevalence_enable_hash_tracking IS 
    'Whether to track file hash prevalence (default: true)';

COMMENT ON COLUMN system_settings.prevalence_enable_domain_tracking IS 
    'Whether to track domain prevalence (default: true)';

COMMENT ON COLUMN system_settings.prevalence_retention_days IS 
    'Number of days to retain prevalence data (default: 90)';

COMMENT ON COLUMN system_settings.prevalence_cache_ttl_seconds IS 
    'Cache TTL in seconds for prevalence queries (default: 60)';
