-- Feed Management Schema
-- Allows defining log sourcetypes based on ingest labels/patterns

-- Feeds table - defines log sourcetypes
CREATE TABLE IF NOT EXISTS feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    -- Matching criteria (at least one should be set)
    match_field VARCHAR(255),           -- Field to match on (e.g., 'metadata.source', 'src_host')
    match_pattern VARCHAR(512),         -- Regex pattern to match
    match_values TEXT[],                -- Exact values to match (alternative to pattern)
    -- Feed metadata
    category VARCHAR(100),              -- e.g., 'network', 'endpoint', 'cloud', 'application'
    vendor VARCHAR(255),                -- e.g., 'Cisco', 'Palo Alto', 'AWS'
    product VARCHAR(255),               -- e.g., 'ASA', 'Firewall', 'CloudTrail'
    -- Display settings
    icon VARCHAR(50),                   -- Icon name for UI
    color VARCHAR(20),                  -- Color for UI badges
    -- Status
    enabled BOOLEAN NOT NULL DEFAULT true,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add sourcetype column to logs table (for categorized logs)
ALTER TABLE logs ADD COLUMN IF NOT EXISTS sourcetype VARCHAR(255);

-- Index for sourcetype queries
CREATE INDEX IF NOT EXISTS idx_logs_sourcetype ON logs (sourcetype);

-- Index for feed lookups
CREATE INDEX IF NOT EXISTS idx_feeds_enabled ON feeds (enabled);
CREATE INDEX IF NOT EXISTS idx_feeds_name ON feeds (name);

-- Insert some default feeds based on common log formats
INSERT INTO feeds (name, description, match_field, match_pattern, category, vendor, product, icon, color) VALUES
    ('syslog', 'Standard syslog messages', 'metadata.source_type', '^syslog$', 'system', 'Generic', 'Syslog', 'terminal', 'gray'),
    ('json', 'JSON formatted logs', 'metadata.source_type', '^json$', 'application', 'Generic', 'JSON', 'braces', 'blue'),
    ('cef', 'Common Event Format logs', 'metadata.source_type', '^cef$', 'security', 'ArcSight', 'CEF', 'shield', 'purple'),
    ('leef', 'Log Event Extended Format', 'metadata.source_type', '^leef$', 'security', 'IBM', 'QRadar', 'shield', 'green'),
    ('aws_cloudtrail', 'AWS CloudTrail audit logs', 'metadata.eventSource', '.*\\.amazonaws\\.com$', 'cloud', 'AWS', 'CloudTrail', 'cloud', 'orange'),
    ('windows_security', 'Windows Security Event Log', 'metadata.Channel', '^Security$', 'endpoint', 'Microsoft', 'Windows', 'monitor', 'blue'),
    ('firewall', 'Network firewall logs', 'action', '^(allow|deny|drop|block)$', 'network', 'Generic', 'Firewall', 'shield-check', 'red')
ON CONFLICT (name) DO NOTHING;

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_feeds_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for updated_at
DROP TRIGGER IF EXISTS feeds_updated_at ON feeds;
CREATE TRIGGER feeds_updated_at
    BEFORE UPDATE ON feeds
    FOR EACH ROW
    EXECUTE FUNCTION update_feeds_updated_at();
