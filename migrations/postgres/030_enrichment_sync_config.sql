-- Add HTTP sync configuration to enrichment sources
-- Migration: 030_enrichment_sync_config.sql
--
-- Adds download/sync configuration options to the enrichment_sources config JSONB field.
-- These settings help handle large file downloads through CDNs like Cloudflare.

-- Update ipinfo_lite source with sync configuration defaults
UPDATE enrichment_sources
SET config = config || '{
    "auto_sync_enabled": true,
    "sync_interval_hours": 24,
    "download_timeout_secs": 1800,
    "tcp_keepalive_secs": 30,
    "connect_timeout_secs": 30,
    "stale_sync_timeout_minutes": 60
}'::jsonb
WHERE id = 'ipinfo_lite';

-- Add comment documenting the config schema
COMMENT ON COLUMN enrichment_sources.config IS 'Source-specific configuration JSON. Common fields:
- auto_sync_enabled (bool): Whether to auto-sync this source on schedule
- sync_interval_hours (int): Hours between syncs (default: 24)
- download_timeout_secs (int): HTTP request timeout for downloads (default: 1800 for large files)
- tcp_keepalive_secs (int): TCP keepalive interval to prevent CDN timeouts (default: 30)
- connect_timeout_secs (int): Initial connection timeout (default: 30)
- stale_sync_timeout_minutes (int): How long before in_progress sync is considered stale (default: 60)';
