-- TOR Exit Nodes enrichment source
-- Migration: 057_tor_exit_nodes_source.sql
--
-- Registers TOR Exit Nodes as a built-in IOC feed using the Tor Project's Onionoo API.
-- Useful for detecting anonymized traffic patterns in enterprise networks.

INSERT INTO enrichment_sources (id, name, source_type, description, enabled, config)
VALUES (
    'tor_exit_nodes',
    'TOR Exit Nodes',
    'ioc_feed',
    'TOR network exit node IPs from the official Tor Project Onionoo API. Useful for detecting anonymized traffic in enterprise networks.',
    false,
    '{
        "sync_interval_hours": 6,
        "auto_sync_enabled": false,
        "ttl_days": 1,
        "confidence_level": 85,
        "timeout_secs": 120,
        "api_endpoint": "https://onionoo.torproject.org/details?type=relay&flag=Exit"
    }'::jsonb
) ON CONFLICT (id) DO NOTHING;
