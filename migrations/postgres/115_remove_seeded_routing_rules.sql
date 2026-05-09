-- ============================================================================
-- Migration 115: Remove Seeded Routing Rules
-- ============================================================================
-- Migration 047 seeded routing rules for apache, json_generic, squid_proxy,
-- and sysmon on the HTTP Ingestion source configuration. Migration 113
-- removed the corresponding feeds and log sources, but the routing rules
-- were missed.
--
-- New deployments should start clean — users configure their own source
-- types via parser repositories or the UI.
--
-- Keeps the default fallback rule (priority 1000) intact.
-- ============================================================================

DELETE FROM routing_rules
WHERE source_configuration_id = '30000000-0000-0000-0000-000000000001'
  AND target_source_type IN ('apache', 'json_generic', 'squid_proxy', 'sysmon');
