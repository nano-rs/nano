-- ============================================================================
-- Migration 105: Remove Default Seeded Parsers
-- ============================================================================
-- Default parsers (Apache, Json Generic, Squid Proxy, Sysmon) were previously
-- seeded in the init migration. Users can now sync parsers from a repository
-- or create them manually, so we remove the stale defaults.
--
-- The seeded parsers had well-known UUIDs (10000000-0000-0000-0000-00000000000X).
-- Migration 051 synced them from the old `parsers` table into `log_sources`,
-- so we clean them up here if they still exist.
-- ============================================================================

DELETE FROM log_sources
WHERE id IN (
    '10000000-0000-0000-0000-000000000001',  -- Apache
    '10000000-0000-0000-0000-000000000002',  -- Json Generic
    '10000000-0000-0000-0000-000000000003',  -- Squid Proxy
    '10000000-0000-0000-0000-000000000004'   -- Sysmon
);
