-- ============================================================================
-- Migration 113: Remove Seeded Feeds and Log Sources
-- ============================================================================
-- The init migration (001) seeded 4 feeds (Apache, Sysmon, Squid Proxy,
-- Json Generic) which were then migrated into log_sources by migration 009.
-- Migration 105 removed the parser-originated seeds (10000000-* UUIDs) but
-- the feed-originated log sources remained.
--
-- New deployments should start with an empty log sources list — users can
-- sync from a parser repository or create sources manually.
-- ============================================================================

-- Remove the seeded feeds (well-known UUIDs from 001_init_postgres.sql)
DELETE FROM feeds
WHERE id IN (
    '20000000-0000-0000-0000-000000000001',  -- Apache
    '20000000-0000-0000-0000-000000000002',  -- Sysmon
    '20000000-0000-0000-0000-000000000003',  -- Squid Proxy
    '20000000-0000-0000-0000-000000000004'   -- Json Generic
);

-- Remove the log sources that were created from those seeded feeds.
-- Migration 009 inserted them by name (not by ID), so match by name.
-- Only delete if they were never deployed (to avoid removing user-customized sources).
DELETE FROM log_sources
WHERE name IN ('Apache', 'Sysmon', 'Squid Proxy', 'Json Generic')
  AND deployed = false
  AND validated = false;
