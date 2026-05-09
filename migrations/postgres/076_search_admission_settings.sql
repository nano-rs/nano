-- ============================================================================
-- Migration 076: Search admission control settings
-- ============================================================================
-- Adds admin-configurable settings for search query concurrency limits
-- and per-priority ClickHouse resource settings. These override the
-- env var defaults on boot.
-- ============================================================================

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS search_global_adhoc_limit integer DEFAULT 30,
  ADD COLUMN IF NOT EXISTS search_per_user_limit integer DEFAULT 5,
  ADD COLUMN IF NOT EXISTS search_max_queue_depth integer DEFAULT 100,
  ADD COLUMN IF NOT EXISTS search_queue_timeout_seconds integer DEFAULT 120,
  ADD COLUMN IF NOT EXISTS search_interactive_max_execution_time integer DEFAULT 300,
  ADD COLUMN IF NOT EXISTS search_interactive_max_memory_gb integer DEFAULT 20,
  ADD COLUMN IF NOT EXISTS search_analytics_max_execution_time integer DEFAULT 3600,
  ADD COLUMN IF NOT EXISTS search_analytics_max_memory_gb integer DEFAULT 50,
  ADD COLUMN IF NOT EXISTS search_realtime_max_execution_time integer DEFAULT 30,
  ADD COLUMN IF NOT EXISTS search_realtime_max_memory_gb integer DEFAULT 5;
