-- ============================================================================
-- Migration 137: Search query safety limits
-- ============================================================================
-- Adds admin-configurable limits for query-level OOM protection.
-- These settings control bounded array aggregation, mvexpand limits,
-- post-processing buffer caps, and optional cost analysis enforcement.
--
-- All defaults are tuned for typical SIEM workloads (50-100GB/day).
-- Enterprise deployments can increase these via the settings API.
-- ============================================================================

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS search_max_group_array_size integer DEFAULT 10000,
  ADD COLUMN IF NOT EXISTS search_max_mvexpand_rows integer DEFAULT 100000,
  ADD COLUMN IF NOT EXISTS search_max_post_processing_groups integer DEFAULT 1000000,
  ADD COLUMN IF NOT EXISTS search_max_streaming_cache_rows integer DEFAULT 50000,
  ADD COLUMN IF NOT EXISTS search_block_on_cost_errors boolean DEFAULT false;
