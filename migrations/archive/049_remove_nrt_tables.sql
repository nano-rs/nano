-- Migration: Remove NRT Tables
-- Description: Drop NRT (Near Real-Time) engine tables after removal of NRT functionality
-- The system now uses a two-tier detection model: Real-Time (materialized views) and Scheduled (cron-based)

-- Drop NRT settings table (if it exists)
DROP TABLE IF EXISTS nrt_settings;

-- Drop NRT watermarks table (if it exists)
DROP TABLE IF EXISTS nrt_watermarks;

-- Note: No need to modify detection_rules table as detection_mode column
-- will simply not use 'near-real-time' value anymore. Existing rules with
-- that mode should be manually migrated to 'scheduled' mode with appropriate
-- cron expressions (e.g., */1 * * * * for continuous detection).

-- Optional: Update any existing near-real-time rules to scheduled mode
-- Uncomment the following if you want to automatically migrate existing NRT rules:
-- UPDATE detection_rules 
-- SET detection_mode = 'scheduled',
--     schedule_cron = COALESCE(schedule_cron, '*/1 * * * *')
-- WHERE detection_mode = 'near-real-time';

