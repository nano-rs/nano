-- Migration: 025_case_mentions_index
-- Description: Add GIN index for querying user mentions in case wall metadata
-- This enables efficient queries for "cases where user X was mentioned"

-- Index for querying mentions in case_wall metadata
-- The metadata->'mentioned_user_ids' contains an array of user UUIDs
CREATE INDEX IF NOT EXISTS idx_case_wall_mentioned_users
ON case_wall USING gin ((metadata->'mentioned_user_ids'));

-- Also add an index on case_id + entry_type for faster mention queries
CREATE INDEX IF NOT EXISTS idx_case_wall_comments
ON case_wall(case_id) WHERE entry_type = 'comment';
