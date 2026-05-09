-- Migration 008: Originally renamed raw_content to message for logs table
-- DEPRECATED: Logs are now stored in ClickHouse, not PostgreSQL
-- This migration is now a no-op for fresh installations

-- For existing installations with the logs table, migration 032 will clean up

SELECT 1; -- No-op placeholder
