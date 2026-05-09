-- Enable pg_textsearch extension for BM25 full-text search
-- Requires pg_textsearch to be installed in the Postgres instance

-- Enable the extension
CREATE EXTENSION IF NOT EXISTS pg_textsearch;

-- Create BM25 index on raw_content
-- This replaces the standard GIN index for better relevance ranking and performance
CREATE INDEX IF NOT EXISTS idx_logs_raw_content_bm25 
ON logs USING bm25 (raw_content) 
WITH (text_config = 'english');

-- Drop the old GIN FTS index - no longer needed with BM25
DROP INDEX IF EXISTS idx_logs_raw_content_fts;
