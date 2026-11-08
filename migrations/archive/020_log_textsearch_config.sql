-- Create a searchable text column for BM25 indexing
-- This column stores raw_content with delimiters replaced by spaces
-- so that searches for "dashboard" match "/dashboard"

-- Drop the old BM25 index
DROP INDEX IF EXISTS idx_logs_raw_content_bm25;

-- Add the search column
ALTER TABLE logs ADD COLUMN IF NOT EXISTS raw_content_search text;

-- Create a function to normalize log content for text search
CREATE OR REPLACE FUNCTION normalize_log_for_search(content text) RETURNS text AS $$
BEGIN
    -- Replace common log delimiters with spaces
    -- This allows "dashboard" to match "/dashboard", "user=admin" to match "admin", etc.
    RETURN regexp_replace(content, '[/=\[\]"''{}()<>|\\:;,]', ' ', 'g');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

-- Backfill existing data
UPDATE logs SET raw_content_search = normalize_log_for_search(raw_content) 
WHERE raw_content_search IS NULL;

-- Create BM25 index on the search column
CREATE INDEX idx_logs_raw_content_bm25 
ON logs USING bm25 (raw_content_search) 
WITH (text_config = 'simple');

-- Create a trigger to auto-populate raw_content_search on insert
CREATE OR REPLACE FUNCTION logs_search_trigger() RETURNS trigger AS $$
BEGIN
    NEW.raw_content_search := normalize_log_for_search(NEW.raw_content);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS logs_search_insert ON logs;
CREATE TRIGGER logs_search_insert
    BEFORE INSERT ON logs
    FOR EACH ROW
    EXECUTE FUNCTION logs_search_trigger();
