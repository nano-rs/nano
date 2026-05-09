-- Fix text search to work with TimescaleDB hypertables
-- pg_textsearch BM25 doesn't auto-detect indexes on hypertables, but works when
-- querying chunks directly with explicit index names

-- Enable pg_trgm extension for fast ILIKE queries (fallback for smaller datasets)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Update the normalization function to also split on dots
-- This allows "reddit" to match "www.reddit.com"
CREATE OR REPLACE FUNCTION normalize_log_for_search(content text) RETURNS text AS $$
BEGIN
    -- Replace common log delimiters with spaces including dots
    -- This allows "dashboard" to match "/dashboard", "reddit" to match "www.reddit.com", etc.
    RETURN regexp_replace(content, '[/=\[\]"''{}()<>|\\:;,.]', ' ', 'g');
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

-- Backfill existing data with updated normalization
UPDATE logs SET raw_content_search = normalize_log_for_search(raw_content);

-- Create trigram GIN index for fast ILIKE queries (used for smaller datasets)
DROP INDEX IF EXISTS idx_logs_raw_content_search_trgm;
CREATE INDEX idx_logs_raw_content_search_trgm 
ON logs USING GIN (raw_content_search gin_trgm_ops);

-- Drop the old FTS index if it exists
DROP INDEX IF EXISTS idx_logs_raw_content_fts;

-- BM25 Search Function for Large-Scale Deployments
-- This function queries TimescaleDB chunks directly with their specific BM25 indexes
-- Use this for datasets > 100GB or when you need BM25 relevance ranking
CREATE OR REPLACE FUNCTION bm25_search(
    search_term text,
    start_time timestamptz,
    end_time timestamptz,
    max_results int DEFAULT 100
) RETURNS TABLE (
    log_id bigint,
    log_timestamp timestamptz,
    raw_content text,
    source_type text,
    score float8
) AS $$
DECLARE
    chunk_rec RECORD;
    chunk_query text;
    idx_name text;
BEGIN
    -- Query each chunk that overlaps with the time range
    FOR chunk_rec IN 
        SELECT c.chunk_schema, c.chunk_name, c.range_start, c.range_end
        FROM timescaledb_information.chunks c
        WHERE c.hypertable_name = 'logs'
          AND c.range_start < end_time
          AND c.range_end > start_time
        ORDER BY c.range_start DESC
    LOOP
        -- Build the chunk-specific index name
        idx_name := chunk_rec.chunk_schema || '.' || chunk_rec.chunk_name || '_idx_logs_raw_content_bm25';
        
        -- Query this chunk with BM25
        chunk_query := format(
            'SELECT l.id, l.timestamp, l.raw_content, l.source_type,
                    l.raw_content_search <@> to_bm25query($1, $2) as score
             FROM %I.%I l
             WHERE l.timestamp >= $3 AND l.timestamp < $4
               AND l.raw_content_search <@> to_bm25query($1, $2) < 0
             ORDER BY l.raw_content_search <@> to_bm25query($1, $2)
             LIMIT $5',
            chunk_rec.chunk_schema, chunk_rec.chunk_name
        );
        
        RETURN QUERY EXECUTE chunk_query USING search_term, idx_name, start_time, end_time, max_results;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Full BM25 Search Function - returns complete log rows
-- This is the primary function used by the SQL generator for keyword searches
-- Results are returned sorted by timestamp DESC within each chunk
CREATE OR REPLACE FUNCTION bm25_search_full(
    search_term text,
    start_time timestamptz,
    end_time timestamptz,
    max_results int DEFAULT 10000
) RETURNS SETOF logs AS $$
DECLARE
    chunk_rec RECORD;
    chunk_query text;
    idx_name text;
    rows_returned int;
    total_returned int := 0;
BEGIN
    -- Query each chunk that overlaps with the time range
    -- Chunks are ordered by range_start DESC so we get newest first
    FOR chunk_rec IN 
        SELECT c.chunk_schema, c.chunk_name, c.range_start, c.range_end
        FROM timescaledb_information.chunks c
        WHERE c.hypertable_name = 'logs'
          AND c.range_start < end_time
          AND c.range_end > start_time
        ORDER BY c.range_start DESC
    LOOP
        -- Stop if we've returned enough results
        IF total_returned >= max_results THEN
            EXIT;
        END IF;
        
        -- Build the chunk-specific index name
        idx_name := chunk_rec.chunk_schema || '.' || chunk_rec.chunk_name || '_idx_logs_raw_content_bm25';
        
        -- Query this chunk with BM25, return full row sorted by timestamp DESC
        chunk_query := format(
            'SELECT l.*
             FROM %I.%I l
             WHERE l.timestamp >= $3 AND l.timestamp < $4
               AND l.raw_content_search <@> to_bm25query($1, $2) < 0
             ORDER BY l.timestamp DESC
             LIMIT $5',
            chunk_rec.chunk_schema, chunk_rec.chunk_name
        );
        
        RETURN QUERY EXECUTE chunk_query 
            USING search_term, idx_name, start_time, end_time, (max_results - total_returned);
        
        GET DIAGNOSTICS rows_returned = ROW_COUNT;
        total_returned := total_returned + rows_returned;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Note: The BM25 index (idx_logs_raw_content_bm25) is kept for the bm25_search function
-- It's created per-chunk automatically by TimescaleDB when the parent index exists
