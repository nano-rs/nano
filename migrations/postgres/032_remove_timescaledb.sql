-- Migration: Remove unused TimescaleDB and pg_textsearch extensions
-- These were used for log storage/search but logs now go to ClickHouse
--
-- This migration:
-- 1. Drops the unused logs table (logs are stored in ClickHouse)
-- 2. Drops BM25 search functions (search is done via ClickHouse)
-- 3. Drops TimescaleDB extension (no longer needed)
-- 4. Drops pg_textsearch extension (no longer needed)

-- Drop BM25 search functions first (they depend on logs table)
DROP FUNCTION IF EXISTS public.bm25_search(text, timestamp with time zone, timestamp with time zone, integer);
DROP FUNCTION IF EXISTS public.bm25_search_full(text, timestamp with time zone, timestamp with time zone, integer);

-- Drop the logs table (data is now in ClickHouse)
-- This will also drop any TimescaleDB hypertable/chunk data
DROP TABLE IF EXISTS public.logs CASCADE;

-- Drop TimescaleDB extension (this cleans up all internal tables)
DROP EXTENSION IF EXISTS timescaledb CASCADE;

-- Drop pg_textsearch extension (BM25 search no longer used)
DROP EXTENSION IF EXISTS pg_textsearch CASCADE;

-- Keep pg_trgm (used for fuzzy matching on detection rules, etc.)
-- Keep uuid-ossp (used for UUID generation)
