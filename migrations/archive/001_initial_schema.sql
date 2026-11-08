-- NanoSIEM Initial Database Schema
-- Requirements: 4.1, 4.2, 4.3, 4.4

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Note: pg_textsearch extension for BM25 search is enabled in migration 014

-- Main logs table - will be converted to TimescaleDB hypertable
-- TimescaleDB handles time-based chunking and compression automatically
CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_content TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    
    -- Unified Data Model fields (denormalized for fast filtering)
    -- Entity fields (using TEXT for IPs for flexibility)
    src_ip TEXT,
    dest_ip TEXT,
    src_host TEXT,
    dest_host TEXT,
    
    -- Network fields
    src_port INTEGER,
    dest_port INTEGER,
    protocol TEXT,
    bytes_in BIGINT,
    bytes_out BIGINT,
    
    -- User/Action fields
    "user" TEXT,
    action TEXT,
    status TEXT,
    
    -- Authentication fields
    auth_type TEXT,
    auth_result TEXT,
    session_id TEXT,
    
    -- Process fields
    process_name TEXT,
    process_id INTEGER,
    parent_process TEXT,
    command_line TEXT,
    
    -- File fields
    file_path TEXT,
    file_name TEXT,
    file_hash TEXT,
    file_action TEXT
);

-- Convert to TimescaleDB hypertable with 1-day chunks
SELECT create_hypertable('logs', 'timestamp', 
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => true
);

-- GIN index on metadata for JSONB queries
CREATE INDEX IF NOT EXISTS idx_logs_metadata ON logs USING GIN (metadata);

-- B-tree indexes on UDM fields for fast filtering
CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON logs (src_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_dest_ip ON logs (dest_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_src_host ON logs (src_host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_dest_host ON logs (dest_host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_user ON logs ("user", timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_action ON logs (action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_status ON logs (status, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_process_name ON logs (process_name, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_file_path ON logs (file_path, timestamp DESC);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_logs_src_dest_ip ON logs (src_ip, dest_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_user_action ON logs ("user", action, timestamp DESC);

-- Note: Full-text search uses pg_textsearch BM25 index (see migration 014)
-- Compression is configured in migration 015
