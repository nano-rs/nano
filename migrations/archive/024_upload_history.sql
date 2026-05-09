-- Upload History Table
-- Migration: 024_upload_history.sql
-- Requirements: 5.1, 5.2
--
-- Tracks all file uploads for both log ingestion and lookup table creation.
-- Provides audit trail and allows users to view upload history with filtering.

CREATE TABLE IF NOT EXISTS upload_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    file_format VARCHAR(50) NOT NULL,           -- 'csv', 'json', 'ndjson'
    destination_type VARCHAR(50) NOT NULL,      -- 'logs' or 'lookup'
    destination_name VARCHAR(255) NOT NULL,     -- source_type for logs, table_name for lookup
    records_total BIGINT DEFAULT 0,
    records_success BIGINT DEFAULT 0,
    records_failed BIGINT DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'processing',  -- 'processing', 'completed', 'failed'
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Index for listing uploads by creation time (most recent first)
CREATE INDEX IF NOT EXISTS idx_upload_history_created ON upload_history(created_at DESC);

-- Index for filtering by status
CREATE INDEX IF NOT EXISTS idx_upload_history_status ON upload_history(status);

-- Index for filtering by destination type and name
CREATE INDEX IF NOT EXISTS idx_upload_history_destination ON upload_history(destination_type, destination_name);

-- Composite index for common filter patterns (date range + status)
CREATE INDEX IF NOT EXISTS idx_upload_history_status_created ON upload_history(status, created_at DESC);

-- Composite index for destination filtering with date
CREATE INDEX IF NOT EXISTS idx_upload_history_dest_created ON upload_history(destination_type, created_at DESC);
