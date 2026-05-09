-- Lookup Tables Registry
-- Migration: 025_lookup_tables.sql
-- Requirements: 2.1, 2.2, 2.7
--
-- Registry for user-created lookup tables used for search enrichment.
-- Each lookup table is stored as a dynamic PostgreSQL table with the
-- actual table name stored in the registry.

CREATE TABLE IF NOT EXISTS lookup_tables_registry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,          -- User-friendly name
    description TEXT,
    table_name VARCHAR(255) NOT NULL UNIQUE,    -- Actual PostgreSQL table name (prefixed)
    columns JSONB NOT NULL,                     -- Column definitions [{name, data_type, nullable}]
    primary_key VARCHAR(255),                   -- Primary key column name for efficient lookups
    row_count BIGINT DEFAULT 0,
    size_bytes BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for name lookups
CREATE INDEX IF NOT EXISTS idx_lookup_tables_name ON lookup_tables_registry(name);

-- Index for listing tables by creation time
CREATE INDEX IF NOT EXISTS idx_lookup_tables_created ON lookup_tables_registry(created_at DESC);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_lookup_tables_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS lookup_tables_updated_at ON lookup_tables_registry;
CREATE TRIGGER lookup_tables_updated_at
    BEFORE UPDATE ON lookup_tables_registry
    FOR EACH ROW
    EXECUTE FUNCTION update_lookup_tables_updated_at();
