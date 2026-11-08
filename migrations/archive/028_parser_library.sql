-- Parser Library Schema
-- Pre-built parser library for common security log sources
-- Requirements: 10.1, 10.4, 11.2

-- Pre-built parser library
CREATE TABLE IF NOT EXISTS parser_library (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,           -- endpoint, network, cloud, identity, application, security
    vendor VARCHAR(255),                     -- e.g., Microsoft, AWS, Palo Alto
    source_type VARCHAR(100) NOT NULL,       -- e.g., windows_event, aws_cloudtrail
    parser_vrl TEXT NOT NULL,                -- The VRL remap code for parsing
    sample_logs JSONB DEFAULT '[]',          -- Array of sample log strings for testing
    field_mappings JSONB DEFAULT '{}',       -- Expected field mappings documentation
    version VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    is_system BOOLEAN NOT NULL DEFAULT true, -- true for built-in, false for user copies
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auto-detection patterns for source type identification
CREATE TABLE IF NOT EXISTS detection_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_type VARCHAR(100) NOT NULL,       -- The source type this pattern identifies
    patterns JSONB NOT NULL,                 -- Array of pattern rules with field, regex, weight
    priority INTEGER NOT NULL DEFAULT 0,     -- Higher priority patterns are checked first
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_parser_library_category ON parser_library(category);
CREATE INDEX IF NOT EXISTS idx_parser_library_source_type ON parser_library(source_type);
CREATE INDEX IF NOT EXISTS idx_parser_library_vendor ON parser_library(vendor);
CREATE INDEX IF NOT EXISTS idx_parser_library_is_system ON parser_library(is_system);
CREATE INDEX IF NOT EXISTS idx_detection_patterns_source_type ON detection_patterns(source_type);
CREATE INDEX IF NOT EXISTS idx_detection_patterns_enabled ON detection_patterns(enabled);
CREATE INDEX IF NOT EXISTS idx_detection_patterns_priority ON detection_patterns(priority DESC);

-- Trigger for updated_at on parser_library
CREATE OR REPLACE FUNCTION update_parser_library_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS parser_library_updated_at ON parser_library;
CREATE TRIGGER parser_library_updated_at
    BEFORE UPDATE ON parser_library
    FOR EACH ROW
    EXECUTE FUNCTION update_parser_library_updated_at();

-- Comments for documentation
COMMENT ON TABLE parser_library IS 'Pre-built parser library for common security log sources';
COMMENT ON COLUMN parser_library.category IS 'Parser category: endpoint, network, cloud, identity, application, security';
COMMENT ON COLUMN parser_library.vendor IS 'Vendor or product name (e.g., Microsoft, AWS, Palo Alto)';
COMMENT ON COLUMN parser_library.source_type IS 'Unique identifier for the log source type';
COMMENT ON COLUMN parser_library.sample_logs IS 'JSON array of sample log strings for testing the parser';
COMMENT ON COLUMN parser_library.field_mappings IS 'JSON object documenting expected field mappings';
COMMENT ON COLUMN parser_library.is_system IS 'True for built-in parsers, false for user customizations';

COMMENT ON TABLE detection_patterns IS 'Patterns for auto-detecting log source types';
COMMENT ON COLUMN detection_patterns.patterns IS 'JSON array of {field, regex, weight} pattern rules';
COMMENT ON COLUMN detection_patterns.priority IS 'Higher priority patterns are evaluated first';
