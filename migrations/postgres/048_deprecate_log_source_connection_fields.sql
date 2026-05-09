-- Mark connection-related fields as deprecated on log_sources
-- These fields will be migrated to source_configurations
-- The fields are kept for backward compatibility but should not be used for new log sources

-- Add deprecation comments to log_sources columns
COMMENT ON COLUMN log_sources.source_config IS 'DEPRECATED: Use source_configurations table instead. Connection-specific configuration.';
COMMENT ON COLUMN log_sources.credential_id IS 'DEPRECATED: Use source_configurations.credential_id instead. Cloud credential reference.';
COMMENT ON COLUMN log_sources.match_field IS 'DEPRECATED: Use routing_rules table instead. Field to match on for routing.';
COMMENT ON COLUMN log_sources.match_pattern IS 'DEPRECATED: Use routing_rules table instead. Regex pattern to match.';
COMMENT ON COLUMN log_sources.match_values IS 'DEPRECATED: Use routing_rules table instead. Exact values to match.';

-- Update table comment
COMMENT ON TABLE log_sources IS 'Log source parsers. Connection config is now in source_configurations table. Only parser_vrl and metadata fields should be used for new log sources.';

-- Add a column to track if this log source uses the new source_configs pattern
-- When source_config is empty/null and this is true, the log source is purely a parser
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS parser_only BOOLEAN NOT NULL DEFAULT false;
COMMENT ON COLUMN log_sources.parser_only IS 'When true, this log source is parser-only and uses source_configurations for connection config';

-- For existing log sources with source_type = "routed", mark as parser_only
-- These already receive logs via HTTP routing and don't need connection config
UPDATE log_sources SET parser_only = true WHERE source_type = 'routed' AND source_config = '{}';
