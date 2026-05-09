-- Per-source timezone support for log ingestion
-- Allows each log source to specify an IANA timezone for timestamps without offset info
ALTER TABLE log_sources ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC';
COMMENT ON COLUMN log_sources.timezone IS 'IANA timezone name for timestamps without offset info (e.g., America/New_York)';
