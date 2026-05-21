-- NAN-928: bind a parser (log_source) to the source-configuration whose stream
-- should dispatch events into it. The parser-import "DISPATCH FROM" picker
-- captures the selection in the UI today but the value is dropped on the
-- floor; this column gives it a home so the parser-generator can emit a
-- filter on `<source_config>_route` instead of a brand-new parser-owned
-- Vector source (which left Kafka / S3 / GCP imports disconnected from
-- their source configs and skipped UDM enrichment silently).
--
-- Nullable + ON DELETE SET NULL: when the source configuration is removed
-- the parser stays around as a draft (no dispatch); existing parsers
-- imported before this column existed are NULL and keep their current
-- parser-owned-source generator behavior for backward compatibility.

ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS dispatch_source_config_id UUID
        REFERENCES source_configurations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_log_sources_dispatch_source_config_id
    ON log_sources(dispatch_source_config_id)
    WHERE dispatch_source_config_id IS NOT NULL;
