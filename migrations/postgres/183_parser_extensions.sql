-- Parser Extensions (NAN-874)
--
-- Adds a small VRL overlay per log_source that runs as an extra Vector transform
-- chained between the parser's _parse and _output steps. One extension per log_source.
-- NULL extension_vrl = no overlay; extension_enabled=false = overlay present but bypassed.
--
-- Stub case: a log_source may have extension_vrl set with parser_vrl empty/placeholder
-- (the extension IS the parser). Vector wiring handles this in router.rs / parser_config.rs.

ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS extension_vrl TEXT,
    ADD COLUMN IF NOT EXISTS extension_enabled BOOLEAN NOT NULL DEFAULT false;

-- Version history mirrors so revert restores both parser and extension state.
ALTER TABLE log_source_versions
    ADD COLUMN IF NOT EXISTS extension_vrl TEXT,
    ADD COLUMN IF NOT EXISTS extension_enabled BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN log_sources.extension_vrl IS 'Optional VRL overlay chained after {name}_parse, before {name}_output. NULL = no extension.';
COMMENT ON COLUMN log_sources.extension_enabled IS 'When false, extension_vrl is persisted but not deployed.';
COMMENT ON COLUMN log_source_versions.extension_vrl IS 'Snapshot of extension_vrl at publish time. NULL preserved through restore.';
COMMENT ON COLUMN log_source_versions.extension_enabled IS 'Snapshot of extension_enabled at publish time.';
