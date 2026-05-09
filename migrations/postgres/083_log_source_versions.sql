-- Log Source Versions: Draft state + revision history with rollback
--
-- Design:
--   log_sources.parser_vrl = working copy (draft)
--   Active version's parser_vrl = what gets deployed
--   Publish creates a new version snapshot, rollback activates a previous one

CREATE TABLE IF NOT EXISTS log_source_versions (
    id SERIAL PRIMARY KEY,
    log_source_id UUID NOT NULL REFERENCES log_sources(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    parser_vrl TEXT NOT NULL,
    output_fields JSONB,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    change_reason TEXT NOT NULL,  -- 'initial_creation', 'publish', 'revert'
    reverted_from_version INTEGER,
    CONSTRAINT uq_log_source_version UNIQUE (log_source_id, version_number)
);

CREATE INDEX idx_lsv_log_source_id ON log_source_versions(log_source_id);
CREATE INDEX idx_lsv_active ON log_source_versions(log_source_id) WHERE is_active = true;

-- Seed: deployed log sources get version 1 (active)
INSERT INTO log_source_versions (log_source_id, version_number, parser_vrl, output_fields, is_active, change_reason)
SELECT id, 1, parser_vrl, output_fields, true, 'initial_creation'
FROM log_sources WHERE deployed = true;

-- Seed: non-deployed log sources with VRL content get version 1 (inactive)
INSERT INTO log_source_versions (log_source_id, version_number, parser_vrl, output_fields, is_active, change_reason)
SELECT id, 1, parser_vrl, output_fields, false, 'initial_creation'
FROM log_sources WHERE deployed = false AND parser_vrl IS NOT NULL AND parser_vrl != ''
AND id NOT IN (SELECT log_source_id FROM log_source_versions);
