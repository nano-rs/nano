-- NAN-1919: default source_type for pull-transport source configs.
-- Unmatched events (no routing rule fired) fall back to this value instead
-- of "unknown". Seeded from the onboarded feed's name on first routing rule.
ALTER TABLE source_configurations
    ADD COLUMN IF NOT EXISTS default_source_type TEXT;

-- NAN-1919: keep the Vector-config publication revision in sync when
-- default_source_type changes. Migration 229 created
-- `vector_config_sources_update` (BEFORE UPDATE OF ...) to bump the
-- publication revision so deployed routing is regenerated, but its column
-- list predates this column — so seeding/updating default_source_type would
-- leave the deployed routing stale (stuck emitting "unknown"). Recreate the
-- trigger with default_source_type added. The bump function already exists
-- from 229; do NOT modify 229.
DROP TRIGGER IF EXISTS vector_config_sources_update ON source_configurations;
CREATE TRIGGER vector_config_sources_update
BEFORE UPDATE OF
    name, config_type, connection_config, credential_id, enabled, deployed, default_source_type
ON source_configurations
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();
