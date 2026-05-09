-- ============================================================================
-- Migration 051: Drop Legacy parsers Table
-- ============================================================================
-- The parsers table was superseded by log_sources in migration 009.
-- However, both tables have been maintained in parallel, causing data sync issues
-- where parser_vrl changes in one table don't propagate to the other.
--
-- This migration:
-- 1. Ensures all data from parsers is in log_sources (one-time sync)
-- 2. Drops the parsers table to eliminate the duplication bug
-- 3. Keeps parser_library (used for templates) and parser_deployments (renamed to log_source_deployments)
-- ============================================================================

-- Only run sync if parsers table still exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'parsers') THEN
        -- Sync any parsers that might exist in parsers but not in log_sources
        INSERT INTO log_sources (
            id, name, description,
            source_type, source_config, credential_id,
            parser_vrl, output_fields,
            validated, validation_error, enabled,
            created_at, updated_at
        )
        SELECT
            p.id,
            p.name,
            p.description,
            COALESCE(p.source_type, 'routed'),
            p.source_config,
            p.credential_id,
            p.parser_vrl,
            p.output_fields,
            p.validated,
            p.validation_error,
            p.enabled,
            p.created_at,
            p.updated_at
        FROM parsers p
        WHERE NOT EXISTS (SELECT 1 FROM log_sources ls WHERE ls.id = p.id)
        ON CONFLICT (id) DO NOTHING;

        -- Update any log_sources entries where parsers has newer parser_vrl
        UPDATE log_sources ls
        SET parser_vrl = p.parser_vrl,
            updated_at = GREATEST(ls.updated_at, p.updated_at)
        FROM parsers p
        WHERE ls.id = p.id
          AND p.updated_at > ls.updated_at;
    END IF;
END $$;

-- Drop the parsers table (IF EXISTS makes this idempotent)
DROP TABLE IF EXISTS parsers CASCADE;

-- Add a comment explaining the migration
COMMENT ON TABLE log_sources IS 'Unified log source configuration. Supersedes the legacy parsers table as of migration 051.';
