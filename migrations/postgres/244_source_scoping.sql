-- Per-Source RBAC Scoping — foundation schema (NAN-1797 / epic NAN-1789)
-- Data-level visibility scoping keyed on the event-borne `source_type` string.
--
-- Model (see docs-internal/working-notes/RBAC_SOURCE_SCOPING_DESIGN.md §6):
--   * restricted_source_types = the registry of source_type values that are
--     invisible-by-default. An EMPTY registry == today's behavior exactly
--     (default allow-all; deny-by-omission).
--   * source_type_grants = which groups may see a restricted source_type. A
--     user's visibility = all unrestricted sources ∪ sources granted to any of
--     their groups. Granting a restricted source to the "Everyone" system group
--     (00000000-0000-0000-0000-000000000001) un-restricts it without deleting
--     the registry row.
--
-- The enforceable unit is the source_type STRING VALUE, not the log-source
-- UUID: events carry the stamped string, never the log_sources.id. Multiple
-- log_sources rows can stamp the same source_type, so grants bind to the value.

-- =============================================================================
-- Restricted source registry
-- =============================================================================

CREATE TABLE IF NOT EXISTS restricted_source_types (
    source_type VARCHAR(100) PRIMARY KEY,               -- the event-borne string value
    description TEXT,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE restricted_source_types IS 'Registry of source_type values that are invisible-by-default; empty table = allow-all (NAN-1797)';
COMMENT ON COLUMN restricted_source_types.source_type IS 'Event-borne source_type string value (NOT a log_sources UUID); deny-by-omission once listed';

-- =============================================================================
-- Group grants for restricted sources
-- =============================================================================
--
-- source_type carries an FK to restricted_source_types(source_type) ON DELETE
-- CASCADE: since both tables live in this migration we prefer the FK for
-- referential integrity (un-listing a source drops its grants). This is
-- stronger than the design doc §6.1 sketch (which left the value free-standing
-- to survive log_sources deletion) — we still keep NO FK to log_sources, so the
-- value survives parser deletion/rename; it is only tied to the registry it
-- belongs to.

CREATE TABLE IF NOT EXISTS source_type_grants (
    source_type VARCHAR(100) NOT NULL
                REFERENCES restricted_source_types(source_type) ON DELETE CASCADE,
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (source_type, group_id)
);

COMMENT ON TABLE source_type_grants IS 'Groups permitted to see a restricted source_type; grant to Everyone (…0001) to un-restrict (NAN-1797)';

-- Resolver walks user_groups → source_type_grants by group_id (see
-- SourceScopeResolver §6.2); index the join key.
CREATE INDEX IF NOT EXISTS idx_source_type_grants_group_id
    ON source_type_grants(group_id);

-- =============================================================================
-- Updated timestamp trigger (reuse the shared public.update_updated_at_column())
-- =============================================================================

DROP TRIGGER IF EXISTS restricted_source_types_set_updated_at ON restricted_source_types;
CREATE TRIGGER restricted_source_types_set_updated_at
    BEFORE UPDATE ON restricted_source_types
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

-- =============================================================================
-- Permissions
-- =============================================================================

INSERT INTO permissions (id, name, description, category) VALUES
    ('source_scopes:view', 'View Source Scopes', 'View the restricted source registry and group grants', 'source_scopes'),
    ('source_scopes:manage', 'Manage Source Scopes', 'Create, edit, and delete restricted sources and their group grants', 'source_scopes')
ON CONFLICT (id) DO NOTHING;

-- Grant both to the Admin role (security-sensitive visibility control — admin only).
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,  -- Admin role
    id
FROM permissions
WHERE id LIKE 'source_scopes:%'
ON CONFLICT DO NOTHING;
