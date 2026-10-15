-- Immutable, one-time saved-content cutover ledger. The strict OCSF runtime
-- does not carry UDM aliases, so a migration tool records the exact old and new
-- nPL before atomically replacing a durable query.
CREATE TABLE IF NOT EXISTS ocsf_content_migration_backups (
    target_contract TEXT NOT NULL,
    surface TEXT NOT NULL,
    object_id TEXT NOT NULL,
    original_query TEXT NOT NULL,
    migrated_query TEXT NOT NULL,
    migrated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (target_contract, surface, object_id),
    CHECK (target_contract <> ''),
    CHECK (surface <> ''),
    CHECK (object_id <> ''),
    CHECK (original_query <> migrated_query)
);

COMMENT ON TABLE ocsf_content_migration_backups IS
    'Conflict-fenced backup ledger for one-time saved nPL migrations into strict canonical OCSF contracts; never a runtime alias store.';
