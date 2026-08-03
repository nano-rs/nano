-- NAN-2304: publish what is actually deployed, from a renderer that identifies
-- itself completely.
--
-- Two independent gaps in the migration-229 publication protocol:
--
--   1. Activating a `log_source_versions` row — i.e. PUBLISHING a parser — did
--      not move `source_revision`. Only the working-copy columns on
--      `log_sources` are trigger inputs, so the fence fired for every editor
--      save (which must NOT be published) and stayed silent for the one event
--      that must be (which version is live). Now that the renderer reads the
--      active version rather than the working copy, a publish/revert/discard
--      that changes the live artefact has to advance the fence itself.
--
--   2. Renderer identity was `(epoch, semantic version)`. Inputs that change
--      the rendered bytes but live in the process environment —
--      `NANO_SCHEMA_PROFILE` above all — were invisible: an env-only UDM→OCSF
--      flip left the revision untouched, so replicas reused the materialized
--      UDM generation indefinitely, and any replica that did re-render was
--      rejected as a divergent render of a revision it could never match.
--      `renderer_fingerprint` carries a digest of those inputs.

-- ---------------------------------------------------------------------------
-- 1. Fence active-version changes into source_revision.
-- ---------------------------------------------------------------------------
--
-- BEFORE STATEMENT, matching migration 229: mutations acquire the singleton
-- revision fence before table rows, which keeps lock order aligned with the
-- publisher and prevents cross-table deadlocks.
--
-- `is_active` is the column that selects the deployed artefact; the payload
-- columns are listed too because `create_version` writes a row and flips it
-- active in one transaction, and a hand-corrected version row must republish.
-- INSERT and DELETE are fenced because `create_version` inserts the new active
-- row and `prune_versions` deletes old ones.

DROP TRIGGER IF EXISTS vector_config_log_source_versions_insert_delete
    ON log_source_versions;
CREATE TRIGGER vector_config_log_source_versions_insert_delete
BEFORE INSERT OR DELETE ON log_source_versions
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

DROP TRIGGER IF EXISTS vector_config_log_source_versions_update
    ON log_source_versions;
CREATE TRIGGER vector_config_log_source_versions_update
BEFORE UPDATE OF
    is_active, parser_vrl, output_fields, extension_vrl, extension_enabled
ON log_source_versions
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

COMMENT ON TABLE log_source_versions IS
    'Versioned parser snapshots. The is_active row is what the Vector renderer deploys; changes here bump vector_config_publication_state.source_revision (NAN-2304).';

-- ---------------------------------------------------------------------------
-- 2. Record the renderer fingerprint on every committed generation.
-- ---------------------------------------------------------------------------
--
-- The fingerprint lives on the immutable snapshot row, not on the singleton
-- pointer, so the pointer's shape CHECK and composite FK from migration 229
-- stay byte-for-byte as they were. Readers resolve it by joining the pointer's
-- current_generation.
--
-- DEFAULT '' rather than NOT NULL with a real value: generations published
-- before this migration have no fingerprint to backfill, and '' never equals a
-- real (64-hex) digest, so the first reconcile after upgrade correctly treats
-- the running renderer as a new identity and republishes once.

ALTER TABLE vector_config_snapshots
    ADD COLUMN IF NOT EXISTS renderer_fingerprint TEXT NOT NULL DEFAULT '';

ALTER TABLE vector_config_snapshots
    DROP CONSTRAINT IF EXISTS vector_config_snapshots_renderer_fingerprint_format;
ALTER TABLE vector_config_snapshots
    ADD CONSTRAINT vector_config_snapshots_renderer_fingerprint_format
    CHECK (renderer_fingerprint = '' OR renderer_fingerprint ~ '^[0-9a-f]{64}$');

-- The uniqueness key must admit two generations that share a revision and a
-- renderer version but were rendered from different environments — that is
-- exactly the mixed-profile rollout this migration exists to unblock. Without
-- widening it, the new PublishNew path would fail on a unique violation and
-- retry forever.
--
-- Not referenced by any foreign key (the pointer FK uses
-- vector_config_snapshots_generation_hash_key), so this drop is local.
ALTER TABLE vector_config_snapshots
    DROP CONSTRAINT IF EXISTS vector_config_snapshots_source_renderer_key;
ALTER TABLE vector_config_snapshots
    ADD CONSTRAINT vector_config_snapshots_source_renderer_key
    UNIQUE (source_revision, renderer_epoch, renderer_version, renderer_fingerprint);

COMMENT ON COLUMN vector_config_snapshots.renderer_fingerprint IS
    'SHA-256 over the render-affecting environment inputs (schema profile, router presence flags, source-config paths). Empty for generations published before NAN-2304.';
