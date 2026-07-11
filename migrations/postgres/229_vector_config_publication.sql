-- NAN-1779: monotonic publication protocol for generated Vector configuration.
--
-- API replicas render independently, so their pod-local files are never an
-- authority. Database mutations bump source_revision. A renderer may publish
-- only when the revision remained stable for its entire render, and the
-- singleton state row serializes the current-generation CAS. A monotonic
-- renderer epoch fences intentional semantic-version rollbacks.

CREATE SEQUENCE IF NOT EXISTS vector_config_generation_seq AS BIGINT;

CREATE TABLE IF NOT EXISTS vector_config_snapshots (
    generation BIGINT PRIMARY KEY DEFAULT nextval('vector_config_generation_seq'),
    source_revision BIGINT NOT NULL,
    renderer_epoch BIGINT NOT NULL DEFAULT 0,
    renderer_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    manifest JSONB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vector_config_snapshots_generation_positive CHECK (generation > 0),
    CONSTRAINT vector_config_snapshots_source_revision_positive CHECK (source_revision > 0),
    CONSTRAINT vector_config_snapshots_renderer_epoch_nonnegative CHECK (renderer_epoch >= 0),
    CONSTRAINT vector_config_snapshots_manifest_object CHECK (jsonb_typeof(manifest) = 'object'),
    CONSTRAINT vector_config_snapshots_created_by_nonempty CHECK (btrim(created_by) <> ''),
    CONSTRAINT vector_config_snapshots_hash_format
        CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT vector_config_snapshots_renderer_version_format
        CHECK (renderer_version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$'),
    CONSTRAINT vector_config_snapshots_source_renderer_key
        UNIQUE (source_revision, renderer_epoch, renderer_version),
    CONSTRAINT vector_config_snapshots_generation_hash_key
        UNIQUE (
            generation, content_hash, renderer_epoch,
            renderer_version, source_revision
        )
);

CREATE TABLE IF NOT EXISTS vector_config_publication_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    source_revision BIGINT NOT NULL DEFAULT 1 CHECK (source_revision > 0),
    published_source_revision BIGINT NOT NULL DEFAULT 0
        CHECK (published_source_revision >= 0),
    current_generation BIGINT REFERENCES vector_config_snapshots(generation),
    current_content_hash TEXT,
    current_renderer_epoch BIGINT NOT NULL DEFAULT 0
        CHECK (current_renderer_epoch >= 0),
    current_renderer_version TEXT NOT NULL DEFAULT '0.0.0',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vector_config_publication_pointer_shape CHECK (
        (current_generation IS NULL AND current_content_hash IS NULL
            AND current_renderer_epoch = 0
            AND current_renderer_version = '0.0.0')
        OR
        (current_generation IS NOT NULL
            AND current_content_hash ~ '^[0-9a-f]{64}$'
            AND current_renderer_version ~ '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$'
            AND current_renderer_version <> '0.0.0')
    ),
    CONSTRAINT vector_config_publication_commit_shape CHECK (
        (published_source_revision = 0 AND current_generation IS NULL)
        OR
        (published_source_revision > 0 AND current_generation IS NOT NULL)
    ),
    CONSTRAINT vector_config_publication_revision_order
        CHECK (published_source_revision <= source_revision),
    CONSTRAINT vector_config_publication_generation_hash_fkey
        FOREIGN KEY (
            current_generation, current_content_hash,
            current_renderer_epoch, current_renderer_version,
            published_source_revision
        )
        REFERENCES vector_config_snapshots(
            generation, content_hash, renderer_epoch,
            renderer_version, source_revision
        )
);

INSERT INTO vector_config_publication_state (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION bump_vector_config_source_revision()
RETURNS TRIGGER AS $$
DECLARE
    next_revision BIGINT;
BEGIN
    UPDATE vector_config_publication_state
       SET source_revision = source_revision + 1,
           updated_at = NOW()
     WHERE singleton = TRUE
     RETURNING source_revision INTO next_revision;

    PERFORM pg_notify('vector_config_changed', next_revision::TEXT);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reject_vector_config_snapshot_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Vector config snapshot generations are immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vector_config_snapshots_immutable ON vector_config_snapshots;
CREATE TRIGGER vector_config_snapshots_immutable
BEFORE UPDATE ON vector_config_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_vector_config_snapshot_update();

CREATE OR REPLACE FUNCTION reject_vector_config_renderer_epoch_regression()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.current_renderer_epoch < OLD.current_renderer_epoch THEN
        RAISE EXCEPTION 'Vector config renderer epoch cannot decrease';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vector_config_renderer_epoch_monotonic
    ON vector_config_publication_state;
CREATE TRIGGER vector_config_renderer_epoch_monotonic
BEFORE UPDATE OF current_renderer_epoch ON vector_config_publication_state
FOR EACH ROW EXECUTE FUNCTION reject_vector_config_renderer_epoch_regression();

-- A credential disappearing from a deployed source must fail closed. The
-- service already rejects deletion while a parser depends on a credential;
-- enforce the same invariant for both config owners at the database boundary
-- so direct SQL and concurrent writers cannot turn an authenticated source
-- into an unauthenticated generation through ON DELETE SET NULL.
ALTER TABLE log_sources
    DROP CONSTRAINT IF EXISTS log_sources_credential_id_fkey;
ALTER TABLE log_sources
    ADD CONSTRAINT log_sources_credential_id_fkey
    FOREIGN KEY (credential_id) REFERENCES cloud_credentials(id) ON DELETE RESTRICT;

ALTER TABLE source_configurations
    DROP CONSTRAINT IF EXISTS source_configurations_credential_id_fkey;
ALTER TABLE source_configurations
    ADD CONSTRAINT source_configurations_credential_id_fkey
    FOREIGN KEY (credential_id) REFERENCES cloud_credentials(id) ON DELETE RESTRICT;

-- Parser/log-source fields consumed by VectorConfigManager. Deployment and
-- validation bookkeeping is intentionally omitted unless it changes the
-- effective enabled parser set. BEFORE STATEMENT is deliberate: mutations
-- acquire the singleton revision fence before table rows, matching publisher
-- lock order and preventing cross-table credential/source deadlocks.
DROP TRIGGER IF EXISTS vector_config_log_sources_insert_delete ON log_sources;
CREATE TRIGGER vector_config_log_sources_insert_delete
BEFORE INSERT OR DELETE ON log_sources
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

DROP TRIGGER IF EXISTS vector_config_log_sources_update ON log_sources;
CREATE TRIGGER vector_config_log_sources_update
BEFORE UPDATE OF
    name, source_type, source_config, credential_id, parser_vrl, match_values,
    enabled, category, vendor, product, namespace, timezone, sampling_ratio,
    sampling_exclude_condition, extension_vrl, extension_enabled,
    dispatch_source_config_id, kind, enrich_kind, enrich_source, target_table,
    normalize_vrl
ON log_sources
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

DROP TRIGGER IF EXISTS vector_config_sources_insert_delete ON source_configurations;
CREATE TRIGGER vector_config_sources_insert_delete
BEFORE INSERT OR DELETE ON source_configurations
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

DROP TRIGGER IF EXISTS vector_config_sources_update ON source_configurations;
CREATE TRIGGER vector_config_sources_update
BEFORE UPDATE OF
    name, config_type, connection_config, credential_id, enabled, deployed
ON source_configurations
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

DROP TRIGGER IF EXISTS vector_config_routing_rules_change ON routing_rules;
CREATE TRIGGER vector_config_routing_rules_change
BEFORE INSERT OR UPDATE OR DELETE ON routing_rules
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

-- The active encrypted payload is mirrored on cloud_credentials. Exclude
-- last_used_at so rendering a credential cannot make the revision self-dirty.
DROP TRIGGER IF EXISTS vector_config_credentials_insert_delete ON cloud_credentials;
CREATE TRIGGER vector_config_credentials_insert_delete
BEFORE INSERT OR DELETE ON cloud_credentials
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

DROP TRIGGER IF EXISTS vector_config_credentials_update ON cloud_credentials;
CREATE TRIGGER vector_config_credentials_update
BEFORE UPDATE OF
    name, provider, credentials_encrypted, nonce, region, active_version
ON cloud_credentials
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

COMMENT ON TABLE vector_config_snapshots IS
    'Immutable path/size manifests for committed Vector configuration generations; plaintext config and per-file secret-bearing hashes are not persisted';
COMMENT ON TABLE vector_config_publication_state IS
    'Singleton CAS pointer and source revision for multi-node Vector config publication';
