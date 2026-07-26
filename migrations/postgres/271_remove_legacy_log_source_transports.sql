-- NAN-2126: log_sources owns parser behavior only.
--
-- Connection configuration and credential references moved to
-- source_configurations in migration 047. The deprecated columns remained
-- writable, however, and the log-source deploy path still decrypted them and
-- generated parser-owned Kafka/S3/GCP sources. Besides duplicating the modern
-- transport model, that let log_sources:deploy use credentials outside the
-- source-configuration authorization boundary.
--
-- Preserve any tenant that still has a legacy fetch parser by converting each
-- parser-owned transport into a dedicated source_configuration before dropping
-- the old columns. A default routing rule preserves the old "all events from
-- this connection go to this parser" behavior.
DO $$
DECLARE
    legacy RECORD;
    migrated_source_config_id UUID;
    routed_source_type TEXT;
BEGIN
    FOR legacy IN
        SELECT
            id,
            name,
            description,
            source_type,
            source_config,
            credential_id,
            match_values,
            enabled,
            deployed,
            deployed_at
        FROM log_sources
        WHERE kind <> 'enrichment'
          AND dispatch_source_config_id IS NULL
          AND LOWER(source_type) IN (
              'kafka',
              'aws_s3',
              'aws_sqs',
              's3',
              'gcp_pubsub',
              'pubsub'
          )
    LOOP
        routed_source_type := COALESCE(
            NULLIF(legacy.match_values[1], ''),
            legacy.name
        );

        INSERT INTO source_configurations (
            name,
            description,
            config_type,
            connection_config,
            credential_id,
            enabled,
            deployed,
            deployed_at,
            default_source_type
        )
        VALUES (
            -- Keep the unique id suffix even when the legacy parser name is
            -- long; truncating the complete string could otherwise collide.
            LEFT(legacy.name, 190)
                || ' migrated transport ['
                || legacy.id::TEXT
                || ']',
            format(
                'Automatically migrated from the deprecated transport embedded in log source %s (%s). %s',
                legacy.name,
                legacy.id,
                COALESCE(legacy.description, '')
            ),
            CASE LOWER(legacy.source_type)
                WHEN 'aws_sqs' THEN 'aws_s3'
                WHEN 's3' THEN 'aws_s3'
                WHEN 'pubsub' THEN 'gcp_pubsub'
                ELSE LOWER(legacy.source_type)
            END,
            legacy.source_config,
            legacy.credential_id,
            legacy.enabled,
            legacy.deployed,
            legacy.deployed_at,
            routed_source_type
        )
        RETURNING id INTO migrated_source_config_id;

        INSERT INTO routing_rules (
            source_configuration_id,
            priority,
            match_field,
            match_type,
            match_value,
            target_source_type
        )
        VALUES (
            migrated_source_config_id,
            1000,
            'source_type',
            'default',
            NULL,
            routed_source_type
        );

        UPDATE log_sources
        SET dispatch_source_config_id = migrated_source_config_id,
            source_type = CASE LOWER(legacy.source_type)
                WHEN 'aws_sqs' THEN 'aws_s3'
                WHEN 's3' THEN 'aws_s3'
                WHEN 'pubsub' THEN 'gcp_pubsub'
                ELSE LOWER(legacy.source_type)
            END,
            updated_at = NOW()
        WHERE id = legacy.id;
    END LOOP;
END
$$;

-- Migration 229's publication trigger names the columns being removed.
-- Recreate it without them so parser edits still advance the publication
-- revision after the schema is narrowed.
DROP TRIGGER IF EXISTS vector_config_log_sources_update ON log_sources;

ALTER TABLE log_sources
    DROP COLUMN source_config,
    DROP COLUMN credential_id,
    DROP COLUMN parser_only;

CREATE TRIGGER vector_config_log_sources_update
BEFORE UPDATE OF
    name, source_type, parser_vrl, match_values,
    enabled, category, vendor, product, namespace, timezone, sampling_ratio,
    sampling_exclude_condition, extension_vrl, extension_enabled,
    dispatch_source_config_id, kind, enrich_kind, enrich_source, target_table,
    normalize_vrl
ON log_sources
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();

COMMENT ON TABLE log_sources IS
    'Log parser definitions. Transport connections and credential references live exclusively in source_configurations.';
