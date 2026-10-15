-- NAN-2361: quarantine exact object versions that can be rejected from trusted
-- object metadata alone. Zero/oversized files must not wedge discovery, and a
-- source that rewrites an already-rejected immutable key must not force Nano to
-- download every later version just to reject the key again.

-- The development publisher can apply this constraint before the API process
-- has restarted onto the migration that records it. Keep the DDL replay-safe so
-- the normal SQLx runner can subsequently record migration 296 without a
-- special-case history edit. Production still executes this exactly once.
ALTER TABLE lake_bronze_object_publications
    DROP CONSTRAINT IF EXISTS lake_bronze_object_publications_object_bytes_check,
    DROP CONSTRAINT IF EXISTS lake_bronze_object_publications_object_sha256_check,
    DROP CONSTRAINT IF EXISTS lake_bronze_object_identity_complete,
    ALTER COLUMN object_sha256 DROP NOT NULL;

ALTER TABLE lake_bronze_object_publications
    ADD CONSTRAINT lake_bronze_object_identity_complete
        CHECK (
            (
                status IN ('pending', 'published')
                AND object_bytes > 0
                AND object_sha256 ~ '^[0-9a-f]{64}$'
            )
            OR
            (
                status = 'rejected'
                AND object_bytes >= 0
                AND (
                    (
                        rejection_code IN ('invalid_object_size', 'immutable_key_quarantined')
                        AND object_sha256 IS NULL
                    )
                    OR
                    (
                        rejection_code NOT IN ('invalid_object_size', 'immutable_key_quarantined')
                        AND object_bytes > 0
                        AND object_sha256 ~ '^[0-9a-f]{64}$'
                    )
                )
            )
        );

COMMENT ON CONSTRAINT lake_bronze_object_identity_complete
    ON lake_bronze_object_publications IS
    'Published/pending rows carry exact content identity. Metadata-only rejection codes intentionally carry no fabricated content digest.';
