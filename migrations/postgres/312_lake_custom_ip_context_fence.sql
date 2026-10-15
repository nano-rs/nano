-- NAN-2361: pin the exact immutable custom CIDR generation used to decorate
-- each reserved Bronze batch. Retries must reopen the same snapshot even when
-- a newer custom feed has been published in the meantime.

ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS ip_context_snapshot_sha256 text
        CHECK (
            ip_context_snapshot_sha256 IS NULL
            OR ip_context_snapshot_sha256 ~ '^[0-9a-f]{64}$'
        );

COMMENT ON COLUMN lake_bronze_object_publications.ip_context_snapshot_sha256 IS
    'Exact immutable custom CIDR snapshot used before OCSF validation, or NULL when no custom context is active.';
