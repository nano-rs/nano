-- NAN-2361: preserve the authoritative object ETag returned by the hosted
-- enterprise_shared R2 conditional writer. R2 does not expose S3 bucket
-- versioning, so a compatibility version identifier alone is not sufficient
-- to admit an object into a signed schema-v4 serving manifest.

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS object_etag text;

ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS object_etag text;

ALTER TABLE lake_hot_tail_objects
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_etag_check,
    ADD CONSTRAINT lake_hot_tail_objects_etag_check
        CHECK (
            object_etag IS NULL
            OR (
                length(object_etag) BETWEEN 3 AND 1024
                AND left(object_etag, 1) = '"'
                AND right(object_etag, 1) = '"'
                AND position(
                    '"' IN substring(object_etag FROM 2 FOR length(object_etag) - 2)
                ) = 0
                AND object_etag !~ '[[:cntrl:]]'
            )
        );

COMMENT ON COLUMN lake_hot_tail_objects.object_etag IS
    'Opaque authoritative provider ETag. Required by enterprise_shared R2 schema-v4 publication; NULL preserves existing versioned-S3 deployments.';

ALTER TABLE lake_bronze_object_publications
    DROP CONSTRAINT IF EXISTS lake_bronze_object_publications_etag_check,
    ADD CONSTRAINT lake_bronze_object_publications_etag_check
        CHECK (
            object_etag IS NULL
            OR (
                length(object_etag) BETWEEN 3 AND 1024
                AND left(object_etag, 1) = '"'
                AND right(object_etag, 1) = '"'
                AND position(
                    '"' IN substring(object_etag FROM 2 FOR length(object_etag) - 2)
                ) = 0
                AND object_etag !~ '[[:cntrl:]]'
            )
        );

COMMENT ON COLUMN lake_bronze_object_publications.object_etag IS
    'Opaque authoritative source ETag. Required for enterprise_shared R2 discovery/read; NULL preserves native versioned-S3 Bronze identity.';
