-- NAN-2361: one physical-GC ledger for Iceberg retention and transient tail
-- objects. Tail packing and compaction enroll exact S3 object versions in the
-- same PostgreSQL transaction that removes them from the visible tail. The GC
-- coordinator still requires a healthy serving-generation proof, a signed
-- manifest/reference check, and a bounded grace period before deletion.

ALTER TABLE lake_retention_gc_objects
    ADD COLUMN IF NOT EXISTS gc_kind text NOT NULL DEFAULT 'iceberg_retention',
    ADD COLUMN IF NOT EXISTS table_location_prefix text,
    ADD COLUMN IF NOT EXISTS object_version_id text,
    ADD COLUMN IF NOT EXISTS replacement_batch_sha256 char(64),
    ADD COLUMN IF NOT EXISTS source_compaction_snapshot_id bigint;

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS physical_deleted_at timestamptz;

ALTER TABLE lake_retention_gc_objects
    ALTER COLUMN retention_snapshot_id DROP NOT NULL,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_retention_snapshot_id_check,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_gc_kind_check,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_version_check,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_table_prefix_check,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_replacement_batch_check,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_source_snapshot_check,
    DROP CONSTRAINT IF EXISTS lake_retention_gc_objects_kind_shape_check,
    ADD CONSTRAINT lake_retention_gc_objects_retention_snapshot_id_check
        CHECK (retention_snapshot_id IS NULL OR retention_snapshot_id > 0),
    ADD CONSTRAINT lake_retention_gc_objects_gc_kind_check
        CHECK (gc_kind IN ('iceberg_retention', 'tail_superseded', 'tail_rewrite')),
    ADD CONSTRAINT lake_retention_gc_objects_version_check
        CHECK (
            object_version_id IS NULL
            OR (object_version_id <> '' AND object_version_id <> 'unversioned')
        ),
    ADD CONSTRAINT lake_retention_gc_objects_table_prefix_check
        CHECK (
            table_location_prefix IS NULL
            OR (
                table_location_prefix LIKE 's3://%/'
                AND object_uri LIKE table_location_prefix || '%'
            )
        ),
    ADD CONSTRAINT lake_retention_gc_objects_replacement_batch_check
        CHECK (
            replacement_batch_sha256 IS NULL
            OR replacement_batch_sha256 ~ '^[0-9a-f]{64}$'
        ),
    ADD CONSTRAINT lake_retention_gc_objects_source_snapshot_check
        CHECK (
            source_compaction_snapshot_id IS NULL
            OR source_compaction_snapshot_id > 0
        ),
    ADD CONSTRAINT lake_retention_gc_objects_kind_shape_check
        CHECK (
            (
                gc_kind = 'iceberg_retention'
                AND retention_snapshot_id IS NOT NULL
                AND replacement_batch_sha256 IS NULL
                AND source_compaction_snapshot_id IS NULL
            )
            OR
            (
                gc_kind = 'tail_superseded'
                AND retention_snapshot_id IS NULL
                AND table_location_prefix IS NOT NULL
                AND object_version_id IS NOT NULL
                AND replacement_batch_sha256 IS NOT NULL
                AND source_compaction_snapshot_id IS NULL
            )
            OR
            (
                gc_kind = 'tail_rewrite'
                AND retention_snapshot_id IS NULL
                AND table_location_prefix IS NOT NULL
                AND object_version_id IS NOT NULL
                AND replacement_batch_sha256 IS NULL
                AND source_compaction_snapshot_id IS NOT NULL
            )
        );

CREATE INDEX IF NOT EXISTS idx_lake_exact_object_gc_due
    ON lake_retention_gc_objects
        (tenant_id, table_uuid, gc_kind, eligible_after, object_uri)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_lake_exact_object_gc_identity
    ON lake_retention_gc_objects
        (tenant_id, table_uuid, object_uri, object_version_id);

CREATE INDEX IF NOT EXISTS idx_lake_hot_tail_batch_identity
    ON lake_hot_tail_objects
        (tenant_id, table_location_prefix, batch_sha256);

COMMENT ON COLUMN lake_retention_gc_objects.gc_kind IS
    'iceberg_retention for catalog data files, tail_superseded for packed-away micro-files, tail_rewrite for staged files replaced by a new Iceberg file';
COMMENT ON COLUMN lake_retention_gc_objects.object_version_id IS
    'Exact provider object version to delete; legacy retention rows are resolved and persisted before deletion';
COMMENT ON COLUMN lake_retention_gc_objects.table_location_prefix IS
    'Immutable table storage boundary used to derive and validate the provider object key';
COMMENT ON COLUMN lake_hot_tail_objects.physical_deleted_at IS
    'Exact transient object version was reference-checked and physically removed; the row remains briefly for audit and replacement-chain proofs';
