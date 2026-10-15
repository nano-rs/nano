-- NAN-2361: make freshly committed Signal and platform-audit files visible
-- through the signed hot tail until their Iceberg snapshot is promoted into
-- the indexed serving generation.
--
-- Vector micro-batches still live below data/tail/tenant_sha256=... and enter
-- this ledger as `staged`. Product-event files are already immutable members
-- of a newer Iceberg snapshot, so the publisher records them as `compacted`
-- with that snapshot ID. Packers/compactors therefore never duplicate them;
-- activation removes them from the tail when the indexed base reaches the
-- same snapshot or a descendant.

ALTER TABLE lake_hot_tail_objects
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_object_uri_check,
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_table_identity_check;

ALTER TABLE lake_hot_tail_objects
    ADD CONSTRAINT lake_hot_tail_objects_object_uri_check
        CHECK (
            object_uri LIKE 's3://%/data/%'
            AND object_uri NOT LIKE 's3://%/metadata/%'
            AND object_uri LIKE '%.parquet'
        ),
    ADD CONSTRAINT lake_hot_tail_objects_table_identity_check
        CHECK (
            event_table <> ''
            AND table_location_prefix LIKE 's3://%/'
            AND object_uri LIKE table_location_prefix || 'data/%'
        );

COMMENT ON TABLE lake_hot_tail_objects IS
    'Exact-version canonical OCSF Parquet objects visible beside an indexed Iceberg base until their catalog snapshot becomes active.';
COMMENT ON COLUMN lake_hot_tail_objects.compaction_snapshot_id IS
    'Iceberg snapshot already containing this exact object; NULL only for out-of-catalog staged ingest files.';
