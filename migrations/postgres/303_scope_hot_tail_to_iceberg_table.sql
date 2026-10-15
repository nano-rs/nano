-- NAN-2361: bind every staged-tail object to one immutable Iceberg table
-- location. Tenant scope alone is insufficient during a table replacement:
-- pending objects from the retired table must never enter the successor's
-- pack, compaction, serving-tail, or activation ledgers.

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS event_table text,
    ADD COLUMN IF NOT EXISTS table_location_prefix text;

-- Preview builds created this ledger before table identity was recorded. The
-- exact object URI contains the owning table root, so recover that boundary
-- losslessly. The catalog name is audit metadata; the location is the durable
-- storage identity used by coordinators.
UPDATE lake_hot_tail_objects
SET table_location_prefix = regexp_replace(object_uri, 'data/tail/.*$', ''),
    event_table = COALESCE(event_table, '__legacy__')
WHERE table_location_prefix IS NULL OR event_table IS NULL;

ALTER TABLE lake_hot_tail_objects
    ALTER COLUMN event_table SET NOT NULL,
    ALTER COLUMN table_location_prefix SET NOT NULL,
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_table_identity_check,
    ADD CONSTRAINT lake_hot_tail_objects_table_identity_check
        CHECK (
            event_table <> ''
            AND table_location_prefix LIKE 's3://%/'
            AND object_uri LIKE table_location_prefix || 'data/tail/%'
        );

ALTER TABLE lake_hot_tail_objects
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_pkey,
    ADD CONSTRAINT lake_hot_tail_objects_pkey PRIMARY KEY
        (tenant_id, table_location_prefix, bronze_store_id, batch_sha256, event_hour);

DROP INDEX IF EXISTS idx_lake_hot_tail_visible;
CREATE INDEX idx_lake_hot_tail_visible
    ON lake_hot_tail_objects
        (tenant_id, table_location_prefix, status, event_hour, staged_at, object_uri)
    WHERE status IN ('staged', 'compacted');

DROP INDEX IF EXISTS idx_lake_hot_tail_compaction;
CREATE INDEX idx_lake_hot_tail_compaction
    ON lake_hot_tail_objects
        (tenant_id, table_location_prefix, bronze_store_id, status, event_hour, staged_at)
    WHERE status = 'staged';

COMMENT ON COLUMN lake_hot_tail_objects.event_table IS
    'Catalog table identifier that accepted this exact staged object.';
COMMENT ON COLUMN lake_hot_tail_objects.table_location_prefix IS
    'Immutable table storage boundary used to isolate packing, compaction, serving-tail, and activation.';
