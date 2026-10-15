-- NAN-2361: let independent tail-packer replicas claim disjoint immutable
-- input sets before object I/O. The previous table-wide advisory lock covered
-- download, decode, sort, compression, upload, and acknowledgement, so adding
-- replicas still used one core and capped the tenant near 1 TB/day.

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS pack_batch_id uuid,
    ADD COLUMN IF NOT EXISTS pack_reserved_at timestamptz;

ALTER TABLE lake_hot_tail_objects
    DROP CONSTRAINT IF EXISTS lake_hot_tail_pack_reservation_check,
    ADD CONSTRAINT lake_hot_tail_pack_reservation_check CHECK (
        (pack_batch_id IS NULL AND pack_reserved_at IS NULL)
        OR
        (status = 'staged' AND compaction_batch_id IS NULL
            AND pack_batch_id IS NOT NULL AND pack_reserved_at IS NOT NULL)
    );

CREATE INDEX IF NOT EXISTS idx_lake_hot_tail_reserved_pack
    ON lake_hot_tail_objects
        (tenant_id, table_location_prefix, pack_batch_id, event_hour, staged_at, object_uri)
    WHERE status = 'staged' AND pack_batch_id IS NOT NULL;

COMMENT ON COLUMN lake_hot_tail_objects.pack_batch_id IS
    'Short-lived exact-input reservation owned by one tail-packer replica; distinct from the durable Iceberg compaction retry identity.';
COMMENT ON COLUMN lake_hot_tail_objects.pack_reserved_at IS
    'Lease start for a bounded tail-pack reservation; abandoned claims become retryable after the compiled timeout.';
