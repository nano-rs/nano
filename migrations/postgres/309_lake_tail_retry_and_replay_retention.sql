-- NAN-2361: freeze cross-system publication inputs before object/catalog I/O
-- and make late-replay metadata finite without discarding actionable work.

CREATE TABLE IF NOT EXISTS lake_product_event_publication_batches (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL,
    signal_ids text[] NOT NULL DEFAULT '{}',
    audit_ids uuid[] NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'reserved',
    created_at timestamptz NOT NULL DEFAULT NOW(),
    completed_at timestamptz,
    CHECK (cardinality(signal_ids) + cardinality(audit_ids) > 0),
    CHECK (status IN ('reserved', 'completed')),
    CHECK (
        (status = 'reserved' AND completed_at IS NULL)
        OR (status = 'completed' AND completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_lake_product_event_one_reserved_tenant
    ON lake_product_event_publication_batches (tenant_id)
    WHERE status = 'reserved';

CREATE INDEX IF NOT EXISTS idx_lake_product_event_completed_retention
    ON lake_product_event_publication_batches (completed_at, id)
    WHERE status = 'completed';

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS compaction_batch_id uuid;

CREATE INDEX IF NOT EXISTS idx_lake_hot_tail_reserved_compaction
    ON lake_hot_tail_objects
        (tenant_id, table_location_prefix, compaction_batch_id, event_hour, staged_at, object_uri)
    WHERE status = 'staged' AND compaction_batch_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_lake_detection_publication_retention
    ON lake_detection_event_publications
        (COALESCE(planned_at, expired_at), tenant_id, bronze_store_id, batch_sha256)
    WHERE planned_at IS NOT NULL OR expired_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_detection_late_replay_completed_retention
    ON detection_late_replay_jobs (completed_at, id)
    WHERE status IN ('completed', 'dead_letter');

COMMENT ON TABLE lake_product_event_publication_batches IS
    'Metadata-only fixed outbox row identities retried across Iceberg commit and PostgreSQL acknowledgement crashes.';
COMMENT ON COLUMN lake_hot_tail_objects.compaction_batch_id IS
    'Durable fixed compaction selection; new staged rows cannot extend an in-flight retry after a catalog commit.';
