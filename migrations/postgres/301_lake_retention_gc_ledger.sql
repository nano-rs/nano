-- Durable handoff between logical Iceberg retention and physical object GC.
--
-- A normal delete snapshot makes old Parquet objects unreachable from the
-- current table, but the objects must remain available while rollback
-- snapshots, queued searches, or an older serving generation can reference
-- them. The retention coordinator reconstructs this ledger from Iceberg
-- manifests before snapshot expiry, so a crash after catalog commit cannot
-- lose the eventual-delete set.

CREATE TABLE IF NOT EXISTS lake_retention_gc_objects (
    tenant_id VARCHAR(255) NOT NULL,
    table_uuid UUID NOT NULL,
    operation_sha256 CHAR(64) NOT NULL
        CHECK (operation_sha256 ~ '^[0-9a-f]{64}$'),
    retention_snapshot_id BIGINT NOT NULL
        CHECK (retention_snapshot_id > 0),
    object_uri TEXT NOT NULL
        CHECK (length(object_uri) BETWEEN 1 AND 4096),
    object_bytes BIGINT NOT NULL
        CHECK (object_bytes > 0),
    eligible_after TIMESTAMPTZ NOT NULL,
    activation_proven_at TIMESTAMPTZ,
    active_generation_snapshot_id BIGINT
        CHECK (active_generation_snapshot_id > 0),
    deleted_at TIMESTAMPTZ,
    delete_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (delete_attempts >= 0),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, table_uuid, operation_sha256, object_uri)
);

CREATE INDEX IF NOT EXISTS idx_lake_retention_gc_due
    ON lake_retention_gc_objects (eligible_after ASC)
    WHERE deleted_at IS NULL AND activation_proven_at IS NOT NULL;

COMMENT ON TABLE lake_retention_gc_objects IS
    'Exact Parquet objects removed by Iceberg retention, held through rollback/job grace before reference-checked physical deletion';
