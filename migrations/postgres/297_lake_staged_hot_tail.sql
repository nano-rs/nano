-- NAN-2361: keep low-latency Vector micro-batches out of the Iceberg catalog.
--
-- Canonical OCSF rows are first published as exact-version Parquet objects in
-- the tenant's bounded signed hot tail. Closed tail objects are later compacted
-- into a sized generation-ready Iceberg append. This avoids one Iceberg
-- snapshot and metadata fan-out per writer flush without introducing a second
-- query mode.

ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS tail_publication_id text
        CHECK (tail_publication_id IS NULL OR tail_publication_id ~ '^[0-9a-f]{64}$');

ALTER TABLE lake_bronze_object_publications
    DROP CONSTRAINT IF EXISTS lake_bronze_publication_state_complete,
    ADD CONSTRAINT lake_bronze_publication_state_complete
        CHECK (
            (
                status = 'pending'
                AND source_rows IS NOT NULL
                AND batch_sha256 IS NOT NULL
                AND event_snapshot_id IS NULL
                AND tail_publication_id IS NULL
                AND published_at IS NULL
                AND rejected_at IS NULL
                AND rejection_code IS NULL
            )
            OR
            (
                status = 'published'
                AND source_rows IS NOT NULL
                AND batch_sha256 IS NOT NULL
                AND (event_snapshot_id IS NULL) <> (tail_publication_id IS NULL)
                AND published_at IS NOT NULL
                AND rejected_at IS NULL
                AND rejection_code IS NULL
            )
            OR
            (
                status = 'rejected'
                AND batch_sha256 IS NULL
                AND event_snapshot_id IS NULL
                AND tail_publication_id IS NULL
                AND published_at IS NULL
                AND rejected_at IS NOT NULL
                AND rejection_code IS NOT NULL
            )
        );

CREATE TABLE IF NOT EXISTS lake_hot_tail_objects (
    tenant_id text NOT NULL,
    bronze_store_id text NOT NULL,
    batch_sha256 text NOT NULL CHECK (batch_sha256 ~ '^[0-9a-f]{64}$'),
    event_hour integer NOT NULL,
    object_uri text NOT NULL CHECK (object_uri LIKE 's3://%/data/tail/%'),
    version_id text NOT NULL CHECK (version_id <> '' AND version_id <> 'unversioned'),
    object_bytes bigint NOT NULL CHECK (object_bytes > 0),
    object_sha256 text NOT NULL CHECK (object_sha256 ~ '^[0-9a-f]{64}$'),
    rows bigint NOT NULL CHECK (rows > 0),
    status text NOT NULL DEFAULT 'staged',
    compaction_snapshot_id bigint,
    superseded_by_batch_sha256 text
        CHECK (
            superseded_by_batch_sha256 IS NULL
            OR superseded_by_batch_sha256 ~ '^[0-9a-f]{64}$'
        ),
    staged_at timestamptz NOT NULL DEFAULT NOW(),
    superseded_at timestamptz,
    compacted_at timestamptz,
    activated_at timestamptz,
    PRIMARY KEY (tenant_id, bronze_store_id, batch_sha256, event_hour),
    UNIQUE (tenant_id, object_uri, version_id),
    CHECK (
        (
            status = 'staged'
            AND compaction_snapshot_id IS NULL
            AND superseded_by_batch_sha256 IS NULL
            AND superseded_at IS NULL
            AND compacted_at IS NULL
            AND activated_at IS NULL
        )
        OR
        (
            status = 'superseded'
            AND compaction_snapshot_id IS NULL
            AND superseded_by_batch_sha256 IS NOT NULL
            AND superseded_at IS NOT NULL
            AND compacted_at IS NULL
            AND activated_at IS NULL
        )
        OR
        (
            status = 'compacted'
            AND compaction_snapshot_id IS NOT NULL
            AND superseded_by_batch_sha256 IS NULL
            AND superseded_at IS NULL
            AND compacted_at IS NOT NULL
            AND activated_at IS NULL
        )
        OR
        (
            status = 'activated'
            AND compaction_snapshot_id IS NOT NULL
            AND superseded_by_batch_sha256 IS NULL
            AND superseded_at IS NULL
            AND compacted_at IS NOT NULL
            AND activated_at IS NOT NULL
        )
    )
);

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS superseded_by_batch_sha256 text,
    ADD COLUMN IF NOT EXISTS superseded_at timestamptz;

ALTER TABLE lake_hot_tail_objects
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_status_check,
    ADD CONSTRAINT lake_hot_tail_objects_status_check
        CHECK (status IN ('staged', 'superseded', 'compacted', 'activated')),
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_superseded_by_batch_sha256_check,
    ADD CONSTRAINT lake_hot_tail_objects_superseded_by_batch_sha256_check
        CHECK (
            superseded_by_batch_sha256 IS NULL
            OR superseded_by_batch_sha256 ~ '^[0-9a-f]{64}$'
        ),
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_check,
    ADD CONSTRAINT lake_hot_tail_objects_check
        CHECK (
            (
                status = 'staged'
                AND compaction_snapshot_id IS NULL
                AND superseded_by_batch_sha256 IS NULL
                AND superseded_at IS NULL
                AND compacted_at IS NULL
                AND activated_at IS NULL
            )
            OR
            (
                status = 'superseded'
                AND compaction_snapshot_id IS NULL
                AND superseded_by_batch_sha256 IS NOT NULL
                AND superseded_at IS NOT NULL
                AND compacted_at IS NULL
                AND activated_at IS NULL
            )
            OR
            (
                status = 'compacted'
                AND compaction_snapshot_id IS NOT NULL
                AND superseded_by_batch_sha256 IS NULL
                AND superseded_at IS NULL
                AND compacted_at IS NOT NULL
                AND activated_at IS NULL
            )
            OR
            (
                status = 'activated'
                AND compaction_snapshot_id IS NOT NULL
                AND superseded_by_batch_sha256 IS NULL
                AND superseded_at IS NULL
                AND compacted_at IS NOT NULL
                AND activated_at IS NOT NULL
            )
        );

CREATE INDEX IF NOT EXISTS idx_lake_hot_tail_visible
    ON lake_hot_tail_objects (tenant_id, status, event_hour, staged_at, object_uri)
    WHERE status IN ('staged', 'compacted');

CREATE INDEX IF NOT EXISTS idx_lake_hot_tail_compaction
    ON lake_hot_tail_objects (tenant_id, bronze_store_id, status, event_hour, staged_at)
    WHERE status = 'staged';

COMMENT ON TABLE lake_hot_tail_objects IS
    'Exact-version canonical OCSF Parquet objects visible beside an indexed Iceberg base until their compacted snapshot becomes the active generation.';
COMMENT ON COLUMN lake_hot_tail_objects.compaction_snapshot_id IS
    'Generation-ready Iceberg append containing this exact staged object; visibility remains in the tail until that snapshot activates.';
COMMENT ON COLUMN lake_hot_tail_objects.superseded_by_batch_sha256 IS
    'Content identity of the exact transient tail pack that atomically replaced this micro-object before Iceberg compaction.';
COMMENT ON COLUMN lake_bronze_object_publications.tail_publication_id IS
    'Content identity of the canonical staged-tail publication that acknowledged this exact Vector bronze batch.';
