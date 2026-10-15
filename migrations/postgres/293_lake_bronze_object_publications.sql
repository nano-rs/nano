-- NAN-2361: durable exact-object fence between Vector's acknowledged Parquet
-- bronze objects and Nano's canonical OCSF Iceberg commits.
--
-- A batch is reserved before its Iceberg append. If the publisher dies after
-- the append but before acknowledgement, the same exact object versions and
-- normalized batch digest are retried. Iceberg's snapshot property makes that
-- retry a no-op, after which these rows can be acknowledged safely.

CREATE TABLE IF NOT EXISTS lake_bronze_object_publications (
    tenant_id text NOT NULL,
    object_key text NOT NULL,
    version_id text NOT NULL,
    object_bytes bigint NOT NULL CHECK (object_bytes > 0),
    object_sha256 text NOT NULL CHECK (object_sha256 ~ '^[0-9a-f]{64}$'),
    source_rows bigint NOT NULL CHECK (source_rows > 0),
    batch_sha256 text NOT NULL CHECK (batch_sha256 ~ '^[0-9a-f]{64}$'),
    ipinfo_snapshot_sha256 text
        CHECK (ipinfo_snapshot_sha256 IS NULL OR ipinfo_snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    ioc_snapshot_sha256 text
        CHECK (ioc_snapshot_sha256 IS NULL OR ioc_snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'published')),
    event_snapshot_id text,
    reserved_at timestamptz NOT NULL DEFAULT NOW(),
    published_at timestamptz,
    last_error text,
    PRIMARY KEY (tenant_id, object_key, version_id),
    CHECK (
        (status = 'pending' AND event_snapshot_id IS NULL AND published_at IS NULL)
        OR
        (status = 'published' AND event_snapshot_id IS NOT NULL AND published_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_lake_bronze_publications_pending
    ON lake_bronze_object_publications (tenant_id, batch_sha256, object_key, version_id)
    WHERE status = 'pending';

COMMENT ON TABLE lake_bronze_object_publications IS
    'Exact versioned Vector bronze objects reserved and acknowledged against one idempotent OCSF Iceberg append.';
COMMENT ON COLUMN lake_bronze_object_publications.batch_sha256 IS
    'Digest of the normalized, deduplicated OCSF batch recorded in the Iceberg snapshot properties.';
COMMENT ON COLUMN lake_bronze_object_publications.ipinfo_snapshot_sha256 IS
    'Exact immutable IPinfo generation used before OCSF validation, or NULL when disabled.';
COMMENT ON COLUMN lake_bronze_object_publications.ioc_snapshot_sha256 IS
    'Exact immutable tenant IOC generation used before OCSF validation, or NULL when disabled.';
