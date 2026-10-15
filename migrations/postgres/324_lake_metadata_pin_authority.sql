-- NAN-2361: fleet-wide authority for exact Iceberg metadata pins.
--
-- Query replicas publish the complete set of metadata files they can still
-- read (active plus draining generations) under a short token-fenced lease.
-- Metadata GC takes a separate lease on the tenant/table authority row. While
-- that lease is live, publishers cannot change the pin set; if the GC lease
-- expires, any publisher update advances `revision` and fences the stale GC
-- holder before its next exact-version delete.

CREATE TABLE IF NOT EXISTS lake_metadata_pin_authorities (
    tenant_id text NOT NULL,
    table_location_prefix text NOT NULL,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    gc_lease_token uuid,
    gc_lease_expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (tenant_id, table_location_prefix),
    CHECK (length(tenant_id) BETWEEN 1 AND 512),
    CHECK (table_location_prefix LIKE 's3://%/'),
    CHECK (
        (gc_lease_token IS NULL AND gc_lease_expires_at IS NULL)
        OR (gc_lease_token IS NOT NULL AND gc_lease_expires_at IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS lake_metadata_pin_leases (
    tenant_id text NOT NULL,
    table_location_prefix text NOT NULL,
    replica_id text NOT NULL,
    lease_token uuid NOT NULL,
    lease_revision bigint NOT NULL CHECK (lease_revision > 0),
    metadata_locations text[] NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (tenant_id, table_location_prefix, replica_id),
    FOREIGN KEY (tenant_id, table_location_prefix)
        REFERENCES lake_metadata_pin_authorities (tenant_id, table_location_prefix)
        ON DELETE CASCADE,
    CHECK (length(replica_id) BETWEEN 1 AND 256),
    CHECK (cardinality(metadata_locations) BETWEEN 1 AND 2048)
);

CREATE INDEX IF NOT EXISTS idx_lake_metadata_pin_leases_expiry
    ON lake_metadata_pin_leases (
        tenant_id, table_location_prefix, lease_expires_at
    );

COMMENT ON TABLE lake_metadata_pin_authorities IS
    'Tenant/table serialization row fencing multi-replica Iceberg metadata pins against native-S3 metadata GC.';
COMMENT ON TABLE lake_metadata_pin_leases IS
    'Short-lived exact metadata-location sets published by query replicas; expired rows never authorize deletion by themselves.';
