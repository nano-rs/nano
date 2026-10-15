-- NAN-2456: daily point-in-time physical storage inventory, not ingest volume.
-- Apply in the control image migration wave, never from a lake pod.
CREATE TABLE tenant_daily_storage_ledger (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    storage_day DATE NOT NULL,
    bucket TEXT NOT NULL CHECK (bucket = 'nano-shared-r2-' || tenant_id::text),
    storage_class TEXT NOT NULL CHECK (storage_class IN
        ('bronze', 'tail', 'silver-committed', 'bundles', 'ledger', 'results', 'other')),
    bytes BIGINT NOT NULL CHECK (bytes >= 0),
    objects BIGINT NOT NULL CHECK (objects >= 0),
    observed_at TIMESTAMPTZ NOT NULL,
    inventory_sha256 TEXT NOT NULL CHECK (inventory_sha256 ~ '^[0-9a-f]{64}$'),
    committed_keys_sha256 TEXT NOT NULL CHECK (committed_keys_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, storage_day, storage_class),
    CHECK (storage_day = (observed_at AT TIME ZONE 'UTC')::date)
);
REVOKE ALL ON tenant_daily_storage_ledger FROM PUBLIC;
-- No tenant/runtime policy until the billing reader capability is assigned.
-- Even installations with default table grants cannot expose another tenant.
ALTER TABLE tenant_daily_storage_ledger ENABLE ROW LEVEL SECURITY;
COMMENT ON TABLE tenant_daily_storage_ledger IS
    'Latest complete inventory per UTC day and class. Only silver-committed is billable; all other classes are platform overhead. Operator-owned writer; no lake or query role grants.';
