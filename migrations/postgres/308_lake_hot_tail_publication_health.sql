-- NAN-2361: observable, tenant-scoped hot-tail publication liveness.
--
-- Event bytes stay in exact-version Parquet objects. This singleton records
-- only the last manifest Nano successfully signed and durably published, so a
-- health collector can distinguish an idle source from a frozen freshness
-- lane while the object writer and query worker themselves remain healthy.

CREATE TABLE IF NOT EXISTS lake_hot_tail_ledger_revisions (
    tenant_id text NOT NULL,
    table_location_prefix text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, table_location_prefix),
    CHECK (table_location_prefix LIKE 's3://%/')
);

INSERT INTO lake_hot_tail_ledger_revisions (
    tenant_id, table_location_prefix, revision
)
SELECT tenant_id, table_location_prefix, 1
FROM lake_hot_tail_objects
GROUP BY tenant_id, table_location_prefix
ON CONFLICT (tenant_id, table_location_prefix) DO NOTHING;

CREATE TABLE IF NOT EXISTS lake_hot_tail_publication_health (
    tenant_id text NOT NULL,
    table_location_prefix text NOT NULL,
    base_snapshot_id bigint NOT NULL CHECK (base_snapshot_id > 0),
    published_ledger_revision bigint NOT NULL
        CHECK (published_ledger_revision >= 0),
    manifest_sha256 character(64) NOT NULL
        CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    tail_id character(64)
        CHECK (tail_id IS NULL OR tail_id ~ '^[0-9a-f]{64}$'),
    visible_objects integer NOT NULL CHECK (visible_objects >= 0),
    visible_bytes bigint NOT NULL CHECK (visible_bytes >= 0),
    newest_visible_event_time timestamptz,
    last_reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, table_location_prefix),
    CHECK (table_location_prefix LIKE 's3://%/')
);

COMMENT ON TABLE lake_hot_tail_publication_health IS
    'Last successfully signed staged-tail manifest. Metadata only; event and result payloads remain in object storage.';
COMMENT ON COLUMN lake_hot_tail_publication_health.last_reconciled_at IS
    'Advanced only after the signed manifest has been atomically persisted; ledger revisions newer than published_ledger_revision are publication backlog.';
