-- NAN-2361: searchable OCSF mirror for the authoritative platform-audit ledger.
--
-- Audit APIs continue to read PostgreSQL. Primary-lake writers additionally
-- persist one stable OCSF API Activity (6003) event beside each new ledger row;
-- the security-event publisher commits those rows to the tenant's Iceberg table
-- and records the exact serving generation that acknowledged them.

ALTER TABLE platform_audit_events
    ADD COLUMN IF NOT EXISTS tenant_id text,
    ADD COLUMN IF NOT EXISTS ocsf_event jsonb,
    ADD COLUMN IF NOT EXISTS lake_published_at timestamptz,
    ADD COLUMN IF NOT EXISTS lake_published_snapshot_id text,
    ADD COLUMN IF NOT EXISTS lake_publish_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS lake_last_error text;

ALTER TABLE platform_audit_events
    DROP CONSTRAINT IF EXISTS platform_audit_events_lake_mirror_complete;
ALTER TABLE platform_audit_events
    ADD CONSTRAINT platform_audit_events_lake_mirror_complete CHECK (
        (tenant_id IS NULL AND ocsf_event IS NULL)
        OR (tenant_id IS NOT NULL AND ocsf_event IS NOT NULL)
    );

ALTER TABLE platform_audit_events
    DROP CONSTRAINT IF EXISTS platform_audit_events_lake_attempts_nonnegative;
ALTER TABLE platform_audit_events
    ADD CONSTRAINT platform_audit_events_lake_attempts_nonnegative
        CHECK (lake_publish_attempts >= 0);

CREATE INDEX IF NOT EXISTS idx_platform_audit_events_lake_pending
    ON platform_audit_events (tenant_id, occurred_at, event_id)
    WHERE ocsf_event IS NOT NULL AND lake_published_at IS NULL;

COMMENT ON COLUMN platform_audit_events.ocsf_event IS
    'Canonical OCSF 1.9 API Activity mirror; PostgreSQL remains the authoritative audit ledger.';
