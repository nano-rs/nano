-- NAN-2361: durable handoff from Nano's detection engine to the compact
-- immutable findings lane used by lake-backed risk queries.
CREATE TABLE IF NOT EXISTS detection_finding_lake_outbox (
    tenant_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    compact_finding JSONB NOT NULL,
    ocsf_event JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    published_snapshot_id TEXT,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    PRIMARY KEY (tenant_id, finding_id),
    CONSTRAINT detection_finding_lake_outbox_attempts_nonnegative
        CHECK (publish_attempts >= 0)
);

CREATE INDEX IF NOT EXISTS idx_detection_finding_lake_outbox_pending
    ON detection_finding_lake_outbox (tenant_id, created_at, finding_id)
    WHERE published_at IS NULL;

COMMENT ON TABLE detection_finding_lake_outbox IS
    'Durable idempotent handoff for OCSF detection findings and compact risk rows; an external publisher advances immutable object-store snapshots.';
