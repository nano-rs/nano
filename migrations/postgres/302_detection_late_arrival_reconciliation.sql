-- NAN-2361: durable late-arriving event reconciliation for lake detections.
--
-- Normal detection watermarks advance over event time. A canonical object can
-- be published later with event timestamps behind that watermark, so it needs
-- a separate replay lane. Publication records are committed atomically with
-- the staged object ledger. API nodes then plan bounded per-rule replay jobs
-- with SKIP LOCKED and execute them without changing the normal watermark.

CREATE TABLE IF NOT EXISTS lake_detection_event_publications (
    tenant_id text NOT NULL,
    bronze_store_id text NOT NULL,
    batch_sha256 text NOT NULL CHECK (batch_sha256 ~ '^[0-9a-f]{64}$'),
    min_event_time timestamptz NOT NULL,
    max_event_time timestamptz NOT NULL,
    published_at timestamptz NOT NULL DEFAULT NOW(),
    planned_at timestamptz,
    expired_at timestamptz,
    PRIMARY KEY (tenant_id, bronze_store_id, batch_sha256),
    CHECK (max_event_time >= min_event_time),
    CHECK (NOT (planned_at IS NOT NULL AND expired_at IS NOT NULL))
);

-- Upgrade/backfill: every exact hot-tail batch already carries conservative,
-- validated event-time bounds. ON CONFLICT also makes the migration safe when
-- a new publisher wrote the publication row before the migration transaction
-- reached this statement on another tenant.
INSERT INTO lake_detection_event_publications (
    tenant_id,
    bronze_store_id,
    batch_sha256,
    min_event_time,
    max_event_time,
    published_at,
    planned_at
)
SELECT
    tenant_id,
    bronze_store_id,
    batch_sha256,
    to_timestamp(MIN(min_time_ms)::double precision / 1000.0),
    to_timestamp(MAX(max_time_ms)::double precision / 1000.0),
    MIN(staged_at),
    -- Existing objects are the upgrade baseline, not newly late data. Mark
    -- them planned in the migration transaction so enabling the repair lane
    -- cannot trigger a historical replay storm or duplicate aggregate output.
    NOW()
FROM lake_hot_tail_objects
GROUP BY tenant_id, bronze_store_id, batch_sha256
ON CONFLICT (tenant_id, bronze_store_id, batch_sha256) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_lake_detection_publications_unplanned
    ON lake_detection_event_publications (published_at, tenant_id, batch_sha256)
    WHERE planned_at IS NULL AND expired_at IS NULL;

CREATE TABLE IF NOT EXISTS detection_late_replay_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id uuid NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    tenant_id text NOT NULL,
    bronze_store_id text NOT NULL,
    batch_sha256 text NOT NULL CHECK (batch_sha256 ~ '^[0-9a-f]{64}$'),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'dead_letter')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT NOW(),
    claimed_by text,
    claimed_at timestamptz,
    claim_expires_at timestamptz,
    completed_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (rule_id, tenant_id, bronze_store_id, batch_sha256),
    CHECK (window_end > window_start),
    CHECK (
        (
            status = 'running'
            AND claimed_by IS NOT NULL
            AND claimed_at IS NOT NULL
            AND claim_expires_at IS NOT NULL
            AND completed_at IS NULL
        )
        OR
        (
            status = 'pending'
            AND claimed_by IS NULL
            AND claimed_at IS NULL
            AND claim_expires_at IS NULL
            AND completed_at IS NULL
        )
        OR
        (
            status IN ('completed', 'dead_letter')
            AND claimed_by IS NULL
            AND claimed_at IS NULL
            AND claim_expires_at IS NULL
            AND completed_at IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_detection_late_replay_claimable
    ON detection_late_replay_jobs (next_attempt_at, created_at, id)
    WHERE status IN ('pending', 'running');

COMMENT ON TABLE lake_detection_event_publications IS
    'Canonical object batches awaiting bounded late-arrival planning against detection-rule event-time watermarks.';
COMMENT ON TABLE detection_late_replay_jobs IS
    'Idempotent per-rule repair windows for events published behind an already-advanced detection watermark.';
COMMENT ON COLUMN detection_late_replay_jobs.window_start IS
    'Context-expanded lower event-time boundary; replay never mutates detection_rules.last_run_at.';
