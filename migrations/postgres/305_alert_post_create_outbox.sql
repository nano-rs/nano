-- Durable, retryable post-create work for detection alerts.
--
-- Alert creation and matched-event checkpointing are the detection critical
-- path. Risk finding publication, case grouping, shadow investigation, and
-- webhook fanout are important but must not hold a scheduled window open for
-- minutes or cause it to replay. Per-event detections enqueue one idempotent
-- row here after the alert is durable; jobs nodes claim with SKIP LOCKED.

CREATE TABLE IF NOT EXISTS alert_post_create_outbox (
    alert_id UUID PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_by TEXT,
    claimed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alert_post_create_outbox_claim
    ON alert_post_create_outbox (status, available_at, created_at)
    WHERE status IN ('pending', 'processing');

