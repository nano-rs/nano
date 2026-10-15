-- NAN-2361: the finding outbox is a bounded product-event handoff and tuning
-- window, not a permanent second event store. Seven days is the largest tuning
-- input window; retain one additional day of safety after the composite
-- event/risk/generation acknowledgement, then let the risk publisher reap it.

CREATE INDEX IF NOT EXISTS idx_detection_finding_lake_outbox_completed_retention
    ON detection_finding_lake_outbox (tenant_id, published_at, finding_id)
    WHERE published_at IS NOT NULL;

COMMENT ON INDEX idx_detection_finding_lake_outbox_completed_retention IS
    'Bounded cleanup path for fully acknowledged finding handoff/tuning rows older than eight days.';
