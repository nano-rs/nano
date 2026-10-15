-- NAN-2361: tuning reads the durable finding outbox in canonical lake mode.
-- Keep the five-minute aggregate and recent-sample paths bounded by tenant,
-- rule, and source-event time as retention grows.
CREATE INDEX IF NOT EXISTS idx_detection_finding_lake_outbox_tuning
    ON detection_finding_lake_outbox (
        tenant_id,
        (compact_finding ->> 'rule_id'),
        ((compact_finding ->> 'timestamp_us')::bigint) DESC
    );

COMMENT ON INDEX idx_detection_finding_lake_outbox_tuning IS
    'Tenant/rule/time access path for canonical-lake detection tuning metrics.';
