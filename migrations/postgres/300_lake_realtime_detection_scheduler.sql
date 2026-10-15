-- Canonical lake deployments execute real-time rules as durable five-second
-- micro-batches. Legacy ClickHouse deployments keep using materialized views,
-- so this index is harmless there and remains empty unless a lake rule has a
-- persisted next_run_at.

CREATE INDEX IF NOT EXISTS idx_detection_rules_lake_realtime_due
  ON detection_rules (next_run_at ASC)
  WHERE archived = false
    AND detection_mode = 'real-time'
    AND mode NOT IN ('staging', 'paused')
    AND schedule_cron IS NOT NULL
    AND next_run_at IS NOT NULL;
