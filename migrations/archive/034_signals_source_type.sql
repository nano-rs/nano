-- Migration: Add signals source type for detection/alert logging
-- This allows detection matches and alerts to be logged as searchable events
--
-- Signal types:
--   - "detection_match": Live mode rule matched (no alert created, for tuning)
--   - "alert": Alerting mode rule matched (alert created)
--
-- This enables:
--   - Searching for all detection activity: source_type=signals
--   - Filtering by signal type: source_type=signals signal_type=alert
--   - Building dashboards on detection metrics
--   - Creating meta-detections (detections that fire on other detections)
--   - Correlating alerts with original log events

-- Add a comment explaining the signals source type
COMMENT ON TABLE logs IS 'Log storage table. source_type="signals" is reserved for detection/alert events that are auto-logged when rules fire. signal_type in metadata distinguishes detection_match (live mode) from alert (alerting mode).';

-- Create an index to optimize queries on signals source type
CREATE INDEX IF NOT EXISTS idx_logs_signals_source_type 
ON logs (source_type, timestamp DESC) 
WHERE source_type = 'signals';

-- Index for signal_type filtering (detection_match vs alert)
CREATE INDEX IF NOT EXISTS idx_logs_signals_type 
ON logs ((metadata->>'signal_type'), timestamp DESC) 
WHERE source_type = 'signals';

-- Index for severity filtering
CREATE INDEX IF NOT EXISTS idx_logs_signals_severity 
ON logs ((metadata->>'severity'), timestamp DESC) 
WHERE source_type = 'signals';

-- Index for rule_id lookups
CREATE INDEX IF NOT EXISTS idx_logs_signals_rule_id 
ON logs ((metadata->>'rule_id'), timestamp DESC) 
WHERE source_type = 'signals';

-- Index for rule_name searches
CREATE INDEX IF NOT EXISTS idx_logs_signals_rule_name 
ON logs ((metadata->>'rule_name'), timestamp DESC) 
WHERE source_type = 'signals';

-- Index for alert_id lookups (only present for signal_type=alert)
CREATE INDEX IF NOT EXISTS idx_logs_signals_alert_id 
ON logs ((metadata->>'alert_id'), timestamp DESC) 
WHERE source_type = 'signals' AND metadata->>'signal_type' = 'alert';
