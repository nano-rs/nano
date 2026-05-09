-- Per-event alert mode for detection rules
-- Allows rules to generate one alert per matched event (vendor pass-through)
-- Default 'grouped' preserves existing behavior (all matches → 1 alert)

ALTER TABLE detection_rules
  ADD COLUMN IF NOT EXISTS alert_mode TEXT DEFAULT 'grouped' NOT NULL;

ALTER TABLE detection_rules
  ADD CONSTRAINT check_alert_mode CHECK (alert_mode IN ('grouped', 'per_event'));
